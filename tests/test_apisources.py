"""
Unit tests for api_sources.py.

These mock urllib.request.urlopen so no real network calls are made and the
suite doesn't depend on live API keys or external services being reachable.
"""
import io
import json
import urllib.error


import api_sources


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------------------
# load_api_keys_from_env
# ---------------------------------------------------------------------------
def test_load_api_keys_from_env_defaults_to_empty_strings(monkeypatch):
    monkeypatch.setattr(api_sources, "_load_dotenv_file", lambda: None)
    for var in ("SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "CENSYS_API_TOKEN", "CENSYS_PERSONAL_ACCESS_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    keys = api_sources.load_api_keys_from_env()
    assert keys == {"shodan": "", "virustotal": "", "censys_token": ""}
# ---------------------------------------------------------------------------
# gather_api_findings - sources with no key configured are "skipped", not attempted
# ---------------------------------------------------------------------------
def test_gather_api_findings_skips_all_sources_with_no_keys(monkeypatch):
    def fail_if_called(*a, **k):
        raise AssertionError("should not make a network call with no API key set")

    monkeypatch.setattr(api_sources.urllib.request, "urlopen", fail_if_called)
    findings = api_sources.gather_api_findings(
        "example.com", resolved_ip="93.184.216.34",
        api_keys={"shodan": "", "virustotal": "", "censys_token": ""},
    )
    sources = {f["source"]: f for f in findings}
    assert set(sources) == {"Shodan", "VirusTotal", "Censys"}
    for finding in findings:
        assert finding["skipped"] is True
        assert finding["ok"] is False
        assert finding["data"] is None


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------
def test_shodan_lookup_success(monkeypatch):
    payload = {
        "org": "Example Org", "os": "Linux", "ports": [80, 443, 80],
        "hostnames": ["example.com"], "vulns": ["CVE-2021-1234"],
    }
    monkeypatch.setattr(
        api_sources.urllib.request, "urlopen",
        lambda req, timeout: _FakeResponse(json.dumps(payload).encode()),
    )
    finding = api_sources._shodan_lookup("93.184.216.34", "fake-key")
    assert finding["ok"] is True
    assert finding["skipped"] is False
    assert finding["data"]["open_ports"] == [80, 443]  # de-duplicated + sorted
    assert finding["data"]["known_vulns"] == ["CVE-2021-1234"]


def test_shodan_lookup_skipped_without_resolved_ip():
    finding = api_sources._shodan_lookup(None, "fake-key")
    assert finding["skipped"] is True
    assert finding["ok"] is False


def test_shodan_lookup_handles_http_error(monkeypatch):
    def raise_404(req, timeout):
        raise urllib.error.HTTPError(
            url="https://api.shodan.io/...", code=404, msg="Not Found",
            hdrs=None, fp=io.BytesIO(json.dumps({"error": "No information available"}).encode()),
        )

    monkeypatch.setattr(api_sources.urllib.request, "urlopen", raise_404)
    finding = api_sources._shodan_lookup("93.184.216.34", "fake-key")
    assert finding["ok"] is False
    assert finding["skipped"] is False
    assert "404" in finding["reason"]


def test_shodan_lookup_handles_network_error(monkeypatch):
    def raise_url_error(req, timeout):
        raise urllib.error.URLError("name resolution failed")

    monkeypatch.setattr(api_sources.urllib.request, "urlopen", raise_url_error)
    finding = api_sources._shodan_lookup("93.184.216.34", "fake-key")
    assert finding["ok"] is False
    assert "network error" in finding["reason"]


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------
def test_virustotal_lookup_success(monkeypatch):
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 70},
                "reputation": 5,
                "categories": {"vendor": "search engines"},
            }
        }
    }
    monkeypatch.setattr(
        api_sources.urllib.request, "urlopen",
        lambda req, timeout: _FakeResponse(json.dumps(payload).encode()),
    )
    finding = api_sources._virustotal_lookup("example.com", "fake-key")
    assert finding["ok"] is True
    assert finding["data"]["malicious_votes"] == 2
    assert finding["data"]["reputation_score"] == 5


def test_virustotal_lookup_handles_unexpected_shape(monkeypatch):
    monkeypatch.setattr(
        api_sources.urllib.request, "urlopen",
        lambda req, timeout: _FakeResponse(b'{"unexpected": true}'),
    )
    finding = api_sources._virustotal_lookup("example.com", "fake-key")
    assert finding["ok"] is False
    assert "unexpected response shape" in finding["reason"]


# ---------------------------------------------------------------------------
# Censys
# ---------------------------------------------------------------------------
def test_censys_lookup_success(monkeypatch):
    payload = {
        "result": {
            "autonomous_system": {"name": "Example AS"},
            "services": [{"port": 443, "service_name": "HTTPS"}, {"port": 22, "service_name": "SSH"}],
        }
    }
    monkeypatch.setattr(
        api_sources.urllib.request, "urlopen",
        lambda req, timeout: _FakeResponse(json.dumps(payload).encode()),
    )
    finding = api_sources._censys_lookup("93.184.216.34", api_token="fake-pat-token")
    assert finding["ok"] is True
    assert finding["data"]["exposed_services"] == ["22/SSH", "443/HTTPS"]


def test_censys_lookup_skipped_without_resolved_ip():
    finding = api_sources._censys_lookup(None, api_token="token")
    assert finding["skipped"] is True


# ---------------------------------------------------------------------------
# Timeout handling shared by every lookup, via _http_get_json
# ---------------------------------------------------------------------------
def test_http_get_json_handles_timeout(monkeypatch):
    import socket

    def raise_timeout(req, timeout):
        raise socket.timeout()

    monkeypatch.setattr(api_sources.urllib.request, "urlopen", raise_timeout)
    data, err = api_sources._http_get_json("https://example.invalid")
    assert data is None
    assert "timed out" in err


def test_http_get_json_handles_bad_json(monkeypatch):
    monkeypatch.setattr(
        api_sources.urllib.request, "urlopen",
        lambda req, timeout: _FakeResponse(b"not json"),
    )
    data, err = api_sources._http_get_json("https://example.invalid")
    assert data is None
    assert "JSON" in err
