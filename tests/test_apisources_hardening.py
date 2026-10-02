"""Tests for the OSINT hardening: distinct statuses, Censys Platform API,
and keeping secrets out of logs and reports."""
import io
import json
import logging
import urllib.error

import pytest

import api_sources


class _Resp:
    def __init__(self, body):
        self._b = body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http_error(code, body=b"{}"):
    return urllib.error.HTTPError("https://x/?key=SECRET", code, "msg", None, io.BytesIO(body))


def _raise(exc):
    def f(req, timeout):
        raise exc
    return f


@pytest.mark.parametrize("code,status", [
    (401, api_sources.STATUS_AUTH_FAILED), (403, api_sources.STATUS_AUTH_FAILED),
    (404, api_sources.STATUS_NO_DATA), (429, api_sources.STATUS_RATE_LIMITED),
    (500, api_sources.STATUS_FAILED),
])
def test_http_codes_map_to_distinct_statuses(monkeypatch, code, status):
    monkeypatch.setattr(api_sources.urllib.request, "urlopen", _raise(_http_error(code)))
    f = api_sources._shodan_lookup("93.184.216.34", "k")
    assert f["status"] == status and f["ok"] is False and f["skipped"] is False


def test_missing_keys_are_not_configured_not_failed():
    findings = api_sources.gather_api_findings("example.com", "93.184.216.34",
                                               api_keys={"shodan": "", "virustotal": "", "censys_token": ""})
    assert {f["status"] for f in findings} == {api_sources.STATUS_NOT_CONFIGURED}
    assert all(f["skipped"] for f in findings)


def test_unresolved_ip_is_no_ip():
    assert api_sources._shodan_lookup(None, "k")["status"] == api_sources.STATUS_NO_IP
    assert api_sources._censys_lookup(None, "t")["status"] == api_sources.STATUS_NO_IP


def test_virustotal_error_body_with_nested_dict(monkeypatch):
    body = json.dumps({"error": {"code": "WrongCredentialsError", "message": "Wrong API key"}}).encode()
    monkeypatch.setattr(api_sources.urllib.request, "urlopen", _raise(_http_error(401, body)))
    f = api_sources._virustotal_lookup("example.com", "k")
    assert f["status"] == api_sources.STATUS_AUTH_FAILED
    assert "Wrong API key" in f["reason"]


def test_status_labels():
    assert api_sources.status_label({"status": "auth_failed"}) == "AUTH FAILED"
    assert api_sources.status_label({"status": "not_configured"}) == "NOT CONFIGURED"
    assert api_sources.status_label({"ok": True}) == "OK"  # legacy finding without status


# ---------------------------------------------------------------- Censys
def test_censys_uses_platform_api_with_bearer_token(monkeypatch):
    seen = {}

    def fake(req, timeout):
        seen["url"], seen["headers"] = req.full_url, dict(req.header_items())
        return _Resp(json.dumps({"result": {"resource": {
            "autonomous_system": {"name": "AS Example"},
            "services": [{"port": 443, "protocol": "HTTP"}, {"port": 22, "protocol": "SSH"}]}}}).encode())

    monkeypatch.setattr(api_sources.urllib.request, "urlopen", fake)
    f = api_sources._censys_lookup("93.184.216.34", "my-pat", org_id="org-123")
    assert seen["url"].startswith("https://api.platform.censys.io/v3/global/asset/host/93.184.216.34")
    assert "organization_id=org-123" in seen["url"]
    assert seen["headers"]["Authorization"] == "Bearer my-pat"
    assert "v3.host" in seen["headers"]["Accept"]
    assert f["data"]["exposed_services"] == ["22/SSH", "443/HTTP"]
    assert f["data"]["autonomous_system"] == "AS Example"


def test_censys_never_calls_legacy_search_host(monkeypatch):
    urls = []
    monkeypatch.setattr(api_sources.urllib.request, "urlopen",
                        lambda req, timeout: urls.append(req.full_url) or _Resp(b'{"result": {}}'))
    api_sources._censys_lookup("1.1.1.1", "pat")
    assert urls and all("search.censys.io" not in u for u in urls)


def test_censys_401_reports_auth_failed(monkeypatch):
    monkeypatch.setattr(api_sources.urllib.request, "urlopen", _raise(_http_error(401)))
    assert api_sources._censys_lookup("1.1.1.1", "bad")["status"] == api_sources.STATUS_AUTH_FAILED


def test_censys_org_id_taken_from_env(monkeypatch):
    seen = []
    monkeypatch.setenv("CENSYS_ORG_ID", "env-org")
    monkeypatch.setattr(api_sources.urllib.request, "urlopen",
                        lambda req, timeout: seen.append(req.full_url) or _Resp(b'{"result": {}}'))
    api_sources.gather_api_findings("example.com", "1.1.1.1",
                                    api_keys={"shodan": "", "virustotal": "", "censys_token": "pat"})
    assert "organization_id=env-org" in seen[0]


# ---------------------------------------------------------------- secrets
def test_safe_url_drops_the_query_string():
    assert api_sources._safe_url("https://api.shodan.io/shodan/host/1.2.3.4?key=SECRET") == \
        "https://api.shodan.io/shodan/host/1.2.3.4"


def test_api_key_never_appears_in_logs_or_findings(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger="swiftscan.api_sources")
    monkeypatch.setattr(api_sources.urllib.request, "urlopen", _raise(_http_error(403, b'{"error": "denied"}')))
    f = api_sources._shodan_lookup("93.184.216.34", "SECRET-KEY-123")
    assert "SECRET-KEY-123" not in caplog.text
    assert "SECRET" not in json.dumps(f)


def test_network_error_reason_has_no_url(monkeypatch):
    monkeypatch.setattr(api_sources.urllib.request, "urlopen", _raise(urllib.error.URLError("dns failure")))
    f = api_sources._shodan_lookup("93.184.216.34", "SECRET-KEY-123")
    assert "SECRET-KEY-123" not in f["reason"] and "api.shodan.io" not in f["reason"]


def test_dotenv_does_not_override_existing_env(monkeypatch, tmp_path):
    p = tmp_path / ".env"
    p.write_text("SHODAN_API_KEY=from-file\nNEW_ONE='quoted'\n")
    monkeypatch.setenv("SHODAN_API_KEY", "from-env")
    monkeypatch.delenv("NEW_ONE", raising=False)
    api_sources._load_dotenv_file(str(p))
    import os
    assert os.environ["SHODAN_API_KEY"] == "from-env" and os.environ["NEW_ONE"] == "quoted"
    monkeypatch.delenv("NEW_ONE", raising=False)
