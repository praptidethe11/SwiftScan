"""Web-layer hardening: local-only default, cross-site blocking, login,
background scans, report writing, input validation and audit logging."""
import logging
import os
import threading
import time

import pytest

import swiftscan
import web_app
from web_app import app, scan_semaphore

COMPLETE = {"event": "scan_complete", "total_elapsed": 0.5, "checks_run": 1, "checks_skipped": 0,
            "vulnerabilities_found": 0, "findings": [], "api_findings": []}


@pytest.fixture
def client():
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def reports_dir(tmp_path, monkeypatch):
    d = tmp_path / "reports"
    monkeypatch.setenv("SWIFTSCAN_REPORTS_DIR", str(d))
    web_app._login_failures.clear()
    return d


@pytest.fixture(autouse=True)
def fake_scan(monkeypatch):
    def run(target, skip=None, tool_timeout=None, **kwargs):
        yield dict(COMPLETE)
    monkeypatch.setattr(swiftscan, "run_scan", run)


def _wait_for_slot(timeout=5):
    """The scan thread releases the slot when it finishes."""
    end = time.time() + timeout
    while time.time() < end:
        if scan_semaphore.acquire(blocking=False):
            scan_semaphore.release()
            return True
        time.sleep(0.02)
    return False


# ---------------------------------------------------------------- local-only default
def test_non_local_client_refused_without_token(client):
    r = client.get("/api/tools", environ_overrides={"REMOTE_ADDR": "10.0.0.5"})
    assert r.status_code == 403 and "SWIFTSCAN_TOKEN" in r.get_json()["error"]


def test_non_local_host_header_refused_without_token(client):
    r = client.get("/api/tools", headers={"Host": "evil.example.com"})   # DNS-rebinding shape
    assert r.status_code == 403


def test_index_also_local_only_without_token(client):
    assert client.get("/", environ_overrides={"REMOTE_ADDR": "203.0.113.9"}).status_code == 403


@pytest.mark.parametrize("host", ["localhost", "localhost:5000", "127.0.0.1:5000", "[::1]:5000"])
def test_loopback_hosts_allowed_without_token(client, host):
    assert client.get("/api/tools", headers={"Host": host}).status_code == 200


def test_remote_client_allowed_with_valid_token(client, monkeypatch):
    monkeypatch.setenv("SWIFTSCAN_TOKEN", "s3cret")
    r = client.get("/api/tools", headers={"Authorization": "Bearer s3cret"},
                   environ_overrides={"REMOTE_ADDR": "10.0.0.5"})
    assert r.status_code == 200


def test_token_compared_in_constant_time(client, monkeypatch):
    monkeypatch.setenv("SWIFTSCAN_TOKEN", "s3cret")
    calls = []
    real = web_app.hmac.compare_digest
    monkeypatch.setattr(web_app.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    client.get("/api/tools", headers={"Authorization": "Bearer s3cret"})
    assert calls


# ---------------------------------------------------------------- cross-site
@pytest.mark.parametrize("headers", [
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
])
def test_cross_site_requests_blocked(client, headers):
    r = client.get("/api/scan/stream?target=example.com&consent=1", headers=headers)
    assert r.status_code == 403
    assert "Cross-site" in r.get_json()["error"]


@pytest.mark.parametrize("headers", [{"Sec-Fetch-Site": "same-origin"}, {"Sec-Fetch-Site": "none"},
                                     {"Origin": "http://localhost"}])
def test_same_origin_requests_allowed(client, headers):
    assert client.get("/api/tools", headers=headers).status_code == 200


# ---------------------------------------------------------------- login
def test_index_redirects_to_login_when_unauthenticated(client, monkeypatch):
    monkeypatch.setenv("SWIFTSCAN_TOKEN", "s3cret")
    r = client.get("/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_login_success_sets_hardened_cookie(client, monkeypatch):
    monkeypatch.setenv("SWIFTSCAN_TOKEN", "s3cret")
    r = client.post("/login", data={"token": "s3cret"})
    assert r.status_code == 302
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Max-Age=" in cookie
    assert client.get("/api/tools").status_code == 200   # cookie now authenticates


def test_login_cookie_secure_flag_on_https(client, monkeypatch):
    monkeypatch.setenv("SWIFTSCAN_TOKEN", "s3cret")
    r = client.post("/login", data={"token": "s3cret"}, base_url="https://localhost")
    assert "Secure" in r.headers["Set-Cookie"]


def test_login_wrong_token_rejected_without_cookie(client, monkeypatch):
    monkeypatch.setenv("SWIFTSCAN_TOKEN", "s3cret")
    r = client.post("/login", data={"token": "nope"})
    assert r.status_code == 401 and "Set-Cookie" not in r.headers


def test_login_is_rate_limited(client, monkeypatch):
    monkeypatch.setenv("SWIFTSCAN_TOKEN", "s3cret")
    for _ in range(web_app.LOGIN_MAX_FAILURES):
        assert client.post("/login", data={"token": "bad"}).status_code == 401
    assert client.post("/login", data={"token": "bad"}).status_code == 429
    assert client.post("/login", data={"token": "s3cret"}).status_code == 429   # even the right one, while locked


def test_login_page_escapes_nothing_user_controlled(client, monkeypatch):
    monkeypatch.setenv("SWIFTSCAN_TOKEN", "s3cret")
    body = client.post("/login", data={"token": "<script>alert(1)</script>"}).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body


# ---------------------------------------------------------------- headers and errors
def test_extra_security_headers(client):
    r = client.get("/api/tools")
    csp = r.headers["Content-Security-Policy"]
    for directive in ("object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"):
        assert directive in csp
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_api_404_and_405_are_json(client):
    r404 = client.get("/api/does-not-exist")
    assert r404.status_code == 404 and r404.get_json() == {"error": "Not found"}
    r405 = client.post("/api/tools")
    assert r405.status_code == 405 and "error" in r405.get_json()


# ---------------------------------------------------------------- reports
@pytest.mark.parametrize("path", [
    "/api/reports/..%2fsetup.py", "/api/reports/%2e%2e/setup.py", "/api/reports/..%5csetup.py",
    "/api/reports/%2fetc%2fpasswd", "/api/reports/rs..", "/api/reports/rs.%2e%2e%2fsetup.py",
    "/api/reports/rs.vul.x/../../setup.py",
])
def test_report_traversal_variants_never_leak(client, path):
    r = client.get(path, follow_redirects=True)   # Werkzeug may 308 a merged-slash path; the destination must still refuse
    assert r.status_code in (400, 403, 404)
    assert b"setup(" not in r.data and b"root:" not in r.data


def test_report_listing_only_shows_report_files(client, reports_dir):
    reports_dir.mkdir()
    (reports_dir / "rs.vul.a.2026-10-01_1").write_text("x")
    (reports_dir / "notes.txt").write_text("secret")
    (reports_dir / "rs.sub").mkdir()
    assert client.get("/api/reports").get_json() == ["rs.vul.a.2026-10-01_1"]


def test_reports_dir_is_absolute_and_not_cwd_relative(monkeypatch):
    monkeypatch.delenv("SWIFTSCAN_REPORTS_DIR", raising=False)
    assert os.path.isabs(web_app.get_reports_dir())
    assert web_app.get_reports_dir().startswith(os.path.dirname(os.path.abspath(web_app.__file__)))


def test_text_report_uses_severity_labels_and_osint_status(reports_dir):
    findings = [{"title": "SNMP", "severity": "m", "definition": "d", "remediation": "r", "cwe": "CWE-200", "module": "ports"},
                {"title": "RDP", "severity": "h", "definition": "d", "remediation": "r", "cwe": None, "module": "ports"}]
    done = dict(COMPLETE, api_findings=[
        {"source": "Shodan", "ok": False, "skipped": False, "status": "auth_failed", "reason": "HTTP 403", "data": None},
        {"source": "Censys", "ok": False, "skipped": True, "status": "not_configured", "reason": "no token", "data": None}])
    names = web_app.write_reports("example.com", "2026-10-02_000000", findings, done)
    vul = (reports_dir / names["vulreport"]).read_text()
    assert "Severity: Medium" in vul and "Severity: High" in vul and "Severity: m\n" not in vul
    api = (reports_dir / names["apireport"]).read_text()
    assert "AUTH FAILED: HTTP 403" in api and "NOT CONFIGURED: no token" in api
    assert (reports_dir / names["jsonreport"]).exists()


# ---------------------------------------------------------------- background scans (#18)
def test_reports_are_written_even_if_client_disconnects(client, monkeypatch, reports_dir):
    release = threading.Event()

    def slow_scan(target, skip=None, tool_timeout=None, **kwargs):
        yield {"event": "tool_start", "name": "x", "index": 0, "total": 1}
        release.wait(5)
        yield dict(COMPLETE)

    monkeypatch.setattr(swiftscan, "run_scan", slow_scan)
    resp = client.get("/api/scan/stream?target=example.com&consent=1", buffered=False)
    first = next(iter(resp.response))            # read one event, then walk away
    assert b"tool_start" in first.encode() if isinstance(first, str) else b"tool_start" in first
    resp.close()
    release.set()
    assert _wait_for_slot(), "scan slot was never released"
    names = sorted(p.name for p in reports_dir.iterdir())
    assert any(n.startswith("rs.vul.example.com") for n in names)
    assert any(n.startswith("rs.json.example.com") for n in names)


def test_slot_stays_held_while_scan_runs_after_disconnect(client, monkeypatch):
    release = threading.Event()

    def slow_scan(target, skip=None, tool_timeout=None, **kwargs):
        yield {"event": "tool_start", "name": "x", "index": 0, "total": 1}
        release.wait(5)
        yield dict(COMPLETE)

    monkeypatch.setattr(swiftscan, "run_scan", slow_scan)
    resp = client.get("/api/scan/stream?target=example.com&consent=1", buffered=False)
    next(iter(resp.response))
    resp.close()
    busy = client.get("/api/scan/stream?target=example.com&consent=1").get_data(as_text=True)
    assert "Server is busy" in busy
    release.set()
    assert _wait_for_slot()


def test_slot_released_when_scan_crashes(client, monkeypatch):
    def boom(target, skip=None, tool_timeout=None, **kwargs):
        raise RuntimeError("secret internal detail /etc/passwd")
        yield  # pragma: no cover

    monkeypatch.setattr(swiftscan, "run_scan", boom)
    text = client.get("/api/scan/stream?target=example.com&consent=1").get_data(as_text=True)
    assert "fatal_error" in text and "secret internal detail" not in text   # no internals leaked
    assert _wait_for_slot()


def test_budget_is_passed_to_the_engine(client, monkeypatch):
    seen = {}

    def spy(target, skip=None, tool_timeout=None, **kwargs):
        seen.update(kwargs)
        yield dict(COMPLETE)

    monkeypatch.setattr(swiftscan, "run_scan", spy)
    client.get("/api/scan/stream?target=example.com&budget=7&consent=1").get_data()
    assert seen["max_total_seconds"] == 7 * 60


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize("bad", ["nan", "inf", "-inf", "0", "-5", "abc", ""])
def test_non_finite_or_bad_budget_rejected(client, bad):
    text = client.get("/api/scan/stream?target=example.com&consent=1&budget=" + bad).get_data(as_text=True)
    assert "Invalid budget" in text


def test_internal_targets_refused_by_default(client):
    text = client.get("/api/scan/stream?target=169.254.169.254&consent=1").get_data(as_text=True)
    assert "fatal_error" in text and "internal" in text


def test_internal_targets_allowed_with_explicit_opt_in(client, monkeypatch):
    monkeypatch.setenv("SWIFTSCAN_ALLOW_INTERNAL", "1")
    text = client.get("/api/scan/stream?target=127.0.0.1&consent=1").get_data(as_text=True)
    assert "scan_complete" in text


# ---------------------------------------------------------------- audit log
def test_audit_records_scan_with_consent_flag_and_client(client):
    records = []

    class H(logging.Handler):
        def emit(self, record):
            records.append((record.getMessage(), getattr(record, "fields", {})))

    audit_logger = logging.getLogger("swiftscan.audit")
    handler = H()
    audit_logger.addHandler(handler)
    try:
        client.get("/api/scan/stream?target=example.com&consent=1").get_data()
        assert _wait_for_slot()
        client.get("/api/scan/stream?target=example.com")   # no consent
    finally:
        audit_logger.removeHandler(handler)

    events = {m: f for m, f in records}
    assert events["scan_started"]["consent"] is True
    assert events["scan_started"]["target"] == "example.com"
    assert events["scan_started"]["client_ip"] == "127.0.0.1"
    assert events["scan_completed"]["checks_run"] == 1
    assert events["scan_rejected"]["reason"] == "no_consent" and events["scan_rejected"]["consent"] is False


# ---------------------------------------------------------------- run_web
def test_run_web_refuses_debug_on_public_bind(monkeypatch):
    monkeypatch.setenv("SWIFTSCAN_TOKEN", "s3cret")
    with pytest.raises(SystemExit) as exc:
        web_app.run_web(host="0.0.0.0", port=5000, debug=True)
    assert exc.value.code == 1


def test_run_web_allows_loopback_without_token(monkeypatch):
    monkeypatch.delenv("SWIFTSCAN_TOKEN", raising=False)
    started = []
    monkeypatch.setattr(app, "run", lambda **k: started.append(k))
    web_app.run_web(host="127.0.0.1", port=5000)
    assert started and started[0]["host"] == "127.0.0.1"


# ---------------------------------------------------------------- health probe
def test_healthz_is_open_and_reveals_nothing(client, monkeypatch):
    monkeypatch.setenv("SWIFTSCAN_TOKEN", "s3cret")          # even with auth enabled
    r = client.get("/healthz", environ_overrides={"REMOTE_ADDR": "10.0.0.5"})
    assert r.status_code == 200 and r.get_json() == {"status": "ok"}
