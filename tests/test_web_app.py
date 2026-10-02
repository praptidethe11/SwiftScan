"""
Comprehensive tests for SwiftScan Flask web application routes and security features (web_app.py).

Covers:
- Base routes (index page, tools availability, reports list)
- Query param validation & clamping (budget 1-60 min, timeout 10-300 s, SSE fatal_error responses)
- Skip tool parameter whitelisting against tools_precheck
- Report downloads using regex, send_from_directory, text/plain mimetype, nosniff header
- Security headers (CSP, X-Frame-Options: DENY, Referrer-Policy: no-referrer, X-Content-Type-Options: nosniff)
- Authentication enforcement (SWIFTSCAN_TOKEN env var, Bearer header, cookie, host bind checks)
- Concurrency limiting via threading.Semaphore (busy response when full)
- User consent enforcement (consent=1 requirement and audit logging)
"""
import pytest
import swiftscan
from web_app import app, scan_semaphore, run_web


@pytest.fixture
def client():
    """Create a Flask test client for web_app."""
    app.config["TESTING"] = False
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def mock_run_scan(monkeypatch):
    """Mock swiftscan.run_scan to avoid executing external security tools."""
    def fake_run_scan(target, skip=None, tool_timeout=None, **kwargs):
        yield {
            "event": "scan_complete",
            "total_elapsed": 0.5,
            "checks_run": 1,
            "checks_skipped": 0,
            "vulnerabilities_found": 0,
            "findings": [],
            "api_findings": [],
        }
    monkeypatch.setattr(swiftscan, "run_scan", fake_run_scan)


# ===========================================================================
# 1. Base routes & UI
# ===========================================================================

def test_index_route(client):
    """GET / should render the main UI page."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"SwiftScan" in response.data


def test_api_tools_route(client):
    """GET /api/tools should return a JSON object with tool availability list."""
    response = client.get("/api/tools")
    assert response.status_code == 200
    assert response.is_json
    data = response.get_json()
    assert "tools" in data
    assert "total_checks" in data
    assert isinstance(data["tools"], list)


def test_api_reports_route(client):
    """GET /api/reports should return a JSON list of available reports."""
    response = client.get("/api/reports")
    assert response.status_code == 200
    assert response.is_json
    assert isinstance(response.get_json(), list)


# ===========================================================================
# 2. Security Headers (Task 6)
# ===========================================================================

def test_security_headers_present(client):
    """Responses must include CSP, X-Frame-Options: DENY, Referrer-Policy: no-referrer, nosniff."""
    response = client.get("/")
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    csp = response.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self' 'unsafe-inline'" in csp


# ===========================================================================
# 3. Consent enforcement (Task 10)
# ===========================================================================

def test_scan_stream_requires_consent(client):
    """GET /api/scan/stream without consent=1 should return SSE fatal_error."""
    response = client.get("/api/scan/stream?target=example.com")
    assert response.status_code == 200
    assert response.mimetype == "text/event-stream"
    text = response.get_data(as_text=True)
    assert "fatal_error" in text
    assert "Authorization consent required" in text


def test_scan_stream_with_valid_consent(client):
    """GET /api/scan/stream with consent=1 should proceed."""
    response = client.get("/api/scan/stream?target=example.com&consent=1")
    assert response.status_code == 200
    assert response.mimetype == "text/event-stream"
    text = response.get_data(as_text=True)
    assert "scan_complete" in text


# ===========================================================================
# 4. Target validation
# ===========================================================================

def test_scan_stream_empty_target(client):
    """GET /api/scan/stream with empty target returns SSE fatal_error."""
    response = client.get("/api/scan/stream?target=&consent=1")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "fatal_error" in text
    assert "Target cannot be empty" in text


def test_scan_stream_invalid_target_injection(client):
    """GET /api/scan/stream with command injection characters returns SSE fatal_error."""
    response = client.get("/api/scan/stream?target=example.com%3Bwhoami&consent=1")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "fatal_error" in text


# ===========================================================================
# 5. Query param validation & clamping: budget & timeout (Task 3)
# ===========================================================================

def test_scan_stream_bad_budget_non_numeric(client):
    """GET /api/scan/stream with non-numeric budget returns SSE fatal_error instead of 500."""
    response = client.get("/api/scan/stream?target=example.com&budget=abc&consent=1")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "fatal_error" in text
    assert "Invalid budget" in text


def test_scan_stream_bad_budget_negative(client):
    """GET /api/scan/stream with negative budget returns SSE fatal_error instead of 500."""
    response = client.get("/api/scan/stream?target=example.com&budget=-5&consent=1")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "fatal_error" in text
    assert "Invalid budget" in text


def test_scan_stream_bad_timeout_non_numeric(client):
    """GET /api/scan/stream with non-numeric timeout returns SSE fatal_error instead of 500."""
    response = client.get("/api/scan/stream?target=example.com&timeout=xyz&consent=1")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "fatal_error" in text
    assert "Invalid timeout" in text


def test_scan_stream_bad_timeout_negative(client):
    """GET /api/scan/stream with negative timeout returns SSE fatal_error instead of 500."""
    response = client.get("/api/scan/stream?target=example.com&timeout=-10&consent=1")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "fatal_error" in text
    assert "Invalid timeout" in text


def test_scan_stream_clamps_budget_and_timeout(client, monkeypatch):
    """Clamps budget between 1-60 min and timeout between 10-300 sec."""
    recorded_kwargs = {}

    def spy_run_scan(target, skip=None, tool_timeout=None, **kwargs):
        recorded_kwargs["tool_timeout"] = tool_timeout
        yield {"event": "scan_complete", "checks_run": 1, "checks_skipped": 0, "total_elapsed": 0.1, "findings": [], "api_findings": []}

    monkeypatch.setattr(swiftscan, "run_scan", spy_run_scan)

    # High budget & timeout should clamp to max (timeout: 300)
    client.get("/api/scan/stream?target=example.com&budget=120&timeout=999&consent=1")
    assert recorded_kwargs["tool_timeout"] == 300

    # Low budget & timeout should clamp to min (timeout: 10)
    client.get("/api/scan/stream?target=example.com&budget=0.5&timeout=2&consent=1")
    assert recorded_kwargs["tool_timeout"] == 10


# ===========================================================================
# 6. Whitelist skip parameter (Task 4)
# ===========================================================================

def test_scan_stream_whitelist_valid_skip_tool(client, monkeypatch):
    """Valid tools present in tools_precheck should be accepted."""
    recorded_skip = None

    def spy_run_scan(target, skip=None, tool_timeout=None, **kwargs):
        nonlocal recorded_skip
        recorded_skip = skip
        yield {"event": "scan_complete", "checks_run": 1, "checks_skipped": 0, "total_elapsed": 0.1, "findings": [], "api_findings": []}

    monkeypatch.setattr(swiftscan, "run_scan", spy_run_scan)
    response = client.get("/api/scan/stream?target=example.com&skip=nmap,nikto&consent=1")
    assert response.status_code == 200
    assert recorded_skip == {"nmap", "nikto"}


def test_scan_stream_whitelist_invalid_skip_tool(client):
    """Unknown tools not in tools_precheck must be rejected with SSE fatal_error."""
    response = client.get("/api/scan/stream?target=example.com&skip=malicious_fake_tool&consent=1")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "fatal_error" in text
    assert "Invalid skip tool" in text


# ===========================================================================
# 7. Concurrency limit (Task 9)
# ===========================================================================

def test_scan_concurrency_busy_when_semaphore_locked(client):
    """When scan semaphore is held by an active scan, subsequent requests return busy."""
    assert scan_semaphore.acquire(blocking=False)
    try:
        response = client.get("/api/scan/stream?target=example.com&consent=1")
        assert response.status_code == 200
        text = response.get_data(as_text=True)
        assert "fatal_error" in text
        assert "Server is busy" in text
    finally:
        scan_semaphore.release()


# ===========================================================================
# 8. Report download security & traversal defenses (Task 5)
# ===========================================================================

def test_download_valid_report(client, tmp_path, monkeypatch):
    """Valid rs.* report file is served with text/plain and nosniff."""
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / "rs.vul.example.com.2026-10-01_120000"
    report_file.write_text("SwiftScan Vulnerability Report\nTarget: example.com\n", encoding="utf-8")

    monkeypatch.setenv("SWIFTSCAN_REPORTS_DIR", str(reports_dir))
    response = client.get(f"/api/reports/{report_file.name}")
    assert response.status_code == 200
    assert response.mimetype == "text/plain"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert b"SwiftScan Vulnerability Report" in response.data


def test_download_traversal_dotdot_rejected(client):
    """Directory traversal attempt (../setup.py) fails regex check and returns 404."""
    response = client.get("/api/reports/../setup.py")
    assert response.status_code == 404


def test_download_traversal_encoded_rejected(client):
    """URL-encoded traversal (%2e%2e%2f) fails regex check and returns 404."""
    response = client.get("/api/reports/%2e%2e%2fsetup.py")
    assert response.status_code == 404


def test_download_non_rs_file_rejected(client, tmp_path, monkeypatch):
    """Files in reports/ that do not match the rs.* regex are rejected."""
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    arbitrary_file = reports_dir / "secret.txt"
    arbitrary_file.write_text("private", encoding="utf-8")

    monkeypatch.setenv("SWIFTSCAN_REPORTS_DIR", str(reports_dir))
    response = client.get("/api/reports/secret.txt")
    assert response.status_code == 404


# ===========================================================================
# 9. Authentication checks (Task 8)
# ===========================================================================

def test_auth_token_protection(client, monkeypatch):
    """When SWIFTSCAN_TOKEN is set, all /api/* routes require valid auth."""
    monkeypatch.setenv("SWIFTSCAN_TOKEN", "supersecret123")

    # Unauthenticated -> 401
    resp_unauth = client.get("/api/tools")
    assert resp_unauth.status_code == 401

    # Wrong token -> 401
    resp_wrong = client.get("/api/tools", headers={"Authorization": "Bearer wrongtoken"})
    assert resp_wrong.status_code == 401

    # Valid Bearer Authorization header -> 200
    resp_bearer = client.get("/api/tools", headers={"Authorization": "Bearer supersecret123"})
    assert resp_bearer.status_code == 200

    # Valid Cookie -> 200
    client.set_cookie("swiftscan_token", "supersecret123")
    resp_cookie = client.get("/api/tools")
    assert resp_cookie.status_code == 200

    # Tokens in the query string are NOT accepted (they leak into logs/history)
    client.delete_cookie("swiftscan_token")
    resp_query = client.get("/api/tools?token=supersecret123")
    assert resp_query.status_code == 401

    # A bare Authorization value without the Bearer scheme is not accepted either
    resp_bare = client.get("/api/tools", headers={"Authorization": "supersecret123"})
    assert resp_bare.status_code == 401


def test_run_web_requires_token_on_public_bind(monkeypatch):
    """run_web on host 0.0.0.0 must exit if SWIFTSCAN_TOKEN is not set."""
    monkeypatch.delenv("SWIFTSCAN_TOKEN", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        run_web(host="0.0.0.0", port=5000)
    assert excinfo.value.code == 1
