"""
API Sources module for SwiftScan.

Set these environment variables (or add them to a local .env file) to enable
each source. A source with no key set is reported as "not_configured", not
"failed":
    SHODAN_API_KEY
    VIRUSTOTAL_API_KEY
    CENSYS_API_TOKEN (or CENSYS_PERSONAL_ACCESS_TOKEN)   Censys *Platform* PAT
    CENSYS_ORG_ID                                         optional, Censys organization ID

Every finding is a dict with:
    source  : "Shodan" | "VirusTotal" | "Censys"
    status  : one of the STATUS_* constants below
    ok      : True only when status == "ok"
    skipped : True when the lookup was not attempted (not_configured / no_ip)
    reason  : human-readable explanation, or None
    data    : dict of results, or None
"""
import json
import logging
import os
import socket
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("swiftscan.api_sources")

# All outbound OSINT lookups share this timeout so a slow/unreachable API
# can't hang the whole scan indefinitely.
REQUEST_TIMEOUT = 10  # seconds

_USER_AGENT = "SwiftScan/1.2 (+https://github.com/praptidethe11/SwiftScan.git)"

# Distinguishing these in reports is the point: "you forgot to configure a
# key" and "your key was rejected" need different fixes.
STATUS_OK = "ok"
STATUS_NOT_CONFIGURED = "not_configured"   # no key set; nothing was attempted
STATUS_NO_IP = "no_ip"                     # target did not resolve; nothing was attempted
STATUS_AUTH_FAILED = "auth_failed"         # HTTP 401 / 403
STATUS_NO_DATA = "no_data"                 # HTTP 404: the service has no record of this target
STATUS_RATE_LIMITED = "rate_limited"       # HTTP 429
STATUS_FAILED = "failed"                   # network error, timeout, 5xx, bad response...

_STATUS_LABELS = {
    STATUS_OK: "OK",
    STATUS_NOT_CONFIGURED: "NOT CONFIGURED",
    STATUS_NO_IP: "SKIPPED",
    STATUS_AUTH_FAILED: "AUTH FAILED",
    STATUS_NO_DATA: "NO DATA",
    STATUS_RATE_LIMITED: "RATE LIMITED",
    STATUS_FAILED: "FAILED",
}

CENSYS_PLATFORM_BASE = "https://api.platform.censys.io/v3/global/asset/host/"
_CENSYS_ACCEPT = "application/vnd.censys.api.v3.host.v1+json"


def status_label(finding):
    """Short upper-case label for a finding's status, for reports and the UI."""
    status = finding.get("status")
    if status is None:  # findings produced before the status field existed
        status = STATUS_OK if finding.get("ok") else (
            STATUS_NOT_CONFIGURED if finding.get("skipped") else STATUS_FAILED)
    return _STATUS_LABELS.get(status, "FAILED")


def _make_finding(source, status, reason=None, data=None):
    return {
        "source": source,
        "status": status,
        "ok": status == STATUS_OK,
        "skipped": status in (STATUS_NOT_CONFIGURED, STATUS_NO_IP),
        "reason": reason,
        "data": data,
    }


def _safe_url(url):
    """scheme://host/path only. Query strings carry secrets (Shodan takes its
    key as ?key=...), so they must never reach a log line or a report."""
    parts = urllib.parse.urlsplit(url)
    return "{}://{}{}".format(parts.scheme, parts.netloc, parts.path)


def _load_dotenv_file(dotenv_path=None):
    """Best-effort loader for a local .env file using only the standard library.
    Looks in the working directory first, then next to this module. Variables
    already present in the environment are never overridden."""
    candidates = [dotenv_path] if dotenv_path else [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
    ]
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = val
        except (OSError, UnicodeDecodeError) as e:
            logger.warning("Failed to parse .env file: %s", e)
        return


def load_api_keys_from_env():
    """Load API keys from environment variables or local .env file."""
    _load_dotenv_file()
    return {
        "shodan": os.environ.get("SHODAN_API_KEY", ""),
        "virustotal": os.environ.get("VIRUSTOTAL_API_KEY", ""),
        "censys_token": os.environ.get("CENSYS_API_TOKEN", "") or os.environ.get("CENSYS_PERSONAL_ACCESS_TOKEN", ""),
    }


def _error_detail(body_text):
    """Pull a readable message out of an API error body (never raises)."""
    try:
        parsed = json.loads(body_text)
    except ValueError:
        return body_text[:200]
    if isinstance(parsed, dict):
        err = parsed.get("error") or parsed.get("detail") or parsed.get("message")
        if isinstance(err, dict):  # VirusTotal: {"error": {"code": ..., "message": ...}}
            err = err.get("message") or err.get("code")
        if err:
            return str(err)[:200]
    return body_text[:200]


def _request_json(url, headers=None):
    """GET `url` and parse the body as JSON.

    Returns (data, None, None) on success, or (None, reason, http_status) on
    any failure; http_status is None for non-HTTP failures (network error,
    timeout, bad JSON). Never raises, and `reason` never contains the URL.
    """
    if not url.startswith("https://"):
        return None, "refusing to call a non-HTTPS URL", None
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, **(headers or {})})  # noqa: S310  # nosec B310
    logger.debug("GET %s", _safe_url(url))
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310  # nosec B310
            body = resp.read()
    except urllib.error.HTTPError as e:
        try:
            detail = _error_detail(e.read().decode(errors="replace"))
        except Exception:  # noqa: BLE001 - body is optional detail only
            detail = str(e)
        return None, "HTTP {}: {}".format(e.code, detail), e.code
    except urllib.error.URLError as e:
        return None, "network error: {}".format(e.reason), None
    except socket.timeout:
        return None, "request timed out after {}s".format(REQUEST_TIMEOUT), None
    except (OSError, ValueError) as e:
        return None, "request failed: {}".format(e), None

    try:
        return json.loads(body.decode("utf-8", errors="replace")), None, None
    except json.JSONDecodeError as e:
        return None, "could not parse response as JSON: {}".format(e), None


def _http_get_json(url, headers=None):
    """Compatibility wrapper: returns (data, None) or (None, reason)."""
    data, err, _code = _request_json(url, headers)
    return data, err


def _failure(source, reason, http_status):
    if http_status in (401, 403):
        status = STATUS_AUTH_FAILED
    elif http_status == 404:
        status = STATUS_NO_DATA
    elif http_status == 429:
        status = STATUS_RATE_LIMITED
    else:
        status = STATUS_FAILED
    logger.warning("%s lookup did not succeed: %s (%s)", source, status, reason)
    return _make_finding(source, status, reason)


def _shodan_lookup(resolved_ip, api_key):
    """Shodan host lookup - open ports, banners, and known CVEs for the IP."""
    if not resolved_ip:
        return _make_finding("Shodan", STATUS_NO_IP, "target did not resolve to an IP")

    url = "https://api.shodan.io/shodan/host/{}?key={}".format(
        urllib.parse.quote(resolved_ip), urllib.parse.quote(api_key)
    )
    data, err, code = _request_json(url)
    if err:
        return _failure("Shodan", err, code)

    return _make_finding("Shodan", STATUS_OK, data={
        "ip": resolved_ip,
        "org": data.get("org") or "unknown",
        "os": data.get("os") or "unknown",
        "open_ports": sorted(set(data.get("ports", []))),
        "hostnames": data.get("hostnames", []),
        # CVEs Shodan has already fingerprinted for banners on this host.
        "known_vulns": sorted(data.get("vulns", [])),
    })


def _virustotal_lookup(target, api_key):
    """VirusTotal v3 domain report - vendor malicious/suspicious votes."""
    url = "https://www.virustotal.com/api/v3/domains/{}".format(urllib.parse.quote(target))
    data, err, code = _request_json(url, headers={"x-apikey": api_key})
    if err:
        return _failure("VirusTotal", err, code)

    try:
        attrs = data["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
    except (KeyError, TypeError):
        return _make_finding("VirusTotal", STATUS_FAILED, "unexpected response shape from VirusTotal")

    return _make_finding("VirusTotal", STATUS_OK, data={
        "target": target,
        "malicious_votes": stats.get("malicious", 0),
        "suspicious_votes": stats.get("suspicious", 0),
        "harmless_votes": stats.get("harmless", 0),
        "reputation_score": attrs.get("reputation", "unknown"),
        "categories": attrs.get("categories", {}),
    })


def _censys_lookup(resolved_ip, api_token, org_id=None):
    """Censys Platform API host lookup (api.platform.censys.io/v3).

    This replaces the legacy Search v2 endpoint (search.censys.io/api/v2),
    which authenticates with an API ID + secret and answers 401 to a Platform
    Personal Access Token. The Platform API takes the PAT as a Bearer token;
    `org_id` is optional and only needed for organisation-scoped accounts.
    """
    if not resolved_ip:
        return _make_finding("Censys", STATUS_NO_IP, "target did not resolve to an IP")
    if not api_token:
        return _make_finding("Censys", STATUS_NOT_CONFIGURED, "CENSYS_API_TOKEN not configured")

    url = CENSYS_PLATFORM_BASE + urllib.parse.quote(resolved_ip)
    if org_id:
        url += "?organization_id=" + urllib.parse.quote(org_id)
    data, err, code = _request_json(url, headers={
        "Authorization": "Bearer " + api_token,
        "Accept": _CENSYS_ACCEPT,
    })
    if err:
        return _failure("Censys", err, code)

    # Platform responses nest the host under result.resource; the legacy shape
    # put it directly under result. Accept both so a schema tweak degrades
    # gracefully instead of failing the whole lookup.
    try:
        result = data["result"]
        host = result.get("resource") or result
        services = host.get("services") or []
    except (KeyError, TypeError, AttributeError):
        return _make_finding("Censys", STATUS_FAILED, "unexpected response shape from Censys")

    exposed = set()
    for s in services:
        if not isinstance(s, dict):
            continue
        name = s.get("service_name") or s.get("protocol") or "unknown"
        exposed.add("{}/{}".format(s.get("port"), name))

    return _make_finding("Censys", STATUS_OK, data={
        "ip": resolved_ip,
        "autonomous_system": (host.get("autonomous_system") or {}).get("name", "unknown"),
        "exposed_services": sorted(exposed),
    })


def gather_api_findings(target, resolved_ip=None, api_keys=None):
    """
    Gather API-based OSINT findings for a target.

    Each configured source (API key present in the environment/`api_keys`)
    is queried for real; sources with no key configured are reported as
    "not_configured" rather than attempted, so a run with no keys set still
    completes normally and just shows nothing was queried.

    Returns a list of finding dicts (see the module docstring).
    """
    api_keys = api_keys or load_api_keys_from_env()
    findings = []

    if not api_keys.get("shodan"):
        findings.append(_make_finding("Shodan", STATUS_NOT_CONFIGURED, "SHODAN_API_KEY not set in environment"))
    else:
        findings.append(_shodan_lookup(resolved_ip, api_keys["shodan"]))

    if not api_keys.get("virustotal"):
        findings.append(_make_finding("VirusTotal", STATUS_NOT_CONFIGURED, "VIRUSTOTAL_API_KEY not set in environment"))
    else:
        findings.append(_virustotal_lookup(target, api_keys["virustotal"]))

    if not api_keys.get("censys_token"):
        findings.append(_make_finding("Censys", STATUS_NOT_CONFIGURED, "CENSYS_API_TOKEN not set in environment"))
    else:
        org_id = api_keys.get("censys_org_id") or os.environ.get("CENSYS_ORG_ID", "")
        findings.append(_censys_lookup(resolved_ip, api_keys.get("censys_token"), org_id=org_id or None))

    return findings
