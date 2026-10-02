"""Tests for the engine hardening work: internal-target blocking (#11),
per-scan temp dirs (#12), process-tree kill (#13), shell-free execution (#14),
module field (#15), severity labels (#16), safe update (#17) and the scan
time budget. No real security tools or network are used."""
import os
import subprocess
import sys
import time

import pytest

import swiftscan


# ---------------------------------------------------------------------------
# #11 internal targets
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("host", [
    "127.0.0.1", "127.1.2.3", "10.0.0.5", "172.16.0.1", "192.168.1.1",
    "169.254.169.254", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1",
])
def test_internal_ip_literals_are_rejected(host):
    with pytest.raises(ValueError, match="internal"):
        swiftscan.validate_target(host)


@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.5", "192.168.1.1"])
def test_allow_internal_overrides(host):
    assert swiftscan.validate_target(host, allow_internal=True) == host


def test_hostname_resolving_to_private_ip_is_rejected(monkeypatch):
    monkeypatch.setattr(swiftscan, "_resolved_addresses", lambda h: ["10.1.2.3"])
    with pytest.raises(ValueError, match="resolves|internal"):
        swiftscan.validate_target("sneaky.example.com")


def test_hostname_with_one_private_record_is_rejected(monkeypatch):
    monkeypatch.setattr(swiftscan, "_resolved_addresses", lambda h: ["93.184.216.34", "192.168.0.9"])
    with pytest.raises(ValueError):
        swiftscan.validate_target("mixed.example.com")


def test_ipv4_mapped_ipv6_is_unwrapped():
    assert swiftscan._is_internal_ip("::ffff:127.0.0.1") is True
    assert swiftscan._is_internal_ip("::1") is True
    assert swiftscan._is_internal_ip("8.8.8.8") is False


def test_public_hostname_is_accepted(monkeypatch):
    monkeypatch.setattr(swiftscan, "_resolved_addresses", lambda h: ["93.184.216.34"])
    assert swiftscan.validate_target("example.com") == "example.com"


def test_unresolvable_hostname_is_left_to_the_tools(monkeypatch):
    monkeypatch.setattr(swiftscan, "_resolved_addresses", lambda h: [])
    assert swiftscan.validate_target("no-such-host.invalid") == "no-such-host.invalid"


def test_url_maker_passes_allow_internal_through():
    with pytest.raises(ValueError):
        swiftscan.url_maker("http://10.0.0.5:8080/x")
    assert swiftscan.url_maker("http://10.0.0.5:8080/x", allow_internal=True) == "10.0.0.5"


def test_main_refuses_internal_target_without_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        swiftscan.main(["127.0.0.1", "--nospinner"])
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# #12 per-scan temp dirs
# ---------------------------------------------------------------------------
def test_two_scan_dirs_do_not_collide():
    a, b = swiftscan.make_scan_tempdir(), swiftscan.make_scan_tempdir()
    try:
        assert a != b
        assert swiftscan.get_temp_file("x", a) != swiftscan.get_temp_file("x", b)
    finally:
        for d in (a, b):
            os.rmdir(d)


def _fake_tables(monkeypatch, cmd, binary="python"):
    monkeypatch.setattr(swiftscan.shutil, "which", lambda name: sys.executable)
    monkeypatch.setattr(swiftscan, "tool_names", (["fake", "Fake", binary, 1, "recon"],))
    monkeypatch.setattr(swiftscan, "tool_cmd", ([cmd, ""],))
    monkeypatch.setattr(swiftscan, "tool_resp", (["Found", "m", 1],))
    monkeypatch.setattr(swiftscan, "tool_status", (["MAGIC", 0, swiftscan.proc_low, " < 1s", "fake", []],))
    monkeypatch.setattr(swiftscan, "tools_precheck", [(binary,)])


def test_run_scan_removes_its_own_temp_dir(monkeypatch, tmp_path):
    created = []
    real = swiftscan.make_scan_tempdir
    monkeypatch.setattr(swiftscan, "make_scan_tempdir",
                        lambda: created.append(real()) or created[-1])
    _fake_tables(monkeypatch, f'"{sys.executable}" -c "print(\'MAGIC\')" ')
    events = list(swiftscan.run_scan("example.com", tool_timeout=10))
    assert any(e["event"] == "tool_result" and e["vulnerable"] for e in events)
    assert len(created) == 1 and not os.path.exists(created[0])


def test_run_scan_keeps_caller_supplied_dir(monkeypatch, tmp_path):
    _fake_tables(monkeypatch, f'"{sys.executable}" -c "print(\'MAGIC\')" ')
    list(swiftscan.run_scan("example.com", tool_timeout=10, scan_dir=str(tmp_path)))
    assert "MAGIC" in swiftscan.read_tool_output("fake", str(tmp_path))


def test_run_scan_removes_dir_when_generator_is_closed(monkeypatch):
    created = []
    real = swiftscan.make_scan_tempdir
    monkeypatch.setattr(swiftscan, "make_scan_tempdir",
                        lambda: created.append(real()) or created[-1])
    _fake_tables(monkeypatch, f'"{sys.executable}" -c "print(1)" ')
    gen = swiftscan.run_scan("example.com", tool_timeout=10)
    next(gen)
    gen.close()
    assert not os.path.exists(created[0])


def test_no_command_embeds_an_import_time_temp_path():
    import tempfile
    for prefix, suffix in swiftscan.tool_cmd:
        assert tempfile.gettempdir() not in prefix + suffix
        assert "swiftscan_temp_" not in prefix + suffix


# ---------------------------------------------------------------------------
# #14 shell-free argv building
# ---------------------------------------------------------------------------
def test_build_argv_splits_prefix_target_suffix():
    assert swiftscan.build_argv("nmap -F --open -Pn ", "example.com") == \
        ["nmap", "-F", "--open", "-Pn", "example.com"]


def test_build_argv_attaches_target_inside_a_token():
    assert swiftscan.build_argv("dirb http://", "example.com") == ["dirb", "http://example.com"]
    assert swiftscan.build_argv("xsser --all=http://", "example.com") == ["xsser", "--all=http://example.com"]


def test_build_argv_handles_quotes():
    assert swiftscan.build_argv("nikto -Plugins 'ssl' -host ", "example.com") == \
        ["nikto", "-Plugins", "ssl", "-host", "example.com"]


def test_build_argv_never_interprets_target_as_shell_syntax():
    # Even if validation were bypassed, the value stays ONE literal argument.
    argv = swiftscan.build_argv("nmap -F ", "a.com; touch /tmp/pwned && id")
    assert argv == ["nmap", "-F", "a.com; touch /tmp/pwned && id"]


def test_build_argv_expands_tmp_placeholder(tmp_path):
    argv = swiftscan.build_argv("wget -O @@TMP:wp_check@@ --tries=1 ", "example.com", "/wp-admin",
                                scan_dir=str(tmp_path))
    assert argv[:2] == ["wget", "-O"]
    assert argv[2] == os.path.join(str(tmp_path), "swiftscan_temp_wp_check") + ".body"
    assert argv[-1] == "example.com/wp-admin"


def test_build_argv_wsl_wraps_with_exec():
    argv = swiftscan.build_argv("nmap -F ", "example.com", wsl=True)
    assert argv[:5] == ["wsl", "-d", "kali-linux", "--exec", "nmap"]


def test_every_table_entry_builds_an_argv(tmp_path):
    for prefix, suffix in swiftscan.tool_cmd:
        argv = swiftscan.build_argv(prefix, "example.com", suffix, scan_dir=str(tmp_path))
        assert argv and all(isinstance(a, str) and a for a in argv)
        assert "@@" not in " ".join(argv)


def test_scan_loop_does_not_use_shell(monkeypatch):
    calls = []
    real_popen = subprocess.Popen

    def spy(*a, **k):
        calls.append(k.get("shell"))
        return real_popen(*a, **k)

    monkeypatch.setattr(subprocess, "Popen", spy)
    _fake_tables(monkeypatch, f'"{sys.executable}" -c "print(1)" ')
    list(swiftscan.run_scan("example.com", tool_timeout=10))
    assert calls == [False]


# ---------------------------------------------------------------------------
# #13 process-tree kill
# ---------------------------------------------------------------------------
def test_run_tool_captures_stdout_and_stderr(tmp_path):
    out = tmp_path / "o"
    swiftscan.run_tool([sys.executable, "-c", "import sys; print('a'); print('b', file=sys.stderr)"],
                       str(out), 10)
    assert out.read_text().split() == ["a", "b"]


def test_run_tool_raises_oserror_for_missing_binary(tmp_path):
    with pytest.raises(OSError):
        swiftscan.run_tool(["definitely-not-a-real-binary-xyz"], str(tmp_path / "o"), 5)


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX shell")
def test_timeout_kills_grandchildren_too(tmp_path):
    marker = tmp_path / "marker"
    script = "(sleep 1.5; touch %s) & wait" % marker
    start = time.time()
    with pytest.raises(subprocess.TimeoutExpired):
        swiftscan.run_tool(["sh", "-c", script], str(tmp_path / "o"), 0.4)
    assert time.time() - start < 5
    time.sleep(2.0)
    assert not marker.exists(), "orphaned grandchild survived the timeout"


# ---------------------------------------------------------------------------
# #15 module field
# ---------------------------------------------------------------------------
def test_every_check_has_a_known_module():
    assert len(swiftscan.tool_names) == 80
    for row in swiftscan.tool_names:
        assert row[swiftscan.ARG_MODULE] in swiftscan.MODULE_NAMES, row[0]


def test_every_module_has_checks():
    used = {row[swiftscan.ARG_MODULE] for row in swiftscan.tool_names}
    assert used == set(swiftscan.MODULE_NAMES)


def test_dos_checks_are_isolated_in_their_own_module():
    dos = {r[0] for r in swiftscan.tool_names if r[swiftscan.ARG_MODULE] == "dos"}
    assert dos == {"nmap_sloris", "uniscan_ministresser"}


# ---------------------------------------------------------------------------
# #16 severity labels
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("code,label", [("c", "Critical"), ("h", "High"), ("m", "Medium"),
                                        ("l", "Low"), ("i", "Info"), (None, "Unknown")])
def test_severity_label(code, label):
    assert swiftscan.severity_label(code) == label


# ---------------------------------------------------------------------------
# #17 update never overwrites the running file
# ---------------------------------------------------------------------------
def test_update_refuses_outside_a_git_checkout(monkeypatch):
    monkeypatch.setattr(swiftscan, "check_internet", lambda: True)
    monkeypatch.setattr(swiftscan.os.path, "isdir", lambda p: False)
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: ran.append(a))
    with pytest.raises(SystemExit) as exc:
        swiftscan.main(["--update", "--nospinner"])
    assert exc.value.code == 1
    assert ran == []


def test_update_uses_git_pull_ff_only(monkeypatch):
    monkeypatch.setattr(swiftscan, "check_internet", lambda: True)
    monkeypatch.setattr(swiftscan.os.path, "isdir", lambda p: True)
    monkeypatch.setattr(swiftscan.shutil, "which", lambda n: "/usr/bin/git")
    seen = {}

    class R:
        returncode = 0
        stdout = b"Already up to date."

    def fake_run(argv, **k):
        seen["argv"], seen["shell"] = argv, k.get("shell", False)
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(SystemExit) as exc:
        swiftscan.main(["--update", "--nospinner"])
    assert exc.value.code == 0
    assert seen["argv"][0] == "git" and "--ff-only" in seen["argv"] and not seen["shell"]


# ---------------------------------------------------------------------------
# time budget
# ---------------------------------------------------------------------------
def test_budget_exhausted_skips_remaining_checks_but_completes(monkeypatch):
    _fake_tables(monkeypatch, f'"{sys.executable}" -c "print(1)" ')
    events = list(swiftscan.run_scan("example.com", tool_timeout=10, max_total_seconds=1e-9))
    assert [e["event"] for e in events if e["event"] in ("tool_skipped", "tool_result")] == ["tool_skipped"]
    done = events[-1]
    assert done["event"] == "scan_complete" and done["budget_exhausted"] is True


# ---------------------------------------------------------------------------
# CLI honours SWIFTSCAN_REPORTS_DIR
# ---------------------------------------------------------------------------
def test_get_reports_dir_defaults_to_relative_reports(monkeypatch):
    monkeypatch.delenv("SWIFTSCAN_REPORTS_DIR", raising=False)
    assert swiftscan.get_reports_dir() == "reports"


def test_get_reports_dir_uses_env_var(monkeypatch, tmp_path):
    monkeypatch.setenv("SWIFTSCAN_REPORTS_DIR", str(tmp_path / "out"))
    assert swiftscan.get_reports_dir() == str(tmp_path / "out")


def test_cli_writes_reports_to_env_dir(monkeypatch, tmp_path):
    out = tmp_path / "elsewhere"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SWIFTSCAN_REPORTS_DIR", str(out))
    monkeypatch.setattr(swiftscan, "_resolved_addresses", lambda h: ["93.184.216.34"])

    def fake_run_scan(target, skip=None, tool_timeout=None, **kwargs):
        yield {"event": "scan_complete", "total_elapsed": 0.1, "checks_run": 0, "checks_skipped": 0,
               "vulnerabilities_found": 0, "findings": [], "api_findings": []}

    monkeypatch.setattr(swiftscan, "run_scan", fake_run_scan)
    swiftscan.main(["example.com", "--nospinner", "--json"])
    assert list(out.glob("rs.json.example.com.*.json"))
    assert not (tmp_path / "reports").exists()
