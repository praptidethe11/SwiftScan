## 2026-10-02 security hardening round

**Web UI (`web_app.py`, `index.html`)**
- Local-only by default: without `SWIFTSCAN_TOKEN` only same-machine requests are served (enforced per request, so it also holds under gunicorn). With a token: `Authorization: Bearer` or the `/login` cookie (HttpOnly, SameSite=Strict, Secure on HTTPS, 8 h), compared in constant time, login rate-limited. Tokens in the query string and bare `Authorization` values are no longer accepted.
- Cross-site requests and mismatched `Host` headers are refused (CSRF / DNS rebinding).
- Scans run in a background thread: reports are written and the scan slot is released even if the browser disconnects. Slot is acquired before the stream starts.
- Budget/timeout/skip validated (NaN/inf/zero/negative rejected, values clamped); the budget is now an overall time limit for the scan.
- Reports served only if the name matches `rs.*`; listing shows report files only; reports directory is absolute (`SWIFTSCAN_REPORTS_DIR`).
- Text report shows Critical/High/Medium/Low/Info instead of `c/h/m/l/i`; OSINT report shows the new statuses.
- Extra headers (`object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, `no-store` on API responses); JSON error bodies for `/api/*`; `/healthz` probe; `--debug` refused on non-loopback binds.
- UI shows a notice when the time budget cut a scan short; XSS sinks use `textContent` / `esc()`.

**Engine (`swiftscan.py`)**
- Internal-target blocking (loopback, private, link-local, CGNAT, multicast, reserved, metadata, IPv4-mapped IPv6; every resolved address checked) unless `--allow-internal`.
- Per-scan temp directory, always cleaned up; no shared `/tmp` file names.
- No more `shell=True`: commands are tokenised into argv lists (the target is inserted after tokenising); WSL uses `--exec`.
- On timeout or Ctrl+C the whole process tree is killed (process group on POSIX, `taskkill /T /F` on Windows).
- Every check has a `module` (recon, ports, tls, webvulns, discovery, fingerprint, dos) for the planned per-module UI; result events carry it.
- `--update` now only does `git pull --ff-only` in a git checkout and never overwrites the running script from a download.
- `os.system` calls for clear-screen/cursor replaced with ANSI escapes.
- The CLI now honours `SWIFTSCAN_REPORTS_DIR` (default is still `./reports`), so `docker run ... swiftscan.py` writes to the `/data` volume.

**OSINT (`api_sources.py`)**
- Statuses: `ok`, `not_configured`, `auth_failed`, `no_data`, `rate_limited`, `failed`, `no_ip`.
- Censys moved to the Platform API (`api.platform.censys.io/v3`, Bearer PAT, optional `CENSYS_ORG_ID`); the legacy Search v2 call returned 401 for Platform tokens.
- Only HTTPS is called; URLs with query strings (the Shodan key) are never logged.

**Logging, packaging, CI**
- `swiftscan_logging.py`: rotating `swiftscan_error.log` plus a JSON-lines `swiftscan_audit.log`.
- Dependencies locked with hashes (`requirements.in` -> `requirements.txt`, `requirements-dev.in` -> `requirements-dev.txt`); minimum Python is now 3.11.
- Dockerfile: non-root user, hashed installs, working healthcheck, single gthread worker, `/data` volume, base image pinnable via `BASE_IMAGE`.
- `setup.py`: correct `py_modules`, `web` extra, console entry point. `pyproject.toml` holds the ruff and bandit configuration.
- CI (`.github/workflows/ci.yml`) runs ruff, bandit, pip-audit and pytest and fails on any of them; the same checks are available as pre-commit hooks.
- Tests: 198 (was 57), including engine, web-hardening and OSINT suites.

**Documentation**
- README: new step-by-step Quick Start (bash, PowerShell and cmd variants), Reading the Results (report files and OSINT statuses), Troubleshooting table, Development section, corrected Docker CLI example, install steps use `requirements.txt` instead of the dev requirements.

## 2026-09-26 follow-up fixes

- **Fixed: `main()` was never called.** The file had no `if __name__ ==
"__main__": main()` guard at the bottom, despite the docstring and the
  entry below both describing one as already present. Result: running
  `python3 swiftscan.py` with any arguments - `--help` included - did
  nothing at all. Added the guard.
- **Fixed a real UnboundLocalError crash.** `main()`'s per-scan counters
  (`rs_vul_list`, `rs_total_elapsed`, `rs_skipped_checks`) were module-level
  globals that `main()` reassigned (e.g. `rs_skipped_checks =
rs_skipped_checks + 1`) without a `global` statement. Python treats a
  name assigned anywhere in a function as local to that whole function, so
  the first `tool_skipped`/`tool_result`/`tool_interrupted`/`tool_timeout`
  event raised `UnboundLocalError` - i.e. every real scan against a real
  target crashed immediately; only `--help`/`--update` ever ran cleanly.
  Fixed by making them ordinary locals inside `main()` instead of module
  globals. Added `test_main_scan_flow_does_not_raise_unboundlocalerror`,
  which drives `main()`'s full event loop with `run_scan()` mocked out, so
  this can't silently regress again.
- **Dead code removed:** module-level `tool = 0`, `runTest = 1`,
  `rs_vul_num`, `rs_avail_tools` (never referenced anywhere), and a
  `deploying_index` variable that was assigned but never read.
- **ASCII banner** replaced: the old art didn't actually spell "SwiftScan"
  (holdover abstract glyph from the original rapidscan logo) and printed a
  broken `[url](url)` Markdown-link artifact literally to the terminal.
  Now renders "SwiftScan" as block letters, and the repo URL prints plain.
- **Housekeeping:** `rapidscan.egg-info/` (a stale build-artifact directory
  name left over from before the project was renamed) renamed to
  `swiftscan.egg-info/`, and `*.egg-info/` added to `.gitignore` so it isn't
  tracked going forward, since it's regenerated by `pip install -e .`.
- **Not fixed here, flagged for you:** the `.env` in this project (already
  gitignored, so never committed) contains real-looking Shodan/VirusTotal/
  Censys API keys. Worth rotating those regardless, since the file has been
  handled outside git.

## Security

- **Shell/command injection fix (main gap).** `target` was interpolated
  directly into shell command strings run via `subprocess(..., shell=True)`,
  with no validation beyond stripping a scheme and `www.`. A target like
  `example.com; rm -rf /` would execute the appended command. Fixed with:
  - `validate_target()` — whitelists hostnames/IPs to `[A-Za-z0-9.-]`, used by
    `url_maker()` so an invalid target is rejected with a clear error instead
    of ever reaching a shell.
  - `shlex.quote(target)` at the point `target` is spliced into each scan
    command, as defense-in-depth on top of the validation above.
- **Safer self-update.** `--update` now hashes the file with `hashlib.sha1`
  instead of shelling out to `sha1sum`, and the download failure path is
  handled explicitly instead of an unguarded `subprocess.check_output`.
  (Known remaining limitation: the download is over HTTPS but not signature
  verified against a known-good checksum, so it's trust-on-first-use like the
  original — full fix would mean code-signing the releases, which is out of
  scope here.)

## Error handling

- Removed every bare `except:` (5 of them) and replaced with the specific
  exceptions each call site can actually raise, logged to `swiftscan_error.log`
  via the `logging` module rather than silently swallowed.
- **Fixed a real bug**, not just style: the debug-log loop used
  `except: break`, so the _first_ tool with no output file (e.g. skipped
  because it wasn't installed) silently truncated the debug log for every
  tool after it in that run's (randomized) scan order. Changed to
  `except OSError: continue`.
- `check_internet()` rewritten to use `subprocess.run(...)` directly instead
  of round-tripping through a `rs_net` file in the current directory (which
  was also a race condition if two instances ran concurrently).
- `open(temp_file).read()` (no `with`, file handle never closed) replaced
  with a context manager and an explicit `OSError` fallback.

## Cleanup / dead code

- Removed the duplicate `import random`.
- Removed commented-out spinner cursor experiments.
- Replaced the shelled-out `date +%Y-%m-%d` call with `datetime.date.today()`.
- Removed redundant `.close()` calls on files already closed by a `with` block.

## Structure / testability

- The entire CLI flow (argument parsing, tool pre-checks, scan loop, report
  generation) is now under `if __name__ == "__main__":`. Previously,
  `import swiftscan` alone would parse `sys.argv` and could call `sys.exit()`
  — making the module untestable. Only the guard was added; no logic moved,
  so behavior when run as `python3 swiftscan.py ...` is unchanged.
- Reports (`rs.dbg.*`, `rs.vul.*`) now write to `reports/` instead of the
  current directory.

## New

- `tests/test_swiftscan.py` — 38 tests covering `validate_target`/`url_maker`
  (including the injection-payload cases the fix addresses), `display_time`,
  `vul_info`, `terminal_size`, `check_internet` (mocked), and a smoke test
  that `python3 swiftscan.py --help` still runs cleanly end-to-end.
- `requirements.txt` / `requirements-dev.txt`.
- `.gitignore` for scan output and test caches.

## Verified

- `python3 -m pytest` → 38/38 passing.
- `python3 swiftscan.py --help` and `python3 swiftscan.py <invalid target>`
  behave correctly.
- A live run against `example.com` completes end-to-end and produces a
  correct `reports/rs.dbg.*` file (this environment only had a handful of the
  scanner's ~20 external tools installed, so most of the 80 checks were
  correctly reported as skipped rather than run).

## Not touched (out of scope for this pass)

- The README's "under development" items (PDF reports, Metasploit
  integration, AI-driven follow-up scans, Docker support) are still
  unimplemented — they're feature work, not gaps/bugs.
- No parallelism was added; the scan loop is still sequential, as documented.
