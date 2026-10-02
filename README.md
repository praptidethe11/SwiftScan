# SwiftScan — Multi-Tool Web Vulnerability Scanner

> **SwiftScan** automates *binge-tool-scanning* — running multiple security tools back-to-back, correlating results, attempting to reduce false positives, and producing a structured report — all under one roof.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Vulnerability Checks](#vulnerability-checks)
- [Platform Support & Tool Availability](#platform-support--tool-availability)
- [Installation](#installation)
  - [Option A — Native Kali Linux (Recommended)](#option-a--native-kali-linux-recommended)
  - [Option B — Windows with WSL 2 (Kali)](#option-b--windows-with-wsl-2-kali)
  - [Option C — Docker (Any OS)](#option-c--docker-any-os)
- [Running SwiftScan](#running-swiftscan)
  - [CLI Mode](#cli-mode)
  - [Web App Mode](#web-app-mode)
- [API Keys Configuration](#api-keys-configuration)
- [Reading the Results](#reading-the-results)
- [Troubleshooting](#troubleshooting)
- [Security Considerations / Authorized Use Only](#security-considerations--authorized-use-only)
- [Development](#development)
- [CLI Reference](#cli-reference)
- [Contribution](#contribution)

---

## Quick Start

> **Only scan systems you own or have written permission to test.** See [Security Considerations](#security-considerations--authorized-use-only).

This is the shortest path from a fresh machine to your first scan. Each step links to the detailed section if you need more.

### 0. What you need

| Requirement | Why |
|---|---|
| **Python 3.11 or newer** (`python3 --version`) | runs SwiftScan |
| **git** | to download the code (and for `--update`) |
| **The scanning tools** (nmap, nikto, ...) | SwiftScan only *drives* them. Checks whose tool is missing are skipped. Kali Linux has most of them; on Windows use WSL 2 (Kali); or use Docker, which has everything. |
| API keys *(optional)* | Shodan / VirusTotal / Censys enrichment |

No Kali and no WSL? Skip to [Option C: Docker](#option-c--docker-any-os).

### 1. Download SwiftScan

```bash
git clone https://github.com/praptidethe11/SwiftScan.git
cd SwiftScan
```

### 2. Create a virtual environment and install Python packages

The command-line scanner uses only the Python standard library. The packages are needed for the **web UI**; installing them is harmless if you only use the CLI.

**Linux / macOS / WSL (bash):**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows PowerShell:**

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Windows cmd:**

```bat
py -3 -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

> PowerShell refuses to run `Activate.ps1`? Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use cmd.

### 3. Install the scanning tools

On Kali / Debian: the `apt-get` command in [Option A](#option-a--native-kali-linux-recommended). On Windows: [Option B](#option-b--windows-with-wsl-2-kali). Not sure what you have? Step 5 shows which tools were found.

### 4. Add your API keys *(optional)*

Without keys SwiftScan still runs; the OSINT section of the report just says `NOT CONFIGURED`.

```bash
cp .env.example .env          # Linux / macOS / WSL / Git Bash
copy .env.example .env        # Windows cmd
Copy-Item .env.example .env   # Windows PowerShell
```

Open `.env` in any editor and fill in the keys you have (no quotes, no spaces around `=`):

```ini
SHODAN_API_KEY=...
VIRUSTOTAL_API_KEY=...
CENSYS_API_TOKEN=...          # a Censys *Platform* personal access token
CENSYS_ORG_ID=...             # optional
```

`.env` is git-ignored. Never commit it or paste it into an issue. Details: [API Keys Configuration](#api-keys-configuration).

### 5. Check the installation

```bash
python3 swiftscan.py --help
```

You should see the usage text. (On Windows use `python` or `py -3` instead of `python3`.) Then start your first scan; the first thing it prints is a **tool check** showing which tools were found and which are missing.

### 6. Run your first scan from the command line

```bash
python3 swiftscan.py your-domain.example --nospinner --json
```

Useful extras: `--tool-timeout 60` (kill any single check after 60 s), `--skip nmap` (skip a tool), `--allow-internal` (needed to scan a private/loopback address you own). A full scan can take a long time; `Ctrl+C` skips the current check.

### 7. Or use the web interface

Start it:

```bash
python3 web_app.py            # same as: python3 swiftscan.py --web
```

Then open **http://localhost:5000**, type the target, tick **"I am authorized to test this target"**, choose a time budget and press **Start scan**. Results stream in as each check finishes.

By default the web UI only answers requests from the same machine. To set an access token (required for `--host 0.0.0.0` or Docker), set it **before** starting the server:

```bash
export SWIFTSCAN_TOKEN="choose-a-long-random-string"      # Linux / macOS / WSL
```
```powershell
$env:SWIFTSCAN_TOKEN = "choose-a-long-random-string"      # Windows PowerShell
```
```bat
rem Windows cmd (no spaces around =, and nothing after the value)
set SWIFTSCAN_TOKEN=choose-a-long-random-string
```

With a token set, the browser sends you to **/login**; paste the same string there. Generate a good token with `python3 -c "import secrets; print(secrets.token_hex(24))"`.

To allow scanning your own private addresses from the web UI, also set `SWIFTSCAN_ALLOW_INTERNAL=1` the same way.

### 8. Read the results

Everything is written to the `reports/` folder (see [Reading the Results](#reading-the-results)). The web UI shows links to the three reports when a scan finishes.

### 9. Stop and update

Stop the web server with `Ctrl+C`. Update with `python3 swiftscan.py --update` (git checkouts only; it runs `git pull --ff-only`), then re-run `pip install -r requirements.txt` if `requirements.txt` changed.

---

## Features

- **80 vulnerability checks** across DNS, HTTP, SSL/TLS, port scanning, CMS detection, and more.
- Orchestrates `nmap`, `nikto`, `dnsrecon`, `wafw00f`, `sslyze`, `amass`, `theharvester`, and 15+ other tools automatically.
- **Web App UI** — real-time streaming scan results in your browser (`--web` flag).
- **OSINT enrichment** via Shodan, VirusTotal, and Censys API integrations.
- **CWE mapping** on discovered vulnerabilities.
- Severity classification: Critical / High / Medium / Low / Informational.
- Vulnerability definitions + remediation guidance per finding.
- Executive summary at scan completion.
- **Cross-platform**: runs on Linux natively, on Windows via WSL 2, or on any OS via Docker.

---

## Vulnerability Checks

| Category | Examples |
|---|---|
| DNS | Zone transfers, sub-domain brute-force, DNS load balancers |
| HTTP | Open directories, CMS detection (WordPress / Joomla / Drupal), WAF detection |
| SSL/TLS | HEARTBLEED, FREAK, POODLE, CCS Injection, LOGJAM, OCSP |
| Ports | Commonly exposed services (RDP, SMB, SNMP, DB ports) |
| Injection | Shallow XSS, SQLi, BSQLi banners |
| DoS / LFI | Slow-Loris, Local/Remote File Inclusion, Remote Code Execution |

---

## Platform Support & Tool Availability

SwiftScan auto-detects available tools and skips those that aren't installed — partial environments still work.

| Tool | Native Kali | Windows + WSL 2 (Kali) | Docker |
|---|:---:|:---:|:---:|
| `nmap` | ✅ | ✅ native | ✅ |
| `nikto` | ✅ | ✅ via WSL | ✅ |
| `dnsrecon` | ✅ | ✅ via WSL | ✅ |
| `wafw00f` | ✅ | ✅ via WSL | ✅ |
| `sslyze` | ✅ | ✅ via WSL | ✅ |
| `amass` | ✅ | ✅ via WSL | ✅ |
| `theharvester` | ✅ | ✅ via WSL | ✅ |
| `dirb` | ✅ | ✅ via WSL | ✅ |
| `fierce` | ✅ | ✅ via WSL | ✅ |
| `dmitry` | ✅ | ✅ via WSL | ✅ |
| `dnsenum` | ✅ | ✅ via WSL | ✅ |
| `whatweb` | ✅ | ✅ via WSL | ✅ |
| `wapiti` | ✅ | ✅ via WSL | ✅ |
| `xsser` | ✅ | ✅ via WSL | ✅ |
| `uniscan` | ✅ | ✅ via WSL | ✅ |
| `davtest` | ✅ | ✅ via WSL | ✅ |
| `lbd` | ✅ | ✅ via WSL | ✅ |
| `dnsmap` | ✅ | ✅ via WSL | ✅ |
| `dnswalk` | ✅ | ✅ via WSL | ✅ |
| `wget` | ✅ | ✅ Python built-in | ✅ |
| `whois` | ✅ | ✅ Python built-in | ✅ |
| `host` | ✅ | ✅ Python built-in | ✅ |
| `golismero` | ❌ abandoned | ❌ | ❌ |

> **Windows note:** `wget`, `whois`, and `host` have native Python fallback engines — they work on all platforms with no external dependency. All other Linux tools are auto-bridged through your Kali WSL instance.

---

## Installation

### Option A — Native Kali Linux (Recommended)

Kali ships with most tools pre-installed. Install any that are missing:

```bash
sudo apt-get update && sudo apt-get install -y \
  nmap nikto dnsrecon wafw00f sslyze amass theharvester \
  dirb fierce dmitry dnsenum whatweb wapiti xsser uniscan \
  davtest lbd dnsmap dnswalk wget whois
```

Clone SwiftScan and install Python dependencies:

```bash
git clone https://github.com/praptidethe11/SwiftScan.git
cd SwiftScan
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt     # needs Python 3.11+; only the web UI uses these packages
```

---

### Option B — Windows with WSL 2 (Kali)

SwiftScan automatically bridges to your Kali WSL instance — no manual routing is needed. When a tool isn't in the Windows PATH, SwiftScan transparently re-runs it through `wsl -d kali-linux`.

**Step 1 — Prerequisites on Windows:**

- WSL 2 enabled: [Microsoft WSL install guide](https://learn.microsoft.com/en-us/windows/wsl/install)
- Kali Linux in WSL: `wsl --install -d kali-linux`
- Python 3 on Windows: [python.org](https://www.python.org/downloads/)
- nmap on Windows (for port scans): [nmap.org](https://nmap.org/download.html#windows)

**Step 2 — Install security tools inside Kali WSL** (run once):

```powershell
# Launch Kali WSL shell
wsl -d kali-linux
```

Then inside the Kali shell:

```bash
sudo apt-get update && sudo apt-get install -y \
  nikto dnsrecon wafw00f sslyze amass theharvester \
  dirb fierce dmitry dnsenum whatweb wapiti xsser uniscan \
  davtest lbd dnsmap dnswalk
```

**Step 3 — Clone SwiftScan on Windows:**

```powershell
git clone https://github.com/praptidethe11/SwiftScan.git
cd SwiftScan
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt     # needs Python 3.11+; only the web UI uses these packages
```

SwiftScan will automatically detect tools in your Kali WSL at startup. Tools not installed in WSL will be skipped with a message listing what's missing.

---

### Option C — Docker (Any OS)

Docker is the easiest way to get **all tools on any OS** — Windows, macOS, or any Linux distro — without touching your system's PATH.

```bash
git clone https://github.com/praptidethe11/SwiftScan.git
cd SwiftScan

# Build the image (installs all Kali security tools inside the container)
docker build -t swiftscan .
```

**Run a CLI scan** (reports go to the `/data/reports` volume, so they survive the container):

```bash
docker run --rm -v swiftscan-data:/data --entrypoint python3 swiftscan \
  swiftscan.py your-domain.example --nospinner --json
```

**Copy the reports out of the volume** into `./reports-out`:

```bash
docker run --rm -v swiftscan-data:/data -v "$(pwd)/reports-out:/out" busybox cp -r /data/reports/. /out/
```

**Run the Web App (http://localhost:5000):**

```bash
docker run --rm -p 127.0.0.1:5000:5000 -e SWIFTSCAN_TOKEN="$(openssl rand -hex 24)" \
  -v swiftscan-data:/data swiftscan
```

Reports and logs go to the `/data` volume. A request through a published port does not count as "local" to the container, so **`SWIFTSCAN_TOKEN` is required** to use the web UI in Docker; without it every request gets a 403. That also means a published port is never an open scanner by accident. Publish the port on `127.0.0.1` as above unless you really need remote access (then put it behind HTTPS).

> The image is based on `kalilinux/kali-rolling` and installs every supported tool. For reproducible builds pin the base image: `docker build --build-arg BASE_IMAGE=kalilinux/kali-rolling@sha256:<digest> -t swiftscan .` (see the comment at the top of the `Dockerfile` for how to get the digest). `nmap` is given the network capabilities it needs for raw scans through file capabilities, so the container runs as a non-root user.

---

## Running SwiftScan

### CLI Mode

```bash
# Basic scan
python3 swiftscan.py example.com

# Skip specific tools
python3 swiftscan.py example.com --skip dmitry --skip theHarvester

# Also produce a machine-readable JSON report
python3 swiftscan.py example.com --json

# Set a per-tool timeout (default: 120 s)
python3 swiftscan.py example.com --tool-timeout 60

# Disable the progress spinner
python3 swiftscan.py example.com --nospinner
```

### Web App Mode

```bash
python3 swiftscan.py --web
# or equivalently
python3 web_app.py
```

Open **http://localhost:5000** in your browser. Results stream in real time via Server-Sent Events (SSE) — no page reloads needed.

Security defaults of the web UI:

- With no `SWIFTSCAN_TOKEN` set it only answers requests that come from the same machine. Set a token to allow remote access (`--host 0.0.0.0` refuses to start without one); sign in at `/login`.
- Other websites cannot start scans through your browser (cross-site requests and DNS-rebinding `Host` headers are refused).
- One scan runs at a time. The scan keeps running and its reports are saved even if you close the tab.
- Loopback, private, link-local and cloud-metadata targets are refused. Set `SWIFTSCAN_ALLOW_INTERNAL=1` (web) or pass `--allow-internal` (CLI) to scan your own internal hosts.
- Run it with a single gunicorn worker (the "one scan" slot is per process).

| Variable | Purpose | Default |
|---|---|---|
| `SWIFTSCAN_TOKEN` | Access token for the web UI | unset (local-only) |
| `SWIFTSCAN_ALLOW_INTERNAL` | Allow private/loopback targets in the web UI | off |
| `SWIFTSCAN_REPORTS_DIR` | Where reports are written | `./reports` next to the app |
| `SWIFTSCAN_LOG_DIR` | Where `swiftscan_error.log` and `swiftscan_audit.log` go | current directory |
| `SWIFTSCAN_DEBUG` | Debug-level logging | off |

`swiftscan_audit.log` has one JSON line per event (scan started/completed/rejected, logins, denied requests) with timestamp, client IP, target and the consent flag. The consent checkbox is a record that the operator certified authorization; it is not an access control.

---

## API Keys Configuration

SwiftScan can enrich results with OSINT data from **Shodan**, **VirusTotal**, and **Censys** if you supply API keys.

1. Copy the example file:

   ```bash
   cp .env.example .env        # Linux / macOS / WSL
   copy .env.example .env      # Windows CMD
   ```

2. Open `.env` and paste your keys:

   ```ini
   SHODAN_API_KEY=your_shodan_key
   VIRUSTOTAL_API_KEY=your_virustotal_key
   CENSYS_API_TOKEN=your_censys_pat_token
   CENSYS_ORG_ID=your_censys_organization_id   # optional
   ```

   `CENSYS_API_TOKEN` must be a **Censys Platform** personal access token (api.platform.censys.io). The old Search v2 API ID/secret pair is not used.

Reports label each source as `OK`, `NOT CONFIGURED` (no key set), `AUTH FAILED` (key rejected, HTTP 401/403), `NO DATA`, `RATE LIMITED` or `FAILED`, so a missing key and a bad key are easy to tell apart. API keys are never written to logs or reports.

The `.env` file is listed in `.gitignore` and will never be committed to Git.

---

## Reading the Results

Every scan writes into the reports folder: `./reports` by default, or the folder in `SWIFTSCAN_REPORTS_DIR` (the Docker image uses `/data/reports`). `<stamp>` is the date and time, so repeat scans never overwrite each other.

| File | Written by | What it contains |
|---|---|---|
| `rs.vul.<target>.<stamp>` | CLI (only if something was found) and web | Each finding: title, severity (Critical / High / Medium / Low / Info), definition, remediation, CWE reference |
| `rs.api.<target>.<stamp>` | CLI and web | OSINT results per source, or the reason a source gave nothing |
| `rs.json.<target>.<stamp>.json` | web always, CLI with `--json` | Everything above as JSON, plus counts, elapsed time and whether the time budget cut the scan short |
| `rs.dbg.<target>.<stamp>` | CLI | Raw output of every tool, for checking a finding by hand |

**OSINT statuses** in `rs.api.*`:

| Status | Meaning | What to do |
|---|---|---|
| `OK` | Data returned | n/a |
| `NOT CONFIGURED` | No key in `.env` | Add the key (optional) |
| `AUTH FAILED` | The service rejected your key (HTTP 401/403) | Check/regenerate the key. Censys needs a **Platform** personal access token |
| `NO DATA` | The service has no record of this target (404) | Normal for small or new sites |
| `RATE LIMITED` | Too many requests (429) | Wait, or check your plan's limits |
| `FAILED` | Network error, timeout or unexpected reply | Re-run; see `swiftscan_error.log` |
| `SKIPPED` | The target did not resolve to an IP | Check the hostname |

**Treat findings as leads, not proof.** Detection is signature matching on tool output: confirm each finding manually (the `rs.dbg.*` file or the tool itself) before reporting it.

**Logs:** `swiftscan_error.log` (warnings and errors) and, for the web UI, `swiftscan_audit.log` (one JSON line per scan, login and denied request). Both are in the current directory, or in `SWIFTSCAN_LOG_DIR`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'flask'` | Packages not installed, or the virtual environment isn't active | Activate `.venv`, then `pip install -r requirements.txt` |
| `SyntaxError` / odd errors on start | Python older than 3.11 | Check `python3 --version`; install 3.11+ |
| Most checks show as **skipped** | Their tool isn't installed (or not visible from Windows/WSL) | Install the tools ([Option A/B](#installation)); the web UI's tool list (`/api/tools`) shows what was found |
| `... is or resolves to an internal/reserved address and cannot be scanned` | Built-in safety block on loopback, private, link-local and cloud-metadata addresses | Only if it is *your* host: pass `--allow-internal` (CLI) or set `SWIFTSCAN_ALLOW_INTERNAL=1` (web) |
| Browser shows **403 "Access restricted to localhost"** | Opened from another machine, through Docker, or via a proxy without `SWIFTSCAN_TOKEN` set | Open it on the same machine, or set `SWIFTSCAN_TOKEN` and restart |
| Browser keeps sending you to `/login` | Token required | Enter the exact value of `SWIFTSCAN_TOKEN`. After 5 wrong tries wait a minute |
| **403 "Cross-site requests are not allowed"** | The page was opened through a different host name or by another site | Use the same URL for the page and the API (e.g. `http://localhost:5000`) |
| **"Server is busy"** | One scan runs at a time | Wait for it to finish (it continues even if its tab was closed) |
| `Binding to 0.0.0.0 requires SWIFTSCAN_TOKEN` | Safety check for network-reachable servers | Set `SWIFTSCAN_TOKEN` first, or bind to `127.0.0.1` |
| Docker: web UI returns 403 | No token (see above) | Run with `-e SWIFTSCAN_TOKEN=...` |
| Docker: `permission denied` writing reports | Reports directory isn't on the `/data` volume | Mount `-v swiftscan-data:/data` |
| A check shows **timed out** | The tool took longer than the per-tool limit | Raise `--tool-timeout` (CLI) or the budget (web); the maximum per tool is 300 s in the web UI |
| Scan stops early with *"Time budget reached"* | The overall time budget was used up | Increase the budget; remaining checks were skipped, reports are still written |
| `nmap` raw/UDP scans find nothing as a normal user | They need elevated network access | Run as root/administrator, or use the Docker image (nmap is given the needed capabilities) |
| Windows: tools "not found" although installed in Kali | Tools must be in the `kali-linux` WSL distro | `wsl -d kali-linux`, install them there, re-run |

Still stuck? Re-run with `SWIFTSCAN_DEBUG=1` and read `swiftscan_error.log`.

---

## Security Considerations / Authorized Use Only

**WARNING**: SwiftScan is a security testing tool that may perform active scanning, enumeration, and vulnerability detection against target systems. You must have explicit written authorization before scanning any target. Unauthorized scanning may violate laws and regulations in your jurisdiction.

- Only scan systems you own or have explicit permission to test
- Use in accordance with all applicable laws and regulations
- The authors assume no liability for misuse or damage caused by this tool
- This tool is intended for authorized security assessments, CTF competitions, and educational purposes only
- Always respect rate limits and terms of service when using integrated APIs (Shodan, VirusTotal, Censys)
- Findings come from signature matching on tool output and need manual verification; expect false positives and false negatives
- The `dos` module checks (Slowloris, stress test) can disrupt a target. Skip them unless the engagement allows it
- Target hostnames are resolved once for the internal-address check; a hostile DNS server could answer differently when the tools resolve it again

## Development

```bash
pip install --require-hashes -r requirements-dev.txt
pytest -q                                  # tests (no real tools or network needed)
ruff check .                               # lint
bandit -c pyproject.toml -r . -ll          # security lint
pip-audit --require-hashes -r requirements.txt   # known-vulnerable dependencies
```

Dependencies are declared in `requirements.in` / `requirements-dev.in` and locked with hashes by `pip-compile --generate-hashes --strip-extras` (Python 3.11+). CI runs the same four checks.

---

## CLI Reference

```
usage: python3 swiftscan.py [options] [URL]

Positional:
  URL                    Target URL/domain to scan.

Options:
  -h, --help             Show this help message and exit.
  -u, --update           Update SwiftScan (git checkouts only: runs `git pull --ff-only`).
  --allow-internal       Permit scanning loopback/private/link-local addresses.
  -s TOOL, --skip TOOL   Skip a specific tool (repeatable).
  -n, --nospinner        Disable the idle spinner/loader.
  -j, --json             Write a JSON report alongside the text report.
  --tool-timeout SECS    Kill any single tool after N seconds (default: 120).
  -w, --web              Launch the interactive web application UI.
```

---

## Contribution

1. Fork the repository.
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :rocket:


