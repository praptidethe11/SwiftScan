import sys
import argparse
import subprocess
import os
import time
import random
import threading
import re
import shlex
import logging
import socket
import shutil
import json
import datetime
import tempfile
import atexit
import ipaddress
import signal
import urllib.request
import urllib.error
from urllib.parse import urlsplit

import api_sources
import swiftscan_logging

# Ensure Python Scripts directory is discoverable on Windows for pip-installed security tools
if os.name == 'nt':
    scripts_dir = os.path.join(sys.prefix, "Scripts")
    if scripts_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = scripts_dir + os.pathsep + os.environ.get("PATH", "")

def _clear_screen():
    """Clear the terminal with an ANSI sequence (no shell involved). Modern
    Windows 10+ consoles understand it; older ones just show the sequence."""
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def _set_cursor(visible):
    """Show or hide the terminal cursor with ANSI escapes (no shell involved)."""
    if sys.stdout.isatty():
        sys.stdout.write("\033[?25h" if visible else "\033[?25l")
        sys.stdout.flush()


def get_reports_dir():
    """Directory for CLI reports: $SWIFTSCAN_REPORTS_DIR if set, otherwise a
    'reports' folder in the current working directory (the historical default).
    The Docker image sets the variable so reports land on the /data volume."""
    return os.environ.get("SWIFTSCAN_REPORTS_DIR", "").strip() or "reports"


def make_scan_tempdir():
    """Create an isolated temp directory for a single scan (#12)."""
    return tempfile.mkdtemp(prefix="swiftscan_")


def get_temp_file(key, scan_dir=None):
    """Return a cross-platform temp file path for a check.

    If *scan_dir* is provided (created by make_scan_tempdir()), files land
    there; otherwise falls back to the legacy global temp dir.
    """
    if scan_dir:
        return os.path.join(scan_dir, "swiftscan_temp_" + str(key))
    return os.path.join(tempfile.gettempdir(), "swiftscan_temp_" + str(key))

def cleanup_temp_files():
    """Safely remove leftover swiftscan temporary files across any OS."""
    td = tempfile.gettempdir()
    try:
        for f in os.listdir(td):
            if f.startswith("swiftscan_temp_"):
                try:
                    os.remove(os.path.join(td, f))
                except OSError:
                    pass
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Command construction and execution (no shell) -- #13 / #14
# ---------------------------------------------------------------------------
# tool_cmd entries are still [prefix, suffix] pairs with the target spliced
# in between, but they are now tokenised with shlex.split() and executed as an
# argv list with shell=False. The target is substituted AFTER tokenising, so
# nothing in it can ever be interpreted as shell syntax, and a validated
# target that happens to start with '-' still cannot become an option because
# validate_target() requires a leading alphanumeric.
#
# "@@TMP:<key>@@" in a command is replaced with a file inside the per-scan
# temp dir (used for wget -O and wapiti -o, which write their own files).
_TARGET_SENTINEL = "@@SS_TARGET@@"
_TMP_PLACEHOLDER_RE = re.compile(r"@@TMP:([A-Za-z0-9_]+)@@")


def build_argv(prefix, target, suffix="", scan_dir=None, wsl=False):
    """Turn a [prefix, suffix] table entry plus a validated target into argv."""
    def _tmp(match):
        path = get_temp_file(match.group(1), scan_dir) + ".body"
        return _win_path_to_wsl(path) if wsl else path

    argv = []
    for token in shlex.split(prefix + _TARGET_SENTINEL + suffix, posix=True):
        token = token.replace(_TARGET_SENTINEL, target)
        argv.append(_TMP_PLACEHOLDER_RE.sub(_tmp, token))
    if wsl:
        # --exec runs the command directly instead of through the default
        # Linux shell, so no argument is ever re-parsed by a shell.
        argv = ["wsl", "-d", "kali-linux", "--exec"] + argv
    return argv


def _kill_process_tree(proc):
    """Kill proc and every child it spawned (nmap, nikto etc. fork helpers)."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        else:
            # start_new_session=True made proc the leader of its own process
            # group, so pgid == pid and this reaches the whole tree.
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=2)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                pass
            try:
                os.killpg(proc.pid, signal.SIGKILL)  # anything that ignored SIGTERM
            except ProcessLookupError:
                pass
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug("Could not kill process tree for pid %s: %s", proc.pid, e)
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("Process %s did not exit after kill", proc.pid)


def run_tool(argv, out_path, timeout):
    """Run argv with stdout+stderr captured to out_path.

    Raises subprocess.TimeoutExpired (after killing the whole process tree)
    when the tool exceeds `timeout`, and re-raises KeyboardInterrupt the same
    way. Raises OSError if the binary cannot be started.
    """
    extra = {}
    if os.name == "nt":
        extra["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        extra["start_new_session"] = True
    with open(out_path, "wb") as out:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out,
                                stderr=subprocess.STDOUT, shell=False, **extra)
        try:
            proc.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            _kill_process_tree(proc)
            raise
    return proc.returncode


def read_tool_output(key, scan_dir=None):
    """Return a check's captured output (log + any -O/-o body file), or None
    if the check never produced output (skipped / binary missing)."""
    base = get_temp_file(key, scan_dir)
    parts = []
    for path in (base, base + ".body"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                parts.append(f.read())
        except OSError:
            continue
    return "\n".join(parts) if parts else None


_WSL_CACHE = None

def _win_path_to_wsl(path):
    """Convert a Windows absolute path (e.g. C:\\Users\\foo) to WSL /mnt/ form."""
    # Normalise backslashes and strip trailing separator
    path = path.replace('\\', '/')
    if len(path) >= 2 and path[1] == ':':
        drive = path[0].lower()
        rest = path[2:]
        return '/mnt/' + drive + rest
    return path

def get_wsl_available_tools():
    """Detect security tools installed inside WSL (checks kali-linux distro).

    Checks both 'theHarvester' and 'theharvester' because Kali apt packages
    the binary under the lowercase name while older/manual installs may use
    the mixed-case name. The canonical entry in tool_names uses 'theHarvester'
    so both names are added to the cache set.
    """
    global _WSL_CACHE
    if _WSL_CACHE is not None:
        return _WSL_CACHE
    _WSL_CACHE = set()
    if os.name != 'nt' or shutil.which('wsl') is None:
        return _WSL_CACHE
    try:
        # 'which' prints found paths; missing tools are simply omitted (exit 1
        # when *none* are found, but stdout still contains the ones that were).
        # theHarvester/theharvester: check both casings; add canonical name.
        probe = (
            'which amass davtest dirb dmitry dnsenum dnsmap dnsrecon dnswalk '
            'fierce host lbd nikto sslyze theHarvester theharvester uniscan '
            'wafw00f wapiti wget whatweb whois xsser 2>/dev/null; true'
        )
        cmd = ['wsl', '-d', 'kali-linux', 'bash', '-c', probe]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, timeout=15)
        for line in res.stdout.strip().splitlines():
            tool_base = line.strip().split('/')[-1]
            if not tool_base:
                continue
            # Normalise harvester casing to match tool_names table entry
            if tool_base == 'theharvester':
                tool_base = 'theHarvester'
            _WSL_CACHE.add(tool_base)
    except Exception as e:
        logger.debug("WSL tool discovery check skipped: %s", e)
    return _WSL_CACHE

# Logging (writes swiftscan's own errors/warnings, separate from tool output).
# Kept at WARNING by default so normal scan UX (all the print() calls) is unaffected;
# run with SWIFTSCAN_DEBUG=1 to see INFO-level detail too.
swiftscan_logging.setup_logging()
logger = logging.getLogger("swiftscan")


CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'

# Scan Time Elapser
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


def terminal_size():
    """Best-effort terminal width; falls back to 80 columns if it can't be read."""
    try:
        return shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception as e:
        logger.debug("terminal_size() fallback: %s", e)
        return 80


# Only letters, digits, dots and hyphens are valid in a hostname/domain label.
# Anything else (spaces, `;`, `|`, `&`, `$`, backticks, quotes, newlines...) is
# rejected outright, since `target` is later interpolated into shell command
# strings run with subprocess(..., shell=True) — this is what stands between a
# scan target and shell/command injection.
_VALID_HOST_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?$')


# ---------------------------------------------------------------------------
# #11 Internal-target / SSRF block
# ---------------------------------------------------------------------------
# Ranges that ipaddress's is_private/is_reserved flags do not cover.
_EXTRA_BLOCKED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),      # carrier-grade NAT (RFC 6598)
    ipaddress.ip_network("0.0.0.0/8"),          # "this network"; 0.0.0.0 reaches localhost on Linux
    ipaddress.ip_network("169.254.169.254/32"), # cloud metadata service (also link-local)
]


def _is_internal_ip(addr_str):
    """True if addr_str is loopback, private, link-local, multicast, reserved,
    unspecified, carrier-grade NAT or a cloud metadata address. IPv4-mapped
    IPv6 addresses (::ffff:127.0.0.1) are unwrapped first."""
    try:
        addr = ipaddress.ip_address(addr_str.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    if (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
            or addr.is_reserved or addr.is_unspecified):
        return True
    return any(addr in net for net in _EXTRA_BLOCKED_NETWORKS if net.version == addr.version)


def _resolved_addresses(host):
    """All IPv4/IPv6 addresses `host` resolves to (empty list if it doesn't)."""
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except (OSError, UnicodeError):
        return []


def validate_target(host, allow_internal=False):
    """Raise ValueError if `host` isn't a plausible, shell-safe hostname/IP.

    Unless allow_internal=True, also rejects any host that is - or resolves
    to - an internal/reserved address (#11). Every resolved address is
    checked, so a name with one public and one private A record is refused.

    Known limitation: the tools resolve the name again when they run, so a
    DNS-rebinding attacker could still return a different answer later.
    """
    if not host or len(host) > 253 or not _VALID_HOST_RE.match(host):
        raise ValueError(
            "'{}' doesn't look like a valid domain/host. Only letters, digits, "
            "dots and hyphens are allowed.".format(host)
        )
    if not allow_internal:
        for addr in _resolved_addresses(host):
            if _is_internal_ip(addr):
                raise ValueError(
                    "'{}' is or resolves to an internal/reserved address ({}) and "
                    "cannot be scanned. Pass --allow-internal to override.".format(host, addr)
                )
    return host


def url_maker(url, allow_internal=False):
    """Normalize user input (bare domain or full URL) down to just the host,
    then validate it so it's safe to use as a scan target."""
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    # Drop a userinfo@ prefix or :port suffix if present, we only want the host.
    host = host.rsplit('@', 1)[-1].split(':', 1)[0]
    return validate_target(host, allow_internal=allow_internal)


def resolve_ip(host):
    """Best-effort DNS resolution. Returns None (not an exception) on failure,
    since a resolution failure just means callers that need an IP (Shodan)
    are skipped - it shouldn't abort the whole scan."""
    try:
        return socket.gethostbyname(host)
    except OSError as e:
        logger.warning("Could not resolve %s: %s", host, e)
        return None


def check_internet():
    """Returns True if github.com responds to a single ping, else False.
    Uses subprocess directly (no shell, no intermediate file) so there's no
    temp-file race and no dependency on the `rm`/`>` shell being available."""
    try:
        ping_arg = '-n' if os.name == 'nt' else '-c'
        result = subprocess.run(
            ['ping', ping_arg, '1', 'github.com'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=10,
        )
        out = result.stdout.decode(errors='replace')
        return ("0% packet loss" in out) or ("0% loss" in out) or ("bytes=" in out) or ("TTL=" in out)
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("check_internet() failed: %s", e)
        return False


# Initializing the color module class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'


# Classifies the Vulnerability's Severity
def vul_info(val):
    result =''
    if val == 'c':
        result = bcolors.BG_CRIT_TXT+" critical "+bcolors.ENDC
    elif val == 'h':
        result = bcolors.BG_HIGH_TXT+" high "+bcolors.ENDC
    elif val == 'm':
        result = bcolors.BG_MED_TXT+" medium "+bcolors.ENDC
    elif val == 'l':
        result = bcolors.BG_LOW_TXT+" low "+bcolors.ENDC
    else:
        result = bcolors.BG_INFO_TXT+" info "+bcolors.ENDC
    return result


# #16 — Map short severity codes to human-readable labels for text reports
_SEVERITY_LABELS = {'c': 'Critical', 'h': 'High', 'm': 'Medium', 'l': 'Low', 'i': 'Info'}

def severity_label(code):
    """Return the human-readable severity label for a code (h/m/l/c/i)."""
    return _SEVERITY_LABELS.get(code, code or 'Unknown')

# Safe legend symbol for non-UTF8 terminals (Windows cp1252)
try:
    "●".encode(sys.stdout.encoding or 'utf-8')
    _DOT = "●"
except (UnicodeEncodeError, AttributeError):
    _DOT = "*"

# Legends
proc_high = bcolors.BADFAIL + _DOT + bcolors.ENDC
proc_med  = bcolors.WARNING + _DOT + bcolors.ENDC
proc_low  = bcolors.OKGREEN + _DOT + bcolors.ENDC

# Links the vulnerability with threat level and remediation database
def vul_remed_info(v1,v2,v3):
    print(bcolors.BOLD+"Vulnerability Threat Level"+bcolors.ENDC)
    print("\t"+vul_info(v2)+" "+bcolors.WARNING+str(tool_resp[v1][0])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Definition"+bcolors.ENDC)
    print("\t"+bcolors.BADFAIL+str(tools_fix[v3-1][1])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Remediation"+bcolors.ENDC)
    print("\t"+bcolors.OKGREEN+str(tools_fix[v3-1][2])+bcolors.ENDC)


# SwiftScan Help Context
def helper():
        print(bcolors.OKBLUE+"Information:"+bcolors.ENDC)
        print("------------")
        print("\t./swiftscan.py example.com: Scans the domain example.com.")
        print("\t./swiftscan.py example.com --skip dmitry --skip theHarvester: Skip the 'dmitry' and 'theHarvester' tests.")
        print("\t./swiftscan.py example.com --nospinner: Disable the idle loader/spinner.")
        print("\t./swiftscan.py example.com --json: Also write a machine-readable JSON report.")
        print("\t./swiftscan.py example.com --tool-timeout 300: Kill any single check after 300s.")
        print("\t./swiftscan.py 192.168.1.5 --allow-internal: Permit scanning a private/loopback address.")
        print("\t./swiftscan.py --update   : Updates the scanner (git checkouts only).")
        print("\t./swiftscan.py --help     : Displays this help context.")
        print(bcolors.OKBLUE+"Interactive:"+bcolors.ENDC)
        print("------------")
        print("\tCtrl+C: Skips current test.")
        print("\tCtrl+Z: Quits SwiftScan.")
        print(bcolors.OKBLUE+"Legends:"+bcolors.ENDC)
        print("--------")
        print("\t["+proc_high+"]: Scan process may take longer times (not predictable).")
        print("\t["+proc_med+"]: Scan process may take less than 10 minutes.")
        print("\t["+proc_low+"]: Scan process may take less than a minute or two.")
        print(bcolors.OKBLUE+"Vulnerability Information:"+bcolors.ENDC)
        print("--------------------------")
        print("\t"+vul_info('c')+": Requires immediate attention as it may lead to compromise or service unavailability.")
        print("\t"+vul_info('h')+"    : May not lead to an immediate compromise, but there are considerable chances for probability.")
        print("\t"+vul_info('m')+"  : Attacker may correlate multiple vulnerabilities of this type to launch a sophisticated attack.")
        print("\t"+vul_info('l')+"     : Not a serious issue, but it is recommended to tend to the finding.")
        print("\t"+vul_info('i')+"    : Not classified as a vulnerability, simply an useful informational alert to be considered.\n")


# Clears Line
def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K") #clears until EOL

# SwiftScan Logo
def logo():
    print(bcolors.WARNING)
    logo_ascii = r"""
     ____          _  __ _   ____
    / ___|_      _(_)/ _| |_/ ___|  ___ __ _ _ __
    \___ \ \ /\ / / | |_| __\___ \ / __/ _` | '_ \
     ___) \ V  V /| |  _| |_ ___) | (_| (_| | | | |
    |____/ \_/\_/ |_|_|  \__|____/ \___\__,_|_| |_|
    """ + bcolors.ENDC + """
                (The Multi-Tool Web Vulnerability Scanner)


                https://github.com/praptidethe11/SwiftScan.git
    """
    try:
        print(logo_ascii)
    except UnicodeEncodeError:
        print(logo_ascii.encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8', errors='replace'))
    print(bcolors.ENDC)



# Initiliazing the idle loader/spinner class
class Spinner:
    busy = False
    delay = 0.005 # 0.05

    @staticmethod
    def spinning_cursor():
        # A single blank "frame" - the visual effect comes from the background
        # color cycling in spinner_task(), not from a rotating character.
        while 1:
            for cursor in ' ':
                yield cursor
    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay):
            self.delay = delay
        self.disabled = False

    def spinner_task(self):
        inc = 0
        try:
            while self.busy:
                if not self.disabled:
                    x = bcolors.BG_SCAN_TXT_START+next(self.spinner_generator)+bcolors.BG_SCAN_TXT_END
                    inc = inc + 1
                    print(x,end='')
                    if inc>random.uniform(0,terminal_size()):  # noqa: S311  # nosec B311
                        print(end="\r")
                        bcolors.BG_SCAN_TXT_START = '\x1b[6;30;'+str(round(random.uniform(40,47)))+'m'  # noqa: S311  # nosec B311
                        inc = 0
                    sys.stdout.flush()
                time.sleep(self.delay)
                if not self.disabled:
                    sys.stdout.flush()

        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"SwiftScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

    def start(self):
        self.busy = True
        try:
            threading.Thread(target=self.spinner_task).start()
        except Exception:
            print("\n")

    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"SwiftScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

# End ofloader/spinner class

# Instantiating the spinner/loader class
spinner = Spinner()



# Scanners that will be used and filename rotation (default: enabled (1))
tool_names = [
                #1
                ["host","Host - Checks for existence of IPV6 address.","host",1],

                #2
                ["aspnet_config_err","ASP.Net Misconfiguration - Checks for ASP.Net Misconfiguration.","wget",1],

                #3
                ["wp_check","WordPress Checker - Checks for WordPress Installation.","wget",1],

                #4
                ["drp_check", "Drupal Checker - Checks for Drupal Installation.","wget",1],

                #5
                ["joom_check", "Joomla Checker - Checks for Joomla Installation.","wget",1],

                #6
                ["uniscan","Uniscan - Checks for robots.txt & sitemap.xml","uniscan",1],

                #7
                ["wafw00f","Wafw00f - Checks for Application Firewalls.","wafw00f",1],

                #8
                ["nmap","Nmap - Fast Scan [Only Few Port Checks]","nmap",1],

                #9
                ["theHarvester","The Harvester - Scans for emails using Google's passive search.","theHarvester",1],

                #10
                ["dnsrecon","DNSRecon - Attempts Multiple Zone Transfers on Nameservers.","dnsrecon",1],

                #11
                #["fierce","Fierce - Attempts Zone Transfer [No Brute Forcing]","fierce",1],

                #12
                ["dnswalk","DNSWalk - Attempts Zone Transfer.","dnswalk",1],

                #13
                ["whois","WHOis - Checks for Administrator's Contact Information.","whois",1],

                #14
                ["nmap_header","Nmap [XSS Filter Check] - Checks if XSS Protection Header is present.","nmap",1],

                #15
                ["nmap_sloris","Nmap [Slowloris DoS] - Checks for Slowloris Denial of Service Vulnerability.","nmap",1],

                #16
                ["sslyze_hbleed","SSLyze - Checks only for Heartbleed Vulnerability.","sslyze",1],

                #17
                ["nmap_hbleed","Nmap [Heartbleed] - Checks only for Heartbleed Vulnerability.","nmap",1],

                #18
                ["nmap_poodle","Nmap [POODLE] - Checks only for Poodle Vulnerability.","nmap",1],

                #19
                ["nmap_ccs","Nmap [OpenSSL CCS Injection] - Checks only for CCS Injection.","nmap",1],

                #20
                ["nmap_freak","Nmap [FREAK] - Checks only for FREAK Vulnerability.","nmap",1],

                #21
                ["nmap_logjam","Nmap [LOGJAM] - Checks for LOGJAM Vulnerability.","nmap",1],

                #22
                ["sslyze_ocsp","SSLyze - Checks for OCSP Stapling.","sslyze",1],

                #23
                ["sslyze_zlib","SSLyze - Checks for ZLib Deflate Compression.","sslyze",1],

                #24
                ["sslyze_reneg","SSLyze - Checks for Secure Renegotiation Support and Client Renegotiation.","sslyze",1],

                #25
                ["sslyze_resum","SSLyze - Checks for Session Resumption Support with [Session IDs/TLS Tickets].","sslyze",1],

                #26
                ["lbd","LBD - Checks for DNS/HTTP Load Balancers.","lbd",1],

                #27
                ["golismero_dns_malware","Golismero - Checks if the domain is spoofed or hijacked.","golismero",1],

                #28
                ["golismero_heartbleed","Golismero - Checks only for Heartbleed Vulnerability.","golismero",1],

                #29
                ["golismero_brute_url_predictables","Golismero - BruteForces for certain files on the Domain.","golismero",1],

                #30
                ["golismero_brute_directories","Golismero - BruteForces for certain directories on the Domain.","golismero",1],

                #31
                ["golismero_sqlmap","Golismero - SQLMap [Retrieves only the DB Banner]","golismero",1],

                #32
                ["dirb","DirB - Brutes the target for Open Directories.","dirb",1],

                #33
                ["xsser","XSSer - Checks for Cross-Site Scripting [XSS] Attacks.","xsser",1],

                #34
                ["golismero_ssl_scan","Golismero SSL Scans - Performs SSL related Scans.","golismero",1],

                #35
                ["golismero_zone_transfer","Golismero Zone Transfer - Attempts Zone Transfer.","golismero",1],

                #36
                ["golismero_nikto","Golismero Nikto Scans - Uses Nikto Plugin to detect vulnerabilities.","golismero",1],

                #37
                ["golismero_brute_subdomains","Golismero Subdomains Bruter - Brute Forces Subdomain Discovery.","golismero",1],

                #38
                ["dnsenum_zone_transfer","DNSEnum - Attempts Zone Transfer.","dnsenum",1],

                #39
                ["fierce_brute_subdomains","Fierce Subdomains Bruter - Brute Forces Subdomain Discovery.","fierce",1],

                #40
                ["dmitry_email","DMitry - Passively Harvests Emails from the Domain.","dmitry",1],

                #41
                ["dmitry_subdomains","DMitry - Passively Harvests Subdomains from the Domain.","dmitry",1],

                #42
                ["nmap_telnet","Nmap [TELNET] - Checks if TELNET service is running.","nmap",1],

                #43
                ["nmap_ftp","Nmap [FTP] - Checks if FTP service is running.","nmap",1],

                #44
                ["nmap_stuxnet","Nmap [STUXNET] - Checks if the host is affected by STUXNET Worm.","nmap",1],

                #45
                ["webdav","WebDAV - Checks if WEBDAV enabled on Home directory.","davtest",1],

                #46
                ["golismero_finger","Golismero - Does a fingerprint on the Domain.","golismero",1],

                #47
                ["uniscan_filebrute","Uniscan - Brutes for Filenames on the Domain.","uniscan",1],

                #48
                ["uniscan_dirbrute", "Uniscan - Brutes Directories on the Domain.","uniscan",1],

                #49
                ["uniscan_ministresser", "Uniscan - Stress Tests the Domain.","uniscan",1],

                #50
                ["uniscan_rfi","Uniscan - Checks for LFI, RFI and RCE.","uniscan",1],

                #51
                ["uniscan_xss","Uniscan - Checks for XSS, SQLi, BSQLi & Other Checks.","uniscan",1],

                #52
                ["nikto_xss","Nikto - Checks for Apache Expect XSS Header.","nikto",1],

                #53
                ["nikto_subrute","Nikto - Brutes Subdomains.","nikto",1],

                #54
                ["nikto_shellshock","Nikto - Checks for Shellshock Bug.","nikto",1],

                #55
                ["nikto_internalip","Nikto - Checks for Internal IP Leak.","nikto",1],

                #56
                ["nikto_putdel","Nikto - Checks for HTTP PUT DEL.","nikto",1],

                #57
                ["nikto_headers","Nikto - Checks the Domain Headers.","nikto",1],

                #58
                ["nikto_ms01070","Nikto - Checks for MS10-070 Vulnerability.","nikto",1],

                #59
                ["nikto_servermsgs","Nikto - Checks for Server Issues.","nikto",1],

                #60
                ["nikto_outdated","Nikto - Checks if Server is Outdated.","nikto",1],

                #61
                ["nikto_httpoptions","Nikto - Checks for HTTP Options on the Domain.","nikto",1],

                #62
                ["nikto_cgi","Nikto - Enumerates CGI Directories.","nikto",1],

                #63
                ["nikto_ssl","Nikto - Performs SSL Checks.","nikto",1],

                #64
                ["nikto_sitefiles","Nikto - Checks for any interesting files on the Domain.","nikto",1],

                #65
                ["nikto_paths","Nikto - Checks for Injectable Paths.","nikto",1],

                #66
                ["dnsmap_brute","DNSMap - Brutes Subdomains.","dnsmap",1],

                #67
                ["nmap_sqlserver","Nmap - Checks for MS-SQL Server DB","nmap",1],

                #68
                ["nmap_mysql", "Nmap - Checks for MySQL DB","nmap",1],

                #69
                ["nmap_oracle", "Nmap - Checks for ORACLE DB","nmap",1],

                #70
                ["nmap_rdp_udp","Nmap - Checks for Remote Desktop Service over UDP","nmap",1],

                #71
                ["nmap_rdp_tcp","Nmap - Checks for Remote Desktop Service over TCP","nmap",1],

                #72
                ["nmap_full_ps_tcp","Nmap - Performs a Full TCP Port Scan","nmap",1],

                #73
                ["nmap_full_ps_udp","Nmap - Performs a Full UDP Port Scan","nmap",1],

                #74
                ["nmap_snmp","Nmap - Checks for SNMP Service","nmap",1],

                #75
                ["aspnet_elmah_axd","Checks for ASP.net Elmah Logger","wget",1],

                #76
                ["nmap_tcp_smb","Checks for SMB Service over TCP","nmap",1],

                #77
                ["nmap_udp_smb","Checks for SMB Service over UDP","nmap",1],

                #78
                ["wapiti","Wapiti - Checks for SQLi, RCE, XSS and Other Vulnerabilities","wapiti",1],

                #79
                ["nmap_iis","Nmap - Checks for IIS WebDAV","nmap",1],

                #80
                ["whatweb","WhatWeb - Checks for X-XSS Protection Header","whatweb",1],

                #81
                ["amass","AMass - Brutes Domain for Subdomains","amass",1]
            ]


# Command that is used to initiate the tool (with parameters and extra params)
tool_cmd   = [
                #1
                ["host ",""],

                #2
                ["wget -O @@TMP:aspnet_config_err@@ --tries=1 ","/%7C~.aspx"],

                #3
                ["wget -O @@TMP:wp_check@@ --tries=1 ","/wp-admin"],

                #4
                ["wget -O @@TMP:drp_check@@ --tries=1 ","/user"],

                #5
                ["wget -O @@TMP:joom_check@@ --tries=1 ","/administrator"],

                #6
                ["uniscan -e -u ",""],

                #7
                ["wafw00f ",""],

                #8
                ["nmap -F --open -Pn ",""],

                #9
                ["theHarvester -l 50 -b censys -d ",""],

                #10
                ["dnsrecon -d ",""],

                #11
                #["fierce -wordlist xxx -dns ",""],

                #12
                ["dnswalk -d ","."],

                #13
                ["whois ",""],

                #14
                ["nmap -p80 --script http-security-headers -Pn ",""],

                #15
                ["nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn ",""],

                #16
                ["sslyze --heartbleed ",""],

                #17
                ["nmap -p443 --script ssl-heartbleed -Pn ",""],

                #18
                ["nmap -p443 --script ssl-poodle -Pn ",""],

                #19
                ["nmap -p443 --script ssl-ccs-injection -Pn ",""],

                #20
                ["nmap -p443 --script ssl-enum-ciphers -Pn ",""],

                #21
                ["nmap -p443 --script ssl-dh-params -Pn ",""],

                #22
                ["sslyze --certinfo=basic ",""],

                #23
                ["sslyze --compression ",""],

                #24
                ["sslyze --reneg ",""],

                #25
                ["sslyze --resum ",""],

                #26
                ["lbd ",""],

                #27
                ["golismero -e dns_malware scan ",""],

                #28
                ["golismero -e heartbleed scan ",""],

                #29
                ["golismero -e brute_url_predictables scan ",""],

                #30
                ["golismero -e brute_directories scan ",""],

                #31
                ["golismero -e sqlmap scan ",""],

                #32
                ["dirb http://"," -fi"],

                #33
                ["xsser --all=http://",""],

                #34
                ["golismero -e sslscan scan ",""],

                #35
                ["golismero -e zone_transfer scan ",""],

                #36
                ["golismero -e nikto scan ",""],

                #37
                ["golismero -e brute_dns scan ",""],

                #38
                ["dnsenum ",""],

                #39
                ["fierce --domain ",""],

                #40
                ["dmitry -e ",""],

                #41
                ["dmitry -s ",""],

                #42
                ["nmap -p23 --open -Pn ",""],

                #43
                ["nmap -p21 --open -Pn ",""],

                #44
                ["nmap --script stuxnet-detect -p445 -Pn ",""],

                #45
                ["davtest -url http://",""],

                #46
                ["golismero -e fingerprint_web scan ",""],

                #47
                ["uniscan -w -u ",""],

                #48
                ["uniscan -q -u ",""],

                #49
                ["uniscan -r -u ",""],

                #50
                ["uniscan -s -u ",""],

                #51
                ["uniscan -d -u ",""],

                #52
                ["nikto -Plugins 'apache_expect_xss' -host ",""],

                #53
                ["nikto -Plugins 'subdomain' -host ",""],

                #54
                ["nikto -Plugins 'shellshock' -host ",""],

                #55
                ["nikto -Plugins 'cookies' -host ",""],

                #56
                ["nikto -Plugins 'put_del_test' -host ",""],

                #57
                ["nikto -Plugins 'headers' -host ",""],

                #58
                ["nikto -Plugins 'ms10-070' -host ",""],

                #59
                ["nikto -Plugins 'msgs' -host ",""],

                #60
                ["nikto -Plugins 'outdated' -host ",""],

                #61
                ["nikto -Plugins 'httpoptions' -host ",""],

                #62
                ["nikto -Plugins 'cgi' -host ",""],

                #63
                ["nikto -Plugins 'ssl' -host ",""],

                #64
                ["nikto -Plugins 'sitefiles' -host ",""],

                #65
                ["nikto -Plugins 'paths' -host ",""],

                #66
                ["dnsmap ",""],

                #67
                ["nmap -p1433 --open -Pn ",""],

                #68
                ["nmap -p3306 --open -Pn ",""],

                #69
                ["nmap -p1521 --open -Pn ",""],

                #70
                ["nmap -p3389 --open -sU -Pn ",""],

                #71
                ["nmap -p3389 --open -sT -Pn ",""],

                #72
                ["nmap -p1-65535 --open -Pn ",""],

                #73
                ["nmap -p1-65535 -sU --open -Pn ",""],

                #74
                ["nmap -p161 -sU --open -Pn ",""],

                #75
                ["wget -O @@TMP:aspnet_elmah_axd@@ --tries=1 ","/elmah.axd"],

                #76
                ["nmap -p445,137-139 --open -Pn ",""],

                #77
                ["nmap -p137,138 --open -Pn ",""],

                #78
                ["wapiti "," -f txt -o @@TMP:wapiti_out@@"],

                #79
                ["nmap -p80 --script=http-iis-webdav-vuln -Pn ",""],

                #80
                ["whatweb "," -a 1"],

                #81
                ["amass enum -d ",""]
            ]


# Tool Responses (Begins) [Responses + Severity (c - critical | h - high | m - medium | l - low | i - informational) + Reference for Vuln Definition and Remediation]
tool_resp   = [
                #1
                ["Does not have an IPv6 Address. It is good to have one.","i",1],

                #2
                ["ASP.Net is misconfigured to throw server stack errors on screen.","m",2],

                #3
                ["WordPress Installation Found. Check for vulnerabilities corresponds to that version.","i",3],

                #4
                ["Drupal Installation Found. Check for vulnerabilities corresponds to that version.","i",4],

                #5
                ["Joomla Installation Found. Check for vulnerabilities corresponds to that version.","i",5],

                #6
                ["robots.txt/sitemap.xml found. Check those files for any information.","i",6],

                #7
                ["No Web Application Firewall Detected","m",7],

                #8
                ["Some ports are open. Perform a full-scan manually.","l",8],

                #9
                ["Email Addresses Found.","l",9],

                #10
                ["Zone Transfer Successful using DNSRecon. Reconfigure DNS immediately.","h",10],

                #11
                #["Zone Transfer Successful using fierce. Reconfigure DNS immediately.","h",10],

                #12
                ["Zone Transfer Successful using dnswalk. Reconfigure DNS immediately.","h",10],

                #13
                ["Whois Information Publicly Available.","i",11],

                #14
                ["XSS Protection Filter is Disabled.","m",12],

                #15
                ["Vulnerable to Slowloris Denial of Service.","c",13],

                #16
                ["HEARTBLEED Vulnerability Found with SSLyze.","h",14],

                #17
                ["HEARTBLEED Vulnerability Found with Nmap.","h",14],

                #18
                ["POODLE Vulnerability Detected.","h",15],

                #19
                ["OpenSSL CCS Injection Detected.","h",16],

                #20
                ["FREAK Vulnerability Detected.","h",17],

                #21
                ["LOGJAM Vulnerability Detected.","h",18],

                #22
                ["Unsuccessful OCSP Response.","m",19],

                #23
                ["Server supports Deflate Compression.","m",20],

                #24
                ["Secure Client Initiated Renegotiation is supported.","m",21],

                #25
                ["Secure Resumption unsupported with (Sessions IDs/TLS Tickets).","m",22],

                #26
                ["No DNS/HTTP based Load Balancers Found.","l",23],

                #27
                ["Domain is spoofed/hijacked.","h",24],

                #28
                ["HEARTBLEED Vulnerability Found with Golismero.","h",14],

                #29
                ["Open Files Found with Golismero BruteForce.","m",25],

                #30
                ["Open Directories Found with Golismero BruteForce.","m",26],

                #31
                ["DB Banner retrieved with SQLMap.","l",27],

                #32
                ["Open Directories Found with DirB.","m",26],

                #33
                ["XSSer found XSS vulnerabilities.","c",28],

                #34
                ["Found SSL related vulnerabilities with Golismero.","m",29],

                #35
                ["Zone Transfer Successful with Golismero. Reconfigure DNS immediately.","h",10],

                #36
                ["Golismero Nikto Plugin found vulnerabilities.","m",30],

                #37
                ["Found Subdomains with Golismero.","m",31],

                #38
                ["Zone Transfer Successful using DNSEnum. Reconfigure DNS immediately.","h",10],

                #39
                ["Found Subdomains with Fierce.","m",31],

                #40
                ["Email Addresses discovered with DMitry.","l",9],

                #41
                ["Subdomains discovered with DMitry.","m",31],

                #42
                ["Telnet Service Detected.","h",32],

                #43
                ["FTP Service Detected.","c",33],

                #44
                ["Vulnerable to STUXNET.","c",34],

                #45
                ["WebDAV Enabled.","m",35],

                #46
                ["Found some information through Fingerprinting.","l",36],

                #47
                ["Open Files Found with Uniscan.","m",25],

                #48
                ["Open Directories Found with Uniscan.","m",26],

                #49
                ["Vulnerable to Stress Tests.","h",37],

                #50
                ["Uniscan detected possible LFI, RFI or RCE.","h",38],

                #51
                ["Uniscan detected possible XSS, SQLi, BSQLi.","h",39],

                #52
                ["Apache Expect XSS Header not present.","m",12],

                #53
                ["Found Subdomains with Nikto.","m",31],

                #54
                ["Webserver vulnerable to Shellshock Bug.","c",40],

                #55
                ["Webserver leaks Internal IP.","l",41],

                #56
                ["HTTP PUT DEL Methods Enabled.","m",42],

                #57
                ["Some vulnerable headers exposed.","m",43],

                #58
                ["Webserver vulnerable to MS10-070.","h",44],

                #59
                ["Some issues found on the Webserver.","m",30],

                #60
                ["Webserver is Outdated.","h",45],

                #61
                ["Some issues found with HTTP Options.","l",42],

                #62
                ["CGI Directories Enumerated.","l",26],

                #63
                ["Vulnerabilities reported in SSL Scans.","m",29],

                #64
                ["Interesting Files Detected.","m",25],

                #65
                ["Injectable Paths Detected.","l",46],

                #66
                ["Found Subdomains with DNSMap.","m",31],

                #67
                ["MS-SQL DB Service Detected.","l",47],

                #68
                ["MySQL DB Service Detected.","l",47],

                #69
                ["ORACLE DB Service Detected.","l",47],

                #70
                ["RDP Server Detected over UDP.","h",48],

                #71
                ["RDP Server Detected over TCP.","h",48],

                #72
                ["TCP Ports are Open","l",8],

                #73
                ["UDP Ports are Open","l",8],

                #74
                ["SNMP Service Detected.","m",49],

                #75
                ["Elmah is Configured.","m",50],

                #76
                ["SMB Ports are Open over TCP","m",51],

                #77
                ["SMB Ports are Open over UDP","m",51],

                #78
                ["Wapiti discovered a range of vulnerabilities","h",30],

                #79
                ["IIS WebDAV is Enabled","m",35],

                #80
                ["X-XSS Protection is not Present","m",12],

                #81
                ["Found Subdomains with AMass","m",31]



            ]

# Tool Responses (Ends)



# Tool Status (Response Data + Response Code (if status check fails and you still got to push it + Legends + Approx Time + Tool Identification + Bad Responses)
tool_status = [
                #1
                ["has IPv6",1,proc_low," < 15s","ipv6",["not found","has IPv6"]],

                #2
                ["Server Error",0,proc_low," < 30s","asp.netmisconf",["unable to resolve host address","Connection timed out"]],

                #3
                ["wp-login",0,proc_low," < 30s","wpcheck",["unable to resolve host address","Connection timed out"]],

                #4
                ["drupal",0,proc_low," < 30s","drupalcheck",["unable to resolve host address","Connection timed out"]],

                #5
                ["joomla",0,proc_low," < 30s","joomlacheck",["unable to resolve host address","Connection timed out"]],

                #6
                ["[+]",0,proc_low," < 40s","robotscheck",["Use of uninitialized value in unpack at"]],

                #7
                ["No WAF",0,proc_low," < 45s","wafcheck",["appears to be down"]],

                #8
                ["tcp open",0,proc_med," <  2m","nmapopen",["Failed to resolve"]],

                #9
                ["No emails found",1,proc_med," <  3m","harvester",["No hosts found","No emails found"]],

                #10
                ["[+] Zone Transfer was successful!!",0,proc_low," < 20s","dnsreconzt",["Could not resolve domain"]],

                #11
                #["Whoah, it worked",0,proc_low," < 30s","fiercezt",["none"]],

                #12
                ["0 errors",0,proc_low," < 35s","dnswalkzt",["!!!0 failures, 0 warnings, 3 errors."]],

                #13
                ["Admin Email:",0,proc_low," < 25s","whois",["No match for domain"]],

                #14
                ["XSS filter is disabled",0,proc_low," < 20s","nmapxssh",["Failed to resolve"]],

                #15
                ["VULNERABLE",0,proc_high," < 45m","nmapdos",["Failed to resolve"]],

                #16
                ["Server is vulnerable to Heartbleed",0,proc_low," < 40s","sslyzehb",["Could not resolve hostname"]],

                #17
                ["VULNERABLE",0,proc_low," < 30s","nmap1",["Failed to resolve"]],

                #18
                ["VULNERABLE",0,proc_low," < 35s","nmap2",["Failed to resolve"]],

                #19
                ["VULNERABLE",0,proc_low," < 35s","nmap3",["Failed to resolve"]],

                #20
                ["VULNERABLE",0,proc_low," < 30s","nmap4",["Failed to resolve"]],

                #21
                ["VULNERABLE",0,proc_low," < 35s","nmap5",["Failed to resolve"]],

                #22
                ["ERROR - OCSP response status is not successful",0,proc_low," < 25s","sslyze1",["Could not resolve hostname"]],

                #23
                ["VULNERABLE",0,proc_low," < 30s","sslyze2",["Could not resolve hostname"]],

                #24
                ["VULNERABLE",0,proc_low," < 25s","sslyze3",["Could not resolve hostname"]],

                #25
                ["VULNERABLE",0,proc_low," < 30s","sslyze4",["Could not resolve hostname"]],

                #26
                ["does NOT use Load-balancing",0,proc_med," <  4m","lbd",["NOT FOUND"]],

                #27
                ["No vulnerabilities found",1,proc_low," < 45s","golism1",["Cannot resolve domain name","No vulnerabilities found"]],

                #28
                ["No vulnerabilities found",1,proc_low," < 40s","golism2",["Cannot resolve domain name","No vulnerabilities found"]],

                #29
                ["No vulnerabilities found",1,proc_low," < 45s","golism3",["Cannot resolve domain name","No vulnerabilities found"]],

                #30
                ["No vulnerabilities found",1,proc_low," < 40s","golism4",["Cannot resolve domain name","No vulnerabilities found"]],

                #31
                ["No vulnerabilities found",1,proc_low," < 45s","golism5",["Cannot resolve domain name","No vulnerabilities found"]],

                #32
                ["FOUND: 0",1,proc_high," < 35m","dirb",["COULDNT RESOLVE HOST","FOUND: 0"]],

                #33
                ["Could not find any vulnerability!",1,proc_med," <  4m","xsser",["XSSer is not working propertly!","Could not find any vulnerability!"]],

                #34
                ["Occurrence ID",0,proc_low," < 45s","golism6",["Cannot resolve domain name"]],

                #35
                ["DNS zone transfer successful",0,proc_low," < 30s","golism7",["Cannot resolve domain name"]],

                #36
                ["Nikto found 0 vulnerabilities",1,proc_med," <  4m","golism8",["Cannot resolve domain name","Nikto found 0 vulnerabilities"]],

                #37
                ["Possible subdomain leak",0,proc_high," < 30m","golism9",["Cannot resolve domain name"]],

                #38
                ["AXFR record query failed:",1,proc_low," < 45s","dnsenumzt",["NS record query failed:","AXFR record query failed","no NS record for"]],

                #39
                ["Found 0 entries",1,proc_high," < 75m","fierce2",["Found 0 entries","is gimp"]],

                #40
                ["Found 0 E-Mail(s)",1,proc_low," < 30s","dmitry1",["Unable to locate Host IP addr","Found 0 E-Mail(s)"]],

                #41
                ["Found 0 possible subdomain(s)",1,proc_low," < 35s","dmitry2",["Unable to locate Host IP addr","Found 0 possible subdomain(s)"]],

                #42
                ["open",0,proc_low," < 15s","nmaptelnet",["Failed to resolve"]],

                #43
                ["open",0,proc_low," < 15s","nmapftp",["Failed to resolve"]],

                #44
                ["open",0,proc_low," < 20s","nmapstux",["Failed to resolve"]],

                #45
                ["SUCCEED",0,proc_low," < 30s","webdav",["is not DAV enabled or not accessible."]],

                #46
                ["No vulnerabilities found",1,proc_low," < 15s","golism10",["Cannot resolve domain name","No vulnerabilities found"]],

                #47
                ["[+]",0,proc_med," <  2m","uniscan2",["Use of uninitialized value in unpack at"]],

                #48
                ["[+]",0,proc_med," <  5m","uniscan3",["Use of uninitialized value in unpack at"]],

                #49
                ["[+]",0,proc_med," <  9m","uniscan4",["Use of uninitialized value in unpack at"]],

                #50
                ["[+]",0,proc_med," <  8m","uniscan5",["Use of uninitialized value in unpack at"]],

                #51
                ["[+]",0,proc_med," <  9m","uniscan6",["Use of uninitialized value in unpack at"]],

                #52
                ["0 item(s) reported",1,proc_low," < 35s","nikto1",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #53
                ["0 item(s) reported",1,proc_low," < 35s","nikto2",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #54
                ["0 item(s) reported",1,proc_low," < 35s","nikto3",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #55
                ["0 item(s) reported",1,proc_low," < 35s","nikto4",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #56
                ["0 item(s) reported",1,proc_low," < 35s","nikto5",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #57
                ["0 item(s) reported",1,proc_low," < 35s","nikto6",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #58
                ["0 item(s) reported",1,proc_low," < 35s","nikto7",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #59
                ["0 item(s) reported",1,proc_low," < 35s","nikto8",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #60
                ["0 item(s) reported",1,proc_low," < 35s","nikto9",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #61
                ["0 item(s) reported",1,proc_low," < 35s","nikto10",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #62
                ["0 item(s) reported",1,proc_low," < 35s","nikto11",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #63
                ["0 item(s) reported",1,proc_low," < 35s","nikto12",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #64
                ["0 item(s) reported",1,proc_low," < 35s","nikto13",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #65
                ["0 item(s) reported",1,proc_low," < 35s","nikto14","ERROR: Cannot resolve hostname , 0 item(s) reported"],

                #66
                ["#1",0,proc_high," < 30m","dnsmap_brute",["[+] 0 (sub)domains and 0 IP address(es) found"]],

                #67
                ["open",0,proc_low," < 15s","nmapmssql",["Failed to resolve"]],

                #68
                ["open",0,proc_low," < 15s","nmapmysql",["Failed to resolve"]],

                #69
                ["open",0,proc_low," < 15s","nmaporacle",["Failed to resolve"]],

                #70
                ["open",0,proc_low," < 15s","nmapudprdp",["Failed to resolve"]],

                #71
                ["open",0,proc_low," < 15s","nmaptcprdp",["Failed to resolve"]],

                #72
                ["open",0,proc_high," > 50m","nmapfulltcp",["Failed to resolve"]],

                #73
                ["open",0,proc_high," > 75m","nmapfulludp",["Failed to resolve"]],

                #74
                ["open",0,proc_low," < 30s","nmapsnmp",["Failed to resolve"]],

                #75
                ["Microsoft SQL Server Error Log",0,proc_low," < 30s","elmahxd",["unable to resolve host address","Connection timed out"]],

                #76
                ["open",0,proc_low," < 20s","nmaptcpsmb",["Failed to resolve"]],

                #77
                ["open",0,proc_low," < 20s","nmapudpsmb",["Failed to resolve"]],

                #78
                ["Host:",0,proc_med," < 5m","wapiti",["none"]],

                #79
                ["WebDAV is ENABLED",0,proc_low," < 40s","nmapwebdaviis",["Failed to resolve"]],

                #80
                ["X-XSS-Protection[1",1,proc_med," < 3m","whatweb",["Timed out","Socket error","X-XSS-Protection[1"]],

                #81
                ["No names were discovered",1,proc_med," < 15m","amass",["The system was unable to build the pool of resolvers"]]



            ]

# Vulnerabilities and Remediation
tools_fix = [
                    [1, "Not a vulnerability, just an informational alert. The host does not have IPv6 support. IPv6 provides more security as IPSec (responsible for CIA - Confidentiality, Integrity and Availablity) is incorporated into this model. So it is good to have IPv6 Support.",
                            "It is recommended to implement IPv6. More information on how to implement IPv6 can be found from this resource. https://www.cisco.com/c/en/us/solutions/collateral/enterprise/cisco-on-cisco/IPv6-Implementation_CS.html"],
                    [2, "Sensitive Information Leakage Detected. The ASP.Net application does not filter out illegal characters in the URL. The attacker injects a special character (%7C~.aspx) to make the application spit sensitive information about the server stack.",
                            "It is recommended to filter out special charaters in the URL and set a custom error page on such situations instead of showing default error messages. This resource helps you in setting up a custom error page on a Microsoft .Net Application. https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs"],
                    [3, "It is not bad to have a CMS in WordPress. There are chances that the version may contain vulnerabilities or any third party scripts associated with it may possess vulnerabilities",
                            "It is recommended to conceal the version of WordPress. This resource contains more information on how to secure your WordPress Blog. https://codex.wordpress.org/Hardening_WordPress"],
                    [4, "It is not bad to have a CMS in Drupal. There are chances that the version may contain vulnerabilities or any third party scripts associated with it may possess vulnerabilities",
                            "It is recommended to conceal the version of Drupal. This resource contains more information on how to secure your Drupal Blog. https://www.drupal.org/docs/7/site-building-best-practices/ensure-that-your-site-is-secure"],
                    [5, "It is not bad to have a CMS in Joomla. There are chances that the version may contain vulnerabilities or any third party scripts associated with it may possess vulnerabilities",
                            "It is recommended to conceal the version of Joomla. This resource contains more information on how to secure your Joomla Blog. https://www.incapsula.com/blog/10-tips-to-improve-your-joomla-website-security.html"],
                    [6, "Sometimes robots.txt or sitemap.xml may contain rules such that certain links that are not supposed to be accessed/indexed by crawlers and search engines. Search engines may skip those links but attackers will be able to access it directly.",
                            "It is a good practice not to include sensitive links in the robots or sitemap files."],
                    [7, "Without a Web Application Firewall, An attacker may try to inject various attack patterns either manually or using automated scanners. An automated scanner may send hordes of attack vectors and patterns to validate an attack, there are also chances for the application to get DoS`ed (Denial of Service)",
                            "Web Application Firewalls offer great protection against common web attacks like XSS, SQLi, etc. They also provide an additional line of defense to your security infrastructure. This resource contains information on web application firewalls that could suit your application. https://www.gartner.com/reviews/market/web-application-firewall"],
                    [8, "Open Ports give attackers a hint to exploit the services. Attackers try to retrieve banner information through the ports and understand what type of service the host is running",
                            "It is recommended to close the ports of unused services and use a firewall to filter the ports wherever necessary. This resource may give more insights. https://security.stackexchange.com/a/145781/6137"],
                    [9, "Chances are very less to compromise a target with email addresses. However, attackers use this as a supporting data to gather information around the target. An attacker may make use of the username on the email address and perform brute-force attacks on not just email servers, but also on other legitimate panels like SSH, CMS, etc with a password list as they have a legitimate name. This is however a shoot in the dark scenario, the attacker may or may not be successful depending on the level of interest",
                            "Since the chances of exploitation is feeble there is no need to take action. Perfect remediation would be choosing different usernames for different services will be more thoughtful."],
                    [10, "Zone Transfer reveals critical topological information about the target. The attacker will be able to query all records and will have more or less complete knowledge about your host.",
                            "Good practice is to restrict the Zone Transfer by telling the Master which are the IPs of the slaves that can be given access for the query. This SANS resource  provides more information. https://www.sans.org/reading-room/whitepapers/dns/securing-dns-zone-transfer-868"],
                    [11, "The email address of the administrator and other information (address, phone, etc) is available publicly. An attacker may use these information to leverage an attack. This may not be used to carry out a direct attack as this is not a vulnerability. However, an attacker makes use of these data to build information about the target.",
                            "Some administrators intentionally would have made this information public, in this case it can be ignored. If not, it is recommended to mask the information. This resource provides information on this fix. http://www.name.com/blog/how-tos/tutorial-2/2013/06/protect-your-personal-information-with-whois-privacy/"],
                    [12, "As the target is lacking this header, older browsers will be prone to Reflected XSS attacks.",
                            "Modern browsers does not face any issues with this vulnerability (missing headers). However, older browsers are strongly recommended to be upgraded."],
                    [13, "This attack works by opening multiple simultaneous connections to the web server and it keeps them alive as long as possible by continously sending partial HTTP requests, which never gets completed. They easily slip through IDS by sending partial requests.",
                            "If you are using Apache Module, `mod_antiloris` would help. For other setup you can find more detailed remediation on this resource. https://www.acunetix.com/blog/articles/slow-http-dos-attacks-mitigate-apache-http-server/"],
                    [14, "This vulnerability seriously leaks private information of your host. An attacker can keep the TLS connection alive and can retrieve a maximum of 64K of data per heartbeat.",
                            "PFS (Perfect Forward Secrecy) can be implemented to make decryption difficult. Complete remediation and resource information is available here. http://heartbleed.com/"],
                    [15, "By exploiting this vulnerability, an attacker will be able gain access to sensitive data in a n encrypted session such as session ids, cookies and with those data obtained, will be able to impersonate that particular user.",
                            "This is a flaw in the SSL 3.0 Protocol. A better remediation would be to disable using the SSL 3.0 protocol. For more information, check this resource. https://www.us-cert.gov/ncas/alerts/TA14-290A"],
                    [16, "This attacks takes place in the SSL Negotiation (Handshake) which makes the client unaware of the attack. By successfully altering the handshake, the attacker will be able to pry on all the information that is sent from the client to server and vice-versa",
                            "Upgrading OpenSSL to latest versions will mitigate this issue. This resource gives more information about the vulnerability and the associated remediation. http://ccsinjection.lepidum.co.jp/"],
                    [17, "With this vulnerability the attacker will be able to perform a MiTM attack and thus compromising the confidentiality factor.",
                            "Upgrading OpenSSL to latest version will mitigate this issue. Versions prior to 1.1.0 is prone to this vulnerability. More information can be found in this resource. https://bobcares.com/blog/how-to-fix-sweet32-birthday-attacks-vulnerability-cve-2016-2183/"],
                    [18, "With the LogJam attack, the attacker will be able to downgrade the TLS connection which allows the attacker to read and modify any data passed over the connection.",
                            "Make sure any TLS libraries you use are up-to-date, that servers you maintain use 2048-bit or larger primes, and that clients you maintain reject Diffie-Hellman primes smaller than 1024-bit. More information can be found in this resource. https://weakdh.org/"],
                    [19, "Allows remote attackers to cause a denial of service (crash), and possibly obtain sensitive information in applications that use OpenSSL, via a malformed ClientHello handshake message that triggers an out-of-bounds memory access.",
                            " OpenSSL versions 0.9.8h through 0.9.8q and 1.0.0 through 1.0.0c are vulnerable. It is recommended to upgrade the OpenSSL version. More resource and information can be found here. https://www.openssl.org/news/secadv/20110208.txt"],
                    [20, "Otherwise termed as BREACH atack, exploits the compression in the underlying HTTP protocol. An attacker will be able to obtain email addresses, session tokens, etc from the TLS encrypted web traffic.",
                            "Turning off TLS compression does not mitigate this vulnerability. First step to mitigation is to disable Zlib compression followed by other measures mentioned in this resource. http://breachattack.com/"],
                    [21, "Otherwise termed as Plain-Text Injection attack, which allows MiTM attackers to insert data into HTTPS sessions, and possibly other types of sessions protected by TLS or SSL, by sending an unauthenticated request that is processed retroactively by a server in a post-renegotiation context.",
                            "Detailed steps of remediation can be found from these resources. https://securingtomorrow.mcafee.com/technical-how-to/tips-securing-ssl-renegotiation/ https://www.digicert.com/news/2011-06-03-ssl-renego/ "],
                    [22, "This vulnerability allows attackers to steal existing TLS sessions from users.",
                            "Better advice is to disable session resumption. To harden session resumption, follow this resource that has some considerable information. https://wiki.crashtest-security.com/display/KB/Harden+TLS+Session+Resumption"],
                    [23, "This has nothing to do with security risks, however attackers may use this unavailability of load balancers as an advantage to leverage a denial of service attack on certain services or on the whole application itself.",
                            "Load-Balancers are highly encouraged for any web application. They improve performance times as well as data availability on during times of server outage. To know more information on load balancers and setup, check this resource. https://www.digitalocean.com/community/tutorials/what-is-load-balancing"],
                    [24, "An attacker can forwarded requests that comes to the legitimate URL or web application to a third party address or to the attacker's location that can serve malware and affect the end user's machine.",
                            "It is highly recommended to deploy DNSSec on the host target. Full deployment of DNSSEC will ensure the end user is connecting to the actual web site or other service corresponding to a particular domain name. For more information, check this resource. https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
                    [25, "Attackers may find considerable amount of information from these files. There are even chances attackers may get access to critical information from these files.",
                            "It is recommended to block or restrict access to these files unless necessary."],
                    [26, "Attackers may find considerable amount of information from these directories. There are even chances attackers may get access to critical information from these directories.",
                            "It is recommended to block or restrict access to these directories unless necessary."],
                    [27, "May not be SQLi vulnerable. An attacker will be able to know that the host is using a backend for operation.",
                            "Banner Grabbing should be restricted and access to the services from outside would should be made minimum."],
                    [28, "An attacker will be able to steal cookies, deface web application or redirect to any third party address that can serve malware.",
                            "Input validation and Output Sanitization can completely prevent Cross Site Scripting (XSS) attacks. XSS attacks can be mitigated in future by properly following a secure coding methodology. The following comprehensive resource provides detailed information on fixing this vulnerability. https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet"],
                    [29, "SSL related vulnerabilities breaks the confidentiality factor. An attacker may perform a MiTM attack, intrepret and eavesdrop the communication.",
                            "Proper implementation and upgraded version of SSL and TLS libraries are very critical when it comes to blocking SSL related vulnerabilities."],
                    [30, "Particular Scanner found multiple vulnerabilities that an attacker may try to exploit the target.",
                            "Refer to RS-Vulnerability-Report to view the complete information of the vulnerability, once the scan gets completed."],
                    [31, "Attackers may gather more information from subdomains relating to the parent domain. Attackers may even find other services from the subdomains and try to learn the architecture of the target. There are even chances for the attacker to find vulnerabilities as the attack surface gets larger with more subdomains discovered.",
                            "It is sometimes wise to block sub domains like development, staging to the outside world, as it gives more information to the attacker about the tech stack. Complex naming practices also help in reducing the attack surface as attackers find hard to perform subdomain bruteforcing through dictionaries and wordlists."],
                    [32, "Through this deprecated protocol, an attacker may be able to perform MiTM and other complicated attacks.",
                            "It is highly recommended to stop using this service and it is far outdated. SSH can be used to replace TELNET. For more information, check this resource https://www.ssh.com/ssh/telnet"],
                    [33, "This protocol does not support secure communication and there are likely high chances for the attacker to eavesdrop the communication. Also, many FTP programs have exploits available in the web such that an attacker can directly crash the application or either get a SHELL access to that target.",
                            "Proper suggested fix is use an SSH protocol instead of FTP. It supports secure communication and chances for MiTM attacks are quite rare."],
                    [34, "The StuxNet is level-3 worm that exposes critical information of the target organization. It was a cyber weapon that was designed to thwart the nuclear intelligence of Iran. Seriously wonder how it got here? Hope this isn't a false positive Nmap ;)",
                            "It is highly recommended to perform a complete rootkit scan on the host. For more information refer to this resource. https://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99&tabid=3"],
                    [35, "WebDAV is supposed to contain multiple vulnerabilities. In some case, an attacker may hide a malicious DLL file in the WebDAV share however, and upon convincing the user to open a perfectly harmless and legitimate file, execute code under the context of that user",
                            "It is recommended to disable WebDAV. Some critical resource regarding disbling WebDAV can be found on this URL. https://www.networkworld.com/article/2202909/network-security/-webdav-is-bad---says-security-researcher.html"],
                    [36, "Attackers always do a fingerprint of any server before they launch an attack. Fingerprinting gives them information about the server type, content- they are serving, last modification times etc, this gives an attacker to learn more information about the target",
                            "A good practice is to obfuscate the information to outside world. Doing so, the attackers will have tough time understanding the server's tech stack and therefore leverage an attack."],
                    [37, "Attackers mostly try to render web applications or service useless by flooding the target, such that blocking access to legitimate users. This may affect the business of a company or organization as well as the reputation",
                            "By ensuring proper load balancers in place, configuring rate limits and multiple connection restrictions, such attacks can be drastically mitigated."],
                    [38, "Intruders will be able to remotely include shell files and will be able to access the core file system or they will be able to read all the files as well. There are even higher chances for the attacker to remote execute code on the file system.",
                            "Secure code practices will mostly prevent LFI, RFI and RCE attacks. The following resource gives a detailed insight on secure coding practices. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [39, "Hackers will be able to steal data from the backend and also they can authenticate themselves to the website and can impersonate as any user since they have total control over the backend. They can even wipe out the entire database. Attackers can also steal cookie information of an authenticated user and they can even redirect the target to any malicious address or totally deface the application.",
                            "Proper input validation has to be done prior to directly querying the database information. A developer should remember not to trust an end-user's input. By following a secure coding methodology attacks like SQLi, XSS and BSQLi. The following resource guides on how to implement secure coding methodology on application development. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [40, "Attackers exploit the vulnerability in BASH to perform remote code execution on the target. An experienced attacker can easily take over the target system and access the internal sources of the machine",
                            "This vulnerability can be mitigated by patching the version of BASH. The following resource gives an indepth analysis of the vulnerability and how to mitigate it. https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-shellshock-bash-vulnerability"],
                    [41, "Gives attacker an idea on how the address scheming is done internally on the organizational network. Discovering the private addresses used within an organization can help attackers in carrying out network-layer attacks aiming to penetrate the organization's internal infrastructure.",
                            "Restrict the banner information to the outside world from the disclosing service. More information on mitigating this vulnerability can be found here. https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed"],
                    [42, "There are chances for an attacker to manipulate files on the webserver.",
                            "It is recommended to disable the HTTP PUT and DEL methods incase if you don't use any REST API Services. Following resources helps you how to disable these methods. http://www.techstacks.com/howto/disable-http-methods-in-tomcat.html https://docs.oracle.com/cd/E19857-01/820-5627/gghwc/index.html https://developer.ibm.com/answers/questions/321629/how-to-disable-http-methods-head-put-delete-option/"],
                    [43, "Attackers try to learn more about the target from the amount of information exposed in the headers. An attacker may know what type of tech stack a web application is emphasizing and many other information.",
                            "Banner Grabbing should be restricted and access to the services from outside would should be made minimum."],
                    [44, "An attacker who successfully exploited this vulnerability could read data, such as the view state, which was encrypted by the server. This vulnerability can also be used for data tampering, which, if successfully exploited, could be used to decrypt and tamper with the data encrypted by the server.",
                            "Microsoft has released a set of patches on their website to mitigate this issue. The information required to fix this vulnerability can be inferred from this resource. https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070"],
                    [45, "Any outdated web server may contain multiple vulnerabilities as their support would've been ended. An attacker may make use of such an opportunity to leverage attacks.",
                            "It is highly recommended to upgrade the web server to the available latest version."],
                    [46, "Hackers will be able to manipulate the URLs easily through a GET/POST request. They will be able to inject multiple attack vectors in the URL with ease and able to monitor the response as well",
                            "By ensuring proper sanitization techniques and employing secure coding practices it will be impossible for the attacker to penetrate through. The following resource gives a detailed insight on secure coding practices. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [47, "Since the attacker has knowledge about the particular type of backend the target is running, they will be able to launch a targetted exploit for the particular version. They may also try to authenticate with default credentials to get themselves through.",
                            "Timely security patches for the backend has to be installed. Default credentials has to be changed. If possible, the banner information can be changed to mislead the attacker. The following resource gives more information on how to secure your backend. http://kb.bodhost.com/secure-database-server/"],
                    [48, "Attackers may launch remote exploits to either crash the service or tools like ncrack to try brute-forcing the password on the target.",
                            "It is recommended to block the service to outside world and made the service accessible only through the a set of allowed IPs only really neccessary. The following resource provides insights on the risks and as well as the steps to block the service. https://www.perspectiverisk.com/remote-desktop-service-vulnerabilities/"],
                    [49, "Hackers will be able to read community strings through the service and enumerate quite a bit of information from the target. Also, there are multiple Remote Code Execution and Denial of Service vulnerabilities related to SNMP services.",
                            "Use a firewall to block the ports from the outside world. The following article gives wide insight on locking down SNMP service. https://www.techrepublic.com/article/lock-it-down-dont-allow-snmp-to-compromise-network-security/"],
                    [50, "Attackers will be able to find the logs and error information generated by the application. They will also be able to see the status codes that was generated on the application. By combining all these information, the attacker will be able to leverage an attack.",
                            "By restricting access to the logger application from the outside world will be more than enough to mitigate this weakness."],
                    [51, "Cyber Criminals mainly target this service as it is very easier for them to perform a remote attack by running exploits. WannaCry Ransomware is one such example.",
                            "Exposing SMB Service to the outside world is a bad idea, it is recommended to install latest patches for the service in order not to get compromised. The following resource provides a detailed information on SMB Hardening concepts. https://kb.iweb.com/hc/en-us/articles/115000274491-Securing-Windows-SMB-and-NetBios-NetBT-Services"]
            ]

# CWE reference for each vulnerability definition above, keyed by the same
# id used in `tools_fix` (tool_resp[i][arg3]). This is the "association with
# OWASP Top 10 & CWE 25" item the README lists as under development.
#
# These are best-effort, indicative mappings meant to point a reader toward
# the right family of weakness (e.g. for a report or a bug tracker tag) -
# several checks here are informational/reconnaissance findings rather than
# a single exploitable weakness, and are marked None rather than forced into
# an inaccurate CWE. Verify against your own research before citing one in a
# formal report.
CWE_REFERENCES = {
    1: None,                       # IPv6 presence - informational
    2: "CWE-209",                  # Info exposure through error message (ASP.Net stack trace)
    3: "CWE-200", 4: "CWE-200", 5: "CWE-200",  # CMS fingerprinting - info exposure
    6: "CWE-200",                  # robots.txt/sitemap.xml disclosure
    7: None,                       # No WAF - a missing control, not itself a weakness
    8: "CWE-200",                  # Open ports - info exposure / attack surface
    9: "CWE-200",                  # Harvested email addresses
    10: "CWE-200",                 # DNS zone transfer
    11: "CWE-200",                 # WHOIS contact info
    12: "CWE-693",                 # Missing XSS-Protection header - protection mechanism failure
    13: "CWE-400",                 # Slowloris - uncontrolled resource consumption
    14: "CWE-125",                 # Heartbleed - out-of-bounds read
    15: "CWE-327",                 # POODLE - broken/risky crypto algorithm (SSLv3)
    16: "CWE-295",                 # OpenSSL CCS Injection - improper certificate/state validation
    17: "CWE-327",                 # FREAK - broken/risky crypto algorithm (export ciphers)
    18: "CWE-327",                 # LOGJAM - weak Diffie-Hellman parameters
    19: "CWE-295",                 # OCSP stapling failure - certificate validation weakness
    20: "CWE-310",                 # TLS compression / BREACH - cryptographic issue
    21: "CWE-295",                 # Insecure renegotiation
    22: "CWE-295",                 # Session resumption weakness
    23: None,                      # No load balancer - availability best practice, not a CWE
    24: "CWE-350",                 # DNS spoofing/hijacking risk (missing DNSSEC)
    25: "CWE-538",                 # Sensitive file exposure (predictable files)
    26: "CWE-548",                 # Directory listing / exposure
    27: "CWE-200",                 # DB banner disclosure
    28: "CWE-79",                  # XSS found by XSSer
    29: "CWE-326",                 # General SSL weaknesses - inadequate encryption strength
    30: None,                      # Generic "scanner found issues" - see the tool's own report
    31: "CWE-200",                 # Subdomain enumeration
    32: "CWE-319",                 # Telnet - cleartext transmission
    33: "CWE-319",                 # FTP - cleartext transmission
    34: None,                      # STUXNET indicator - not a single weakness class
    35: "CWE-16",                  # WebDAV enabled - configuration
    36: "CWE-200",                 # Fingerprinting
    37: "CWE-400",                 # Stress-test / flooding susceptibility
    38: "CWE-98",                  # LFI/RFI/RCE (paired with CWE-22 path traversal)
    39: "CWE-89",                  # SQLi/XSS/BSQLi found (paired with CWE-79)
    40: "CWE-78",                  # Shellshock - OS command injection
    41: "CWE-200",                 # Internal IP disclosure
    42: "CWE-650",                 # HTTP PUT/DELETE enabled - trusting HTTP methods
    43: "CWE-200",                 # Header-based info disclosure
    44: "CWE-310",                 # MS10-070 ASP.NET padding oracle - cryptographic issue
    45: "CWE-1104",                # Outdated/unmaintained server software
    46: "CWE-20",                  # Injectable paths - improper input validation
    47: "CWE-200",                 # DB service fingerprinted
    48: "CWE-284",                 # RDP exposed - improper access control
    49: "CWE-200",                 # SNMP exposed - info disclosure (often paired with default community strings)
    50: "CWE-532",                 # Elmah logger exposed - sensitive info in log file
    51: "CWE-284",                 # SMB exposed - improper access control (e.g. EternalBlue/WannaCry)
}


# Tool Set
tools_precheck = [
                    ["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"], ["davtest"], ["theHarvester"], ["xsser"], ["dnsrecon"],["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"], ["golismero"], ["dnsenum"],["dmitry"], ["davtest"], ["nikto"], ["dnsmap"], ["amass"]
                 ]

def get_parser():

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true',
                        help='Show help message and exit.')
    parser.add_argument('-u', '--update', action='store_true',
                        help='Update SwiftScan.')
    parser.add_argument('-s', '--skip', action='append', default=[],
                        help='Skip some tools', choices=[t[0] for t in tools_precheck])
    parser.add_argument('-n', '--nospinner', action='store_true',
                        help='Disable the idle loader/spinner.')
    parser.add_argument('-j', '--json', action='store_true',
                        help='Also write a machine-readable JSON report (reports/rs.json.<target>.<timestamp>.json).')
    parser.add_argument('--tool-timeout', type=int, default=DEFAULT_TOOL_TIMEOUT, metavar='SECONDS',
                        help='Kill any single check that runs longer than this many seconds '
                             '(default: {}).'.format(DEFAULT_TOOL_TIMEOUT))
    parser.add_argument('--allow-internal', action='store_true',
                        help='Allow scanning loopback/private/link-local addresses (default: refused).')
    parser.add_argument('-w', '--web', action='store_true',
                        help='Launch the SwiftScan interactive web application interface.')
    parser.add_argument('target', nargs='?', metavar='URL', help='URL to scan.', default='', type=str)
    return parser


# Shuffling Scan Order (starts)
# #15 -- every check belongs to one functional module. Used by the planned
# per-module web UI; appended as the 5th field of each tool_names row.
CHECK_MODULES = {
    "host": "recon",
    "dnsrecon": "recon",
    "dnswalk": "recon",
    "whois": "recon",
    "golismero_dns_malware": "recon",
    "golismero_zone_transfer": "recon",
    "golismero_brute_subdomains": "recon",
    "dnsenum_zone_transfer": "recon",
    "fierce_brute_subdomains": "recon",
    "dmitry_email": "recon",
    "dmitry_subdomains": "recon",
    "dnsmap_brute": "recon",
    "amass": "recon",
    "theHarvester": "recon",
    "nikto_subrute": "recon",
    "nmap": "ports",
    "nmap_telnet": "ports",
    "nmap_ftp": "ports",
    "nmap_stuxnet": "ports",
    "nmap_sqlserver": "ports",
    "nmap_mysql": "ports",
    "nmap_oracle": "ports",
    "nmap_rdp_udp": "ports",
    "nmap_rdp_tcp": "ports",
    "nmap_full_ps_tcp": "ports",
    "nmap_full_ps_udp": "ports",
    "nmap_snmp": "ports",
    "nmap_tcp_smb": "ports",
    "nmap_udp_smb": "ports",
    "sslyze_hbleed": "tls",
    "sslyze_ocsp": "tls",
    "sslyze_zlib": "tls",
    "sslyze_reneg": "tls",
    "sslyze_resum": "tls",
    "nmap_hbleed": "tls",
    "nmap_poodle": "tls",
    "nmap_ccs": "tls",
    "nmap_freak": "tls",
    "nmap_logjam": "tls",
    "golismero_heartbleed": "tls",
    "golismero_ssl_scan": "tls",
    "nikto_ssl": "tls",
    "nmap_sloris": "dos",
    "uniscan_ministresser": "dos",
    "uniscan": "discovery",
    "dirb": "discovery",
    "golismero_brute_url_predictables": "discovery",
    "golismero_brute_directories": "discovery",
    "uniscan_filebrute": "discovery",
    "uniscan_dirbrute": "discovery",
    "nikto_cgi": "discovery",
    "nikto_sitefiles": "discovery",
    "wafw00f": "fingerprint",
    "lbd": "fingerprint",
    "whatweb": "fingerprint",
    "golismero_finger": "fingerprint",
    "wp_check": "fingerprint",
    "drp_check": "fingerprint",
    "joom_check": "fingerprint",
    "nikto_outdated": "fingerprint",
    "aspnet_config_err": "webvulns",
    "aspnet_elmah_axd": "webvulns",
    "nmap_header": "webvulns",
    "xsser": "webvulns",
    "golismero_sqlmap": "webvulns",
    "golismero_nikto": "webvulns",
    "webdav": "webvulns",
    "nmap_iis": "webvulns",
    "uniscan_rfi": "webvulns",
    "uniscan_xss": "webvulns",
    "nikto_xss": "webvulns",
    "nikto_shellshock": "webvulns",
    "nikto_internalip": "webvulns",
    "nikto_putdel": "webvulns",
    "nikto_headers": "webvulns",
    "nikto_ms01070": "webvulns",
    "nikto_servermsgs": "webvulns",
    "nikto_httpoptions": "webvulns",
    "nikto_paths": "webvulns",
    "wapiti": "webvulns",
}

tool_names = [row + [CHECK_MODULES[row[0]]] for row in tool_names]  # KeyError = unmapped check

MODULE_NAMES = ("recon", "ports", "tls", "webvulns", "discovery", "fingerprint", "dos")
ARG_MODULE = 4  # index of the module field in a tool_names row

# The four tables above (tool_names, tool_cmd, tool_resp, tool_status) are
# parallel arrays keyed by position - they must always be the same length or
# every index past the first mismatch silently pairs the wrong tool with the
# wrong command/response/status. Previously this was "checked" by averaging
# three of the four lengths and rounding, which can't actually catch a
# mismatch (e.g. lengths 79/81/82/81 average to ~81 and round cleanly,
# masking the bug). An explicit assert fails loudly, at import time, with
# the actual lengths - the only useful outcome for four tables meant to be
# edited by hand.
assert len(tool_names) == len(tool_cmd) == len(tool_resp) == len(tool_status), (
    "tool_names/tool_cmd/tool_resp/tool_status must all be the same length; "
    "got {}, {}, {}, {}".format(len(tool_names), len(tool_cmd), len(tool_resp), len(tool_status))
)
scan_shuffle = list(zip(tool_names, tool_cmd, tool_resp, tool_status, strict=True))
random.shuffle(scan_shuffle)  # noqa: S311 - scan ordering only, not security
tool_names, tool_cmd, tool_resp, tool_status = zip(*scan_shuffle, strict=True)
tool_checks = len(tool_names)
# Shuffling Scan Order (ends)

# For accessing list/dictionary elements
arg1 = 0
arg2 = 1
arg3 = 2
arg4 = 3
arg5 = 4
arg6 = 5

# Note: per-scan state (detected vulnerabilities, elapsed time, skipped-check
# counters) used to live here as module-level globals (rs_vul_list,
# rs_total_elapsed, rs_skipped_checks, plus a couple of never-referenced ones:
# tool, runTest, rs_vul_num, rs_avail_tools). That's both dead weight and a
# real bug: main() below reassigns rs_total_elapsed/rs_skipped_checks (e.g.
# `rs_skipped_checks = rs_skipped_checks + 1`) without a `global` statement,
# which makes Python treat those names as local to main() for its entire
# body - so the very first such line raises UnboundLocalError as soon as a
# scan produces a tool_skipped/tool_result/tool_interrupted/tool_timeout
# event, i.e. on every real (non---help/--update) invocation. Fixed by
# declaring this state as ordinary local variables inside main() instead of
# module globals; see the `elif args_namespace.target:` branch.


DEFAULT_TOOL_TIMEOUT = 2700  # 45 minutes - matches the slowest documented check (Slowloris)


def run_scan(target, skip=None, api_keys=None, tool_timeout=DEFAULT_TOOL_TIMEOUT,
             scan_dir=None, max_total_seconds=None):
    """Run a full scan and yield structured events (see _run_scan_impl).

    Each scan gets its own temp directory (#12) so concurrent scans cannot
    overwrite each other's output. If `scan_dir` is None one is created and
    removed when the generator finishes or is closed; if the caller passes
    one (the CLI does, so it can build its debug log afterwards) the caller
    owns the cleanup. `max_total_seconds` is an overall time budget: once it
    is spent the remaining checks are skipped and the scan still completes
    normally, so reports and OSINT results are never lost to a long run.
    """
    own_dir = scan_dir is None
    if own_dir:
        scan_dir = make_scan_tempdir()
    try:
        yield from _run_scan_impl(target, skip, api_keys, tool_timeout, scan_dir, max_total_seconds)
    finally:
        if own_dir:
            shutil.rmtree(scan_dir, ignore_errors=True)


def _run_scan_impl(target, skip, api_keys, tool_timeout, scan_dir, max_total_seconds):
    """
    Generator that runs a full scan against `target` and yields structured
    events instead of printing to the terminal. This is the reusable "engine"
    behind SwiftScan: both the CLI (the `__main__` block below) and any other
    consumer - e.g. a web UI driving a live progress view - should go through
    this function rather than duplicating the scan loop.

    IMPORTANT: `target` must already be validated - call
    `validate_target()`/`url_maker()` on any user-supplied input BEFORE
    passing it here. This function does not re-validate it, since by the
    time it's driving shell commands it's too late to safely reject a bad
    value; validation is the caller's responsibility precisely so that every
    caller (CLI, web app, tests) is forced to go through the same check.

    `skip` is an iterable of tool *binary* names (e.g. {"nikto", "amass"}),
    matching the `-s/--skip` CLI flag. `api_keys` is a dict like
    {"shodan": "...", "virustotal": "..."}; defaults to reading from the
    environment via api_sources.load_api_keys_from_env(). `tool_timeout` is
    the maximum number of seconds any single check may run before it's
    killed and treated as skipped - without this, a hung/misbehaving tool
    (or a target that intentionally stalls connections) blocks the entire
    scan indefinitely.

    Unlike the original script, tool availability is tracked in a *local*
    dict for this call rather than by mutating the shared tool_names table -
    the original approach permanently flipped a tool "unavailable" for the
    rest of the process, which is fine for a single CLI invocation but wrong
    for a long-running process (e.g. a web server) handling multiple scans.

    Yields dicts, each with an "event" key:
      {"event": "tool_precheck", "tool": str, "available": bool}
      {"event": "precheck_done", "unavailable_tools": [str, ...]}
      {"event": "tool_start", "name": str, "index": int, "total": int}
      {"event": "tool_skipped", "name": str, "index": int, "total": int}
      {"event": "tool_result", "name": str, "index": int, "elapsed": float,
       "vulnerable": bool, "severity": str|None, "title": str|None,
       "definition": str|None, "remediation": str|None, "cwe": str|None}
      {"event": "tool_interrupted", "name": str, "index": int, "elapsed": float}
      {"event": "tool_timeout", "name": str, "index": int, "elapsed": float,
       "timeout": float}
      {"event": "api_finding", "source": str, "ok": bool, "skipped": bool,
       "reason": str|None, "data": dict|None}
      {"event": "scan_complete", "total_elapsed": float, "checks_run": int,
       "checks_skipped": int, "vulnerabilities_found": int,
       "findings": [...], "api_findings": [...]}
      {"event": "fatal_error", "message": str}  # precheck itself couldn't run
    """
    skip = set(skip or [])
    api_keys = api_keys if api_keys is not None else api_sources.load_api_keys_from_env()

    # --- Tool availability precheck (local to this call; see docstring) ---
    # Previously this launched every tool with no arguments (subprocess.Popen
    # with shell=True AND a list argument - which only "worked" because the
    # list happened to have exactly one element) and grepped its output for
    # "not found". That meant ~25 real subprocesses spawned per scan just to
    # answer "is this installed", was fragile (a tool whose own --help text
    # happens to contain the words "not found" would be misreported as
    # missing), and mixed shell=True with a list of args, which is undefined/
    # confusing behavior. shutil.which() answers the same question by walking
    # $PATH directly - no subprocess, no shell, no output-scraping.
    unavailable_binaries = set()
    wsl_tools = get_wsl_available_tools() if os.name == 'nt' else set()
    for binary_name in dict.fromkeys(b for (b,) in tools_precheck):  # de-duplicated, order preserved
        available = shutil.which(binary_name) is not None and binary_name not in skip
        if not available and binary_name not in skip:
            if binary_name in ("wget", "host", "whois"):
                # Native Python fallback engine available for HTTP CMS/error checks, IPv6 DNS, and WHOIS
                available = True
            elif binary_name in wsl_tools:
                # Available through WSL Kali bridge
                available = True
        yield {"event": "tool_precheck", "tool": binary_name, "available": available}
        if not available:
            unavailable_binaries.add(binary_name)

    yield {"event": "precheck_done", "unavailable_tools": sorted(unavailable_binaries)}

    # --- Main scan loop ---
    findings = []
    checks_run = 0
    checks_skipped = 0
    total_elapsed = 0.0
    total = len(tool_names)
    deadline = (time.time() + max_total_seconds) if max_total_seconds else None
    budget_exhausted = False

    for i in range(total):
        key, name, binary = tool_names[i][arg1], tool_names[i][arg2], tool_names[i][arg3]

        if deadline is not None and time.time() >= deadline:
            budget_exhausted = True
            checks_skipped += 1
            yield {"event": "tool_skipped", "name": name, "index": i, "total": total}
            continue

        if binary in unavailable_binaries:
            checks_skipped += 1
            yield {"event": "tool_skipped", "name": name, "index": i, "total": total}
            continue

        yield {"event": "tool_start", "name": name, "index": i, "total": total}

        temp_file = get_temp_file(key, scan_dir)
        start = time.time()

        # Check if we should execute using built-in Python fallback engine
        ran_builtin = False
        if binary == "wget" and shutil.which("wget") is None:
            ran_builtin = True
            try:
                subpath = tool_cmd[i][arg2]
                url = "http://" + target + subpath
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SwiftScan"})
                with urllib.request.urlopen(req, timeout=tool_timeout) as resp:  # noqa: S310  # nosec B310
                    resp_content = resp.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                resp_content = e.read().decode("utf-8", errors="replace")
            except Exception as e:
                resp_content = "Connection error: " + str(e)
            try:
                with open(temp_file, "w", encoding="utf-8") as tf:
                    tf.write(resp_content)
            except OSError as e:
                logger.error("Could not write temp file %s: %s", temp_file, e)

        elif binary == "host" and shutil.which("host") is None:
            ran_builtin = True
            try:
                addrinfo = socket.getaddrinfo(target, None, socket.AF_INET6)
                if addrinfo:
                    resp_content = target + " has IPv6 address " + str(addrinfo[0][4][0]) + "\n"
                else:
                    resp_content = "Host " + target + " not found: 3(NXDOMAIN)\n"
            except Exception as e:
                resp_content = "Host " + target + " not found: " + str(e) + "\n"
            try:
                with open(temp_file, "w", encoding="utf-8") as tf:
                    tf.write(resp_content)
            except OSError as e:
                logger.error("Could not write temp file %s: %s", temp_file, e)

        elif binary == "whois" and shutil.which("whois") is None:
            ran_builtin = True
            try:
                domain = target.split('.')[-2] + '.' + target.split('.')[-1] if '.' in target else target
                with socket.create_connection(("whois.iana.org", 43), timeout=min(5, tool_timeout)) as s:
                    s.sendall((domain + "\r\n").encode())
                    chunks = []
                    while True:
                        c = s.recv(4096)
                        if not c:
                            break
                        chunks.append(c)
                resp_content = b"".join(chunks).decode("utf-8", errors="replace")
            except Exception as e:
                resp_content = "No match for domain: " + str(e)
            try:
                with open(temp_file, "w", encoding="utf-8") as tf:
                    tf.write(resp_content)
            except OSError as e:
                logger.error("Could not write temp file %s: %s", temp_file, e)

        if not ran_builtin:
            use_wsl = (os.name == 'nt' and shutil.which(binary) is None
                       and binary in get_wsl_available_tools())
            argv = build_argv(tool_cmd[i][arg1], target, tool_cmd[i][arg2], scan_dir=scan_dir, wsl=use_wsl)
            if not use_wsl:
                resolved = shutil.which(argv[0])  # honours PATHEXT (.exe/.bat) on Windows
                if resolved:
                    argv[0] = resolved

            try:
                run_tool(argv, temp_file, tool_timeout)
            except KeyboardInterrupt:
                elapsed = time.time() - start
                checks_skipped += 1
                yield {"event": "tool_interrupted", "name": name, "index": i, "elapsed": elapsed}
                continue
            except subprocess.TimeoutExpired:
                elapsed = time.time() - start
                checks_skipped += 1
                logger.warning("Tool '%s' exceeded the %ss timeout and was killed.", key, tool_timeout)
                yield {"event": "tool_timeout", "name": name, "index": i, "elapsed": elapsed,
                       "timeout": tool_timeout}
                continue
            # run_tool() never raises on a non-zero exit status, which is what
            # we want: many of these tools exit non-zero on "nothing found",
            # and the verdict comes from parsing the captured output.
            except OSError as e:
                logger.error("Scan command failed to run (%s): %s", key, e)

        elapsed = time.time() - start
        total_elapsed += elapsed
        checks_run += 1

        output_text = read_tool_output(key, scan_dir)
        if output_text is None:
            logger.error("No output captured for %s", key)
            output_text = ""

        if tool_status[i][arg2] == 0:
            vulnerable = tool_status[i][arg1].lower() in output_text.lower()
        else:
            vulnerable = not any(marker in output_text for marker in tool_status[i][arg6])

        result_event = {
            "event": "tool_result", "name": name, "index": i, "elapsed": elapsed,
            "vulnerable": vulnerable, "severity": None, "title": None,
            "definition": None, "remediation": None, "cwe": None,
            "module": tool_names[i][ARG_MODULE] if len(tool_names[i]) > ARG_MODULE else None,
        }
        if vulnerable:
            fix_index = tool_resp[i][arg3]
            result_event.update({
                "severity": tool_resp[i][arg2],
                "title": tool_resp[i][arg1],
                "definition": tools_fix[fix_index - 1][1],
                "remediation": tools_fix[fix_index - 1][2],
                "cwe": CWE_REFERENCES.get(fix_index),
            })
            findings.append(result_event)

        yield result_event

    # --- API-based OSINT lookups (see api_sources.py) ---
    resolved_ip = resolve_ip(target)
    api_findings = api_sources.gather_api_findings(target, resolved_ip=resolved_ip, api_keys=api_keys)
    for finding in api_findings:
        yield {"event": "api_finding", **finding}

    yield {
        "event": "scan_complete",
        "total_elapsed": total_elapsed,
        "checks_run": checks_run,
        "checks_skipped": checks_skipped,
        "vulnerabilities_found": len(findings),
        "findings": findings,
        "api_findings": api_findings,
        "budget_exhausted": budget_exhausted,
    }


def main(args=None):
    effective_args = sys.argv[1:] if args is None else args
    if not effective_args:
        logo()
        helper()
        sys.exit(1)

    args_namespace = get_parser().parse_args(effective_args)

    if args_namespace.nospinner:
        spinner.disabled = True

    if args_namespace.web:
        import web_app
        web_app.run_web()
        return

    if args_namespace.help or (not args_namespace.update \
        and not args_namespace.target):
        logo()
        helper()
    elif args_namespace.update:
        logo()
        print("SwiftScan is updating....Please wait.\n")
        spinner.start()
        # Checking internet connectivity first...
        rs_internet_availability = check_internet()
        if not rs_internet_availability:
            print("\t"+ bcolors.BG_ERR_TXT + "There seems to be some problem connecting to the internet. Please try again or later." +bcolors.ENDC)
            spinner.stop()
            sys.exit(1)
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        if not os.path.isdir(os.path.join(repo_dir, ".git")) or shutil.which("git") is None:
            # Not a git checkout: overwriting the running script with an
            # unverified download is how supply-chain attacks happen, so don't.
            spinner.stop()
            print("\t" + bcolors.WARNING + "Automatic update only works for git checkouts. "
                  "Re-clone https://github.com/praptidethe11/SwiftScan or run `git pull` yourself." + bcolors.ENDC)
            sys.exit(1)
        try:
            result = subprocess.run(["git", "-C", repo_dir, "pull", "--ff-only", "origin", "main"],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        except (subprocess.SubprocessError, OSError) as e:
            logger.error("Update failed: %s", e)
            spinner.stop()
            print("\t" + bcolors.BG_ERR_TXT + "Update failed: " + str(e) + bcolors.ENDC)
            sys.exit(1)
        spinner.stop()
        output = result.stdout.decode(errors="replace").strip()
        if result.returncode != 0:
            logger.error("git pull failed: %s", output)
            print("\t" + bcolors.BG_ERR_TXT + "Update failed (git pull): " + output + bcolors.ENDC)
            sys.exit(1)
        if "Already up to date" in output:
            print("\t" + bcolors.OKBLUE + "You already have the latest version of SwiftScan." + bcolors.ENDC)
        else:
            print("\t" + bcolors.OKGREEN + "SwiftScan successfully updated to the latest version." + bcolors.ENDC)
        sys.exit(0)

    elif args_namespace.target:

        try:
            target = url_maker(args_namespace.target, allow_internal=args_namespace.allow_internal)
        except ValueError as e:
            print("\t" + bcolors.BG_ERR_TXT + str(e) + bcolors.ENDC)
            sys.exit(1)
        cleanup_temp_files()  # sweep leftovers from older versions that used the shared temp dir
        scan_dir = make_scan_tempdir()
        atexit.register(shutil.rmtree, scan_dir, True)  # also runs on Ctrl+C / sys.exit
        if os.name == 'posix':
            _clear_screen()
            _set_cursor(False)
        else:
            _clear_screen()
        logo()

        # --- Drive the scan through run_scan() and print based on the events it
        # yields. All of the actual precheck/scan/API-lookup logic lives in
        # run_scan() now, so this block's only job is turning events into the
        # same terminal output the original inline version produced (this is
        # what lets a future web UI reuse run_scan() and just render the same
        # events differently, instead of duplicating the scan logic). ---
        print(bcolors.BG_HEAD_TXT+"[ Checking Available Security Scanning Tools Phase... Initiated. ]"+bcolors.ENDC)
        precheck_done = False
        current_precheck_tool = None
        # Per-scan state, local to this call (see the note where these used to
        # be module globals, just above DEFAULT_TOOL_TIMEOUT).
        rs_vul_list = []
        rs_total_elapsed = 0.0
        rs_skipped_checks = 0

        for event in run_scan(target, skip=set(args_namespace.skip),
                               tool_timeout=args_namespace.tool_timeout, scan_dir=scan_dir):
            kind = event["event"]

            if kind == "fatal_error":
                print("\t"+bcolors.BG_ERR_TXT+"SwiftScan was terminated abruptly..."+bcolors.ENDC)
                sys.exit(1)

            elif kind == "tool_precheck":
                current_precheck_tool = event["tool"]
                status_word = "available" if event["available"] else "unavailable"
                color = bcolors.OKGREEN if event["available"] else bcolors.BADFAIL
                print("\t"+bcolors.OKBLUE+event["tool"]+bcolors.ENDC+color+"..."+status_word+"."+bcolors.ENDC)
                clear()

            elif kind == "precheck_done":
                if not precheck_done:
                    precheck_done = True
                    unavail = event["unavailable_tools"]
                    if len(unavail) == 0:
                        print("\t"+bcolors.OKGREEN+"All Scanning Tools are available. Complete vulnerability checks will be performed by SwiftScan."+bcolors.ENDC)
                    else:
                        print("\t"+bcolors.WARNING+"Some of these tools "+bcolors.BADFAIL+str(unavail)+bcolors.ENDC+bcolors.WARNING+" are unavailable or will be skipped. SwiftScan will still perform the rest of the tests. Install these tools to fully utilize the functionality of SwiftScan."+bcolors.ENDC)
                    print(bcolors.BG_ENDL_TXT+"[ Checking Available Security Scanning Tools Phase... Completed. ]"+bcolors.ENDC)
                    print("\n")
                    print(bcolors.BG_HEAD_TXT+"[ Preliminary Scan Phase Initiated... Loaded "+str(tool_checks)+" vulnerability checks. ]"+bcolors.ENDC)

            elif kind == "tool_skipped":
                print("["+tool_status[event["index"]][arg3]+tool_status[event["index"]][arg4]+"] Deploying "+str(event["index"]+1)+"/"+str(event["total"])+" | "+bcolors.OKBLUE+event["name"]+bcolors.ENDC,)
                print(bcolors.WARNING+"\nScanning Tool Unavailable. Skipping Test...\n"+bcolors.ENDC)
                rs_skipped_checks = rs_skipped_checks + 1

            elif kind == "tool_start":
                print("["+tool_status[event["index"]][arg3]+tool_status[event["index"]][arg4]+"] Deploying "+str(event["index"]+1)+"/"+str(event["total"])+" | "+bcolors.OKBLUE+event["name"]+bcolors.ENDC,)
                try:
                    spinner.start()
                except Exception:
                    print("\n")

            elif kind == "tool_result":
                spinner.stop()
                rs_total_elapsed = rs_total_elapsed + event["elapsed"]
                sys.stdout.write(ERASE_LINE)
                print(bcolors.OKBLUE+"\nScan Completed in "+display_time(int(event["elapsed"]))+bcolors.ENDC, end='\r', flush=True)
                print("\n")
                if event["vulnerable"]:
                    print(bcolors.BOLD+"Vulnerability Threat Level"+bcolors.ENDC)
                    print("\t"+vul_info(event["severity"])+" "+bcolors.WARNING+str(event["title"])+bcolors.ENDC)
                    print(bcolors.BOLD+"Vulnerability Definition"+bcolors.ENDC)
                    print("\t"+bcolors.BADFAIL+str(event["definition"])+bcolors.ENDC)
                    print(bcolors.BOLD+"Vulnerability Remediation"+bcolors.ENDC)
                    print("\t"+bcolors.OKGREEN+str(event["remediation"])+bcolors.ENDC)
                    if event.get("cwe"):
                        print(bcolors.BOLD+"Reference"+bcolors.ENDC)
                        print("\t"+bcolors.OKBLUE+event["cwe"]+bcolors.ENDC)
                    rs_vul_list.append(tool_names[event["index"]][arg1]+"*"+tool_names[event["index"]][arg2])

            elif kind == "tool_interrupted":
                spinner.stop()
                rs_total_elapsed = rs_total_elapsed + event["elapsed"]
                sys.stdout.write(ERASE_LINE)
                print(bcolors.OKBLUE+"\nScan Interrupted in "+display_time(int(event["elapsed"]))+bcolors.ENDC, end='\r', flush=True)
                print("\n"+bcolors.WARNING + "\tTest Skipped. Performing Next. Press Ctrl+Z to Quit SwiftScan.\n" + bcolors.ENDC)
                rs_skipped_checks = rs_skipped_checks + 1

            elif kind == "tool_timeout":
                spinner.stop()
                rs_total_elapsed = rs_total_elapsed + event["elapsed"]
                sys.stdout.write(ERASE_LINE)
                print(bcolors.WARNING+"\nTimed Out after "+display_time(int(event["timeout"]))+bcolors.ENDC, end='\r', flush=True)
                print("\n"+bcolors.WARNING + "\tTest exceeded its time budget and was killed. Performing Next.\n" + bcolors.ENDC)
                rs_skipped_checks = rs_skipped_checks + 1

            elif kind == "api_finding":
                if current_precheck_tool != "__api_header_printed__":
                    # Print the phase header exactly once, right before the first
                    # api_finding event (run_scan() yields these after the scan
                    # loop finishes, so this is the correct point in the stream).
                    print(bcolors.BG_ENDL_TXT+"[ Preliminary Scan Phase Completed. ]"+bcolors.ENDC)
                    print("\n")
                    print(bcolors.BG_HEAD_TXT+"[ API-Based OSINT Phase Initiated. ]"+bcolors.ENDC)
                    resolved_ip = resolve_ip(target)
                    if resolved_ip:
                        print("\t"+bcolors.OKBLUE+"Resolved "+target+" to "+resolved_ip+bcolors.ENDC)
                    else:
                        print("\t"+bcolors.WARNING+"Could not resolve "+target+"; IP-based lookups (Shodan) will be skipped."+bcolors.ENDC)
                    current_precheck_tool = "__api_header_printed__"
                if event["skipped"]:
                    print("\t"+bcolors.OKBLUE+event["source"]+bcolors.ENDC+bcolors.WARNING+"...skipped ("+event["reason"]+")."+bcolors.ENDC)
                elif not event["ok"]:
                    print("\t"+bcolors.OKBLUE+event["source"]+bcolors.ENDC+bcolors.BADFAIL+"...failed ("+event["reason"]+")."+bcolors.ENDC)
                else:
                    print("\t"+bcolors.OKBLUE+event["source"]+bcolors.ENDC+bcolors.OKGREEN+"...done."+bcolors.ENDC)

            elif kind == "scan_complete":
                print(bcolors.BG_ENDL_TXT+"[ API-Based OSINT Phase Completed. ]"+bcolors.ENDC)
                print("\n")
                scan_result = event

        #################### Report & Documentation Phase ###########################
        # Timestamped to the second (not just the date) so re-scanning the same
        # target twice in one day produces two distinct report sets instead of
        # the second run's "a" (append) writes silently mixing into the first
        # run's report files.
        run_stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        reports_dir = get_reports_dir()
        os.makedirs(reports_dir, exist_ok=True)
        debuglog = os.path.join(reports_dir, "rs.dbg.%s.%s" % (target, run_stamp))
        vulreport = os.path.join(reports_dir, "rs.vul.%s.%s" % (target, run_stamp))
        apireport = os.path.join(reports_dir, "rs.api.%s.%s" % (target, run_stamp))
        jsonreport = os.path.join(reports_dir, "rs.json.%s.%s.json" % (target, run_stamp))
        print(bcolors.BG_HEAD_TXT+"[ Report Generation Phase Initiated. ]"+bcolors.ENDC)
        if len(rs_vul_list)==0:
            print("\t"+bcolors.OKGREEN+"No Vulnerabilities Detected."+bcolors.ENDC)
        else:
            with open(vulreport, "a") as report:
                for vuln_entry in rs_vul_list:
                    vuln_info = vuln_entry.split('*')
                    report.write(vuln_info[arg2])
                    report.write("\n------------------------\n\n")
                    data = read_tool_output(vuln_info[arg1], scan_dir)
                    if data is None:
                        logger.warning("Could not read scan output for vulnerability report (%s)", vuln_info[arg1])
                        report.write("[SwiftScan] Raw tool output unavailable.\n\n")
                    else:
                        report.write(data)
                        report.write("\n\n")

                print("\tComplete Vulnerability Report for "+bcolors.OKBLUE+target+bcolors.ENDC+" named "+bcolors.OKGREEN+vulreport+bcolors.ENDC+" is available under the same directory SwiftScan resides.")

        # API-based OSINT findings get their own report file rather than being
        # forced into the vulnerability-report format above: that format is
        # built around one severity + one remediation string per line, while
        # API results are structured data (lists of subdomains, lists of open
        # ports) that reads better as its own labeled section per source.
        with open(apireport, "w") as report:
            for finding in scan_result["api_findings"]:
                report.write("=== {} ===\n".format(finding["source"]))
                if finding["skipped"]:
                    report.write("SKIPPED: {}\n\n".format(finding["reason"]))
                elif not finding["ok"]:
                    report.write("FAILED: {}\n\n".format(finding["reason"]))
                else:
                    for key, value in finding["data"].items():
                        report.write("{}: {}\n".format(key, value))
                    report.write("\n")
        print("\tAPI-Based OSINT Report for "+bcolors.OKBLUE+target+bcolors.ENDC+" named "+bcolors.OKGREEN+apireport+bcolors.ENDC+" is available under the same directory SwiftScan resides.")

        # Optional machine-readable report: the same findings/api_findings the
        # terminal output is built from, as JSON - meant for feeding into a CI
        # pipeline, a dashboard, or any other tool rather than being read
        # directly. Only written with --json since most CLI runs don't need it.
        if args_namespace.json:
            json_payload = {
                "target": target,
                "scanned_at": run_stamp,
                "total_elapsed_seconds": rs_total_elapsed,
                "checks_run": len(tool_names) - rs_skipped_checks,
                "checks_skipped": rs_skipped_checks,
                "vulnerabilities_found": len(scan_result["findings"]),
                "findings": [
                    {
                        "tool": f["name"], "severity": f["severity"], "title": f["title"],
                        "definition": f["definition"], "remediation": f["remediation"],
                        "cwe": f.get("cwe"),
                    }
                    for f in scan_result["findings"]
                ],
                "api_findings": scan_result["api_findings"],
            }
            try:
                with open(jsonreport, "w") as report:
                    json.dump(json_payload, report, indent=2)
                print("\tJSON Report for "+bcolors.OKBLUE+target+bcolors.ENDC+" named "+bcolors.OKGREEN+jsonreport+bcolors.ENDC+" is available under the same directory SwiftScan resides.")
            except OSError as e:
                logger.error("Could not write JSON report %s: %s", jsonreport, e)
                print("\t"+bcolors.WARNING+"Could not write JSON report: "+str(e)+bcolors.ENDC)

        # Writing all scan files output into RS-Debug-ScanLog for debugging purposes.
        # Opened once outside the loop (was previously reopened in "append" mode
        # once per tool - 81 redundant open/close cycles for no behavioral
        # difference, since each write already appended in order).
        with open(debuglog, "w") as report:
            for file_name in tool_names:
                data = read_tool_output(file_name[arg1], scan_dir)
                if data is None:
                    # Tool was skipped/unavailable and never produced output;
                    # keep going so later tools still appear in the debug log.
                    logger.debug("No output file for %s", file_name[arg1])
                    continue
                report.write(file_name[arg2])
                report.write("\n------------------------\n\n")
                report.write(data)
                report.write("\n\n")

        print("\tTotal Number of Vulnerability Checks        : "+bcolors.BOLD+bcolors.OKGREEN+str(len(tool_names))+bcolors.ENDC)
        print("\tTotal Number of Vulnerability Checks Skipped: "+bcolors.BOLD+bcolors.WARNING+str(rs_skipped_checks)+bcolors.ENDC)
        print("\tTotal Number of Vulnerabilities Detected    : "+bcolors.BOLD+bcolors.BADFAIL+str(len(rs_vul_list))+bcolors.ENDC)
        print("\tTotal Time Elapsed for the Scan             : "+bcolors.BOLD+bcolors.OKBLUE+display_time(int(rs_total_elapsed))+bcolors.ENDC)
        print("\n")
        print("\tFor Debugging Purposes, You can view the complete output generated by all the tools named "+bcolors.OKBLUE+debuglog+bcolors.ENDC+" under the same directory.")
        print(bcolors.BG_ENDL_TXT+"[ Report Generation Phase Completed. ]"+bcolors.ENDC)

        shutil.rmtree(scan_dir, ignore_errors=True)
        if os.name == 'posix':
            _set_cursor(True)


# Entry point. Without this, `main` is defined but never called, so running
# `python3 swiftscan.py ...` - with any arguments, `--help` included - does
# nothing at all. (The docstring above and CHANGES.md both describe this
# guard as already present; it had been dropped from the actual file.)
if __name__ == "__main__":
    main()
