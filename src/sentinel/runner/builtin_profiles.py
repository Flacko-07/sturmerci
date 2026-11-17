# SPDX-License-Identifier: Apache-2.0
"""Built-in operation profiles for every adapter.

Each adapter's exact argv construction moves here. Adapters import the
profile name and pass params; they do not construct argv themselves.
This is the boundary that makes M6-P0-A (runner enforces argv) real.

Registration happens at import. Import this module once, early
(sandbox_runner imports it at top level).
"""

from __future__ import annotations

from typing import Any

from sentinel.runner.profiles import (
    OperationProfile,
    register_profile,
)


# --- Nmap ---

NMAP_PROHIBITED_FLAGS = (
    "--script",
    "-sC",
    "-sV",
    "-A",
    "-O",
    "-sU",
    "-sS",
    "-sA",
    "-sW",
    "-sM",
    "--traceroute",
    "--osscan-limit",
    "--osscan-guess",
    "-sI",
    "-b",
    "--interactive",
)


def _build_nmap_tcp_connect(executable: str, params: dict[str, Any]) -> list[str]:
    target = params["target"]
    ports = params["ports"]
    max_rate = params["max_rate"]
    if not isinstance(ports, list) or not ports:
        raise ValueError("ports must be a non-empty list")
    if not (1 <= max_rate <= 1000):
        raise ValueError(f"max_rate out of range: {max_rate}")
    return [
        executable,
        "-sT",
        "-Pn",
        "-n",
        "--max-rate",
        str(max_rate),
        "-p",
        ",".join(str(p) for p in sorted(ports)),
        "-oX",
        "-",
        target,
    ]


register_profile(
    OperationProfile(
        name="nmap/tcp_connect_scan",
        builder=_build_nmap_tcp_connect,
        required_params=frozenset({"target", "ports", "max_rate"}),
        prohibited_flags=NMAP_PROHIBITED_FLAGS,
    )
)


# --- httpx ---

HTTPX_PROHIBITED_FLAGS = (
    "-path",
    "-paths",
    "-p",
    "-follow-redirects",
    "-fr",
    "-H",
    "-header",
    "-body",
    "-X",
    "-method",  # -x IS the method flag, but see builder note below
    "-x",
    "-http-proxy",
    "-proxy",
    "-websocket",
    "-ws",
    "-auth",
    "-dc",
    "-dashboard",
    "-sr",
    "-store-response",
    "-screenshot",
    "-ss",
)


def _build_httpx_inventory(executable: str, params: dict[str, Any]) -> list[str]:
    hostname = params["hostname"]
    port = params["port"]
    scheme = params["scheme"]
    method = params["method"]
    if method not in ("GET", "HEAD"):
        raise ValueError(f"method {method!r} not in (GET, HEAD)")
    url = f"{scheme}://{hostname}:{port}/"
    # -x <METHOD> sends the actual HTTP method. Without it, httpx uses
    # GET regardless of what the approval authorizes -- that was M7-P0-E.
    # Verify the pinned 1.6.10 binary accepts `-x` (run: `httpx -h | grep -x`).
    return [
        executable,
        "-u",
        url,
        "-x",
        method,
        "-silent",
        "-json",
        "-nc",
        "-duc",
    ]


register_profile(
    OperationProfile(
        name="httpx/inventory",
        builder=_build_httpx_inventory,
        required_params=frozenset({"hostname", "port", "scheme", "method"}),
        # Note: "-x" is in prohibited_flags because the current httpx adapter
        # does not pass a method flag to the binary. Fix tracked in M7-P0-E;
        # once that is implemented, remove "-x" from prohibited list.
        prohibited_flags=tuple(f for f in HTTPX_PROHIBITED_FLAGS if f != "-x"),
    )
)


# --- Subfinder ---

SUBFINDER_PROHIBITED_FLAGS = (
    "-all",
    "-recursive",
    "-active",
    "-silent-json",  # we want -silent -json as separate tokens
)


def _build_subfinder_passive(executable: str, params: dict[str, Any]) -> list[str]:
    domain = params["domain"]
    sources = params.get("sources") or []
    if not isinstance(sources, list) or not sources:
        raise ValueError("sources must be a non-empty list")
    if set(sources) - {"crtsh"}:
        raise ValueError(
            f"sources {sources!r} includes a provider not authorized "
            "(only crtsh is allowed in this profile)"
        )
    return [
        executable,
        "-d",
        domain,
        "-sources",
        ",".join(sources),
        "-silent",
        "-json",
        "-nc",
    ]


register_profile(
    OperationProfile(
        name="subfinder/passive_crtsh",
        builder=_build_subfinder_passive,
        required_params=frozenset({"domain", "sources"}),
        prohibited_flags=SUBFINDER_PROHIBITED_FLAGS,
    )
)

# --- WHOIS ---

WHOIS_PROHIBITED_FLAGS: tuple[str, ...] = ()


def _build_whois_target_lookup(executable: str, params: dict) -> list[str]:
    domain = params.get("target_domain", "")
    server = params.get("server", "")
    if not domain or not server:
        raise ValueError("whois profile requires target_domain + server")
    if "/" in domain or "/" in server:
        raise ValueError("slash not allowed in whois args")
    return [executable, "--server", server, domain]


register_profile(
    OperationProfile(
        name="whois/target_lookup",
        builder=_build_whois_target_lookup,
        required_params=frozenset({"target_domain", "server"}),
        prohibited_flags=WHOIS_PROHIBITED_FLAGS,
    )
)

# --- dig ---

DIG_PROHIBITED_FLAGS = ("+trace", "-f", "+qr", "+tcp")


def _build_dig_dns_lookup(executable: str, params: dict) -> list[str]:
    domain = params.get("domain", "")
    resolver = params.get("resolver", "")
    record_type = params.get("record_type", "A")
    if not domain or not resolver:
        raise ValueError("dig profile requires domain + resolver")
    # Reject anything that could smuggle in a second resolver or flags
    if "@" in domain or " " in domain or "\t" in domain:
        raise ValueError(f"domain contains forbidden chars: {domain!r}")
    if "@" in resolver or " " in resolver:
        raise ValueError(f"resolver contains forbidden chars: {resolver!r}")
    return [
        executable,
        "+noall",
        "+answer",
        f"@{resolver}",
        domain,
        record_type,
    ]


register_profile(
    OperationProfile(
        name="dig/dns_lookup",
        builder=_build_dig_dns_lookup,
        required_params=frozenset({"domain", "resolver", "record_type"}),
        prohibited_flags=DIG_PROHIBITED_FLAGS,
    )
)

# --- ffuf ---

FFUF_PROHIBITED_FLAGS = (
    "-x",  # proxy
    "-H",  # arbitrary headers (auth injection risk)
    "-b",  # cookies
    "POST",
    "PUT",
    "PATCH",
    "DELETE",  # method value must be GET
    "-d",  # body
    "-input-cmd",  # shell exec
    "-request",  # raw request file
    "-request-proto",  # raw request protocol override
)


def _build_ffuf_dir_discovery(executable: str, params: dict) -> list[str]:
    hostname = params.get("hostname", "")
    port = params.get("port")
    scheme = params.get("scheme", "https")
    wordlist = params.get("wordlist_path", "")
    rate = params.get("rate", 10)
    if not hostname or not wordlist:
        raise ValueError("ffuf profile requires hostname + wordlist_path")
    if scheme not in ("http", "https"):
        raise ValueError(f"scheme must be http or https: {scheme!r}")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"port out of range: {port!r}")
    if not isinstance(rate, int) or not (1 <= rate <= 100):
        raise ValueError(f"rate out of range: {rate!r}")

    target_url = f"{scheme}://{hostname}:{port}/FUZZ"
    return [
        executable,
        "-u",
        target_url,
        "-w",
        wordlist,
        "-of",
        "json",
        "-o",
        "/dev/stdout",
        "-mc",
        "200,201,202,204,301,302,307,308,401,403,405",
        "-rate",
        str(rate),
        "-t",
        "1",
        "-timeout",
        "10",
        "-s",
        "-X",
        "GET",
    ]


register_profile(
    OperationProfile(
        name="ffuf/dir_discovery",
        builder=_build_ffuf_dir_discovery,
        required_params=frozenset(
            {"hostname", "port", "scheme", "wordlist_path", "rate"}
        ),
        prohibited_flags=FFUF_PROHIBITED_FLAGS,
    )
)

# --- nikto ---

# Single-token prohibitions only. Pair-based rules like "-Tuning 4" cannot
# be expressed by the current token-match layer; the builder is the
# authority for tuning value (set(tunings) <= set("123")).
NIKTO_PROHIBITED_FLAGS = (
    "-evasion",
    "-useproxy",
    "-update",
    "-list-plugins",
    "-dbcheck",
    "-D",  # directory brute (overlaps with ffuf)
    "-vhost",  # vhost brute
    "-output",  # we use -o /dev/stdout
)


def _build_nikto_web_scan(executable: str, params: dict) -> list[str]:
    hostname = params.get("hostname", "")
    port = params.get("port")
    scheme = params.get("scheme", "https")
    tunings = params.get("tunings", "123")
    pause = params.get("pause_seconds", 1.0)
    maxtime = params.get("max_time_seconds", 600)

    if not hostname:
        raise ValueError("nikto profile requires hostname")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"port out of range: {port!r}")
    if scheme not in ("http", "https"):
        raise ValueError(f"scheme must be http or https: {scheme!r}")
    if not isinstance(tunings, str) or not set(tunings) <= set("123"):
        raise ValueError(
            f"tunings {tunings!r} contains a category outside (1,2,3). "
            "Categories 4-9 (XSS/upload/DoS/RFI/RCE/SQLi) are not permitted."
        )
    if not isinstance(pause, (int, float)) or pause < 0.05:
        raise ValueError(f"pause out of range: {pause!r}")
    if not isinstance(maxtime, int) or not (1 <= maxtime <= 900):
        raise ValueError(f"maxtime out of range: {maxtime!r}")

    argv = [executable, "-h", hostname, "-p", str(port)]
    if scheme == "https":
        argv.append("-ssl")
    argv.extend(
        [
            "-Format",
            "json",
            "-o",
            "/dev/stdout",
            "-Tuning",
            tunings,
            "-Pause",
            str(pause),
            "-timeout",
            "10",
            "-maxtime",
            f"{maxtime}s",
            "-ask",
            "no",
            "-nointeractive",
            "-useragent",
            "Sentinel/0.1",
        ]
    )
    return argv


register_profile(
    OperationProfile(
        name="nikto/web_server_scan",
        builder=_build_nikto_web_scan,
        required_params=frozenset(
            {
                "hostname",
                "port",
                "scheme",
                "tunings",
                "pause_seconds",
                "max_time_seconds",
            }
        ),
        prohibited_flags=NIKTO_PROHIBITED_FLAGS,
    )
)

# --- scion ---

SCION_PROHIBITED_FLAGS = (
    "--verify",
    "--output",
    "--out-file",
    "--compare",
    "--scope-file",
)


def _build_scion_passive(executable: str, params: dict) -> list[str]:
    domain = params.get("domain", "")
    if not domain:
        raise ValueError("scion profile requires domain")
    return [executable, "--subs-only", "--silent", "--no-color", domain]


register_profile(
    OperationProfile(
        name="scion/passive_discovery",
        builder=_build_scion_passive,
        required_params=frozenset({"domain"}),
        prohibited_flags=SCION_PROHIBITED_FLAGS,
    )
)

# --- sqlmap (Class 3, detection-only) ---

SQLMAP_PROHIBITED_FLAGS = (
    # Post-exploitation
    "--os-shell",
    "--os-pwn",
    "--os-cmd",
    "--os-smbrelay",
    "--sql-shell",
    "--sql-query",
    "--sql-file",
    "--file-read",
    "--file-write",
    "--file-dest",
    "--eval",
    "--shell",
    "--api",
    # Data extraction (proof-only mode)
    "--dump",
    "--dump-all",
    "--dump-format",
    "--passwords",
    "--common-tables",
    "--common-columns",
    "--common-files",
    "--dbs",
    "--tables",
    "--columns",
    "--schema",
    "--count",
    "--reg-read",
    "--reg-add",
    "--reg-del",
    "--priv-esc",
    "--roles",
    # Method/header override (data via --data instead)
    "--method",
    "--cookie",
    "--cookie-del",
    "--headers",
    "--user-agent",
    "--referer",
    "--random-agent",
    "--auth-type",
    "--auth-cred",
    "--auth-file",
    # Evasion
    "--tamper",
    "--proxy",
    "--tor",
    "--check-tor",
    # Interactive / scanning breadth
    "--wizard",
    "--update",
    "--forms",
    "--crawl",
    "--crawl-exclude",
    # Temp dir override
    "--temp-dir",
    # Lock down risk knobs (builder enforces level=1 risk=1 technique=B)
    "--level=2",
    "--level=3",
    "--level=4",
    "--level=5",
    "--risk=2",
    "--risk=3",
    "--technique=U",
    "--technique=E",
    "--technique=S",
    "--technique=T",
    "--technique=Q",
)


def _build_sqlmap_detect(executable: str, params: dict) -> list[str]:
    host = params.get("hostname", "")
    port = params.get("port")
    scheme = params.get("scheme", "http")
    path = params.get("path", "/")
    query = params.get("query", "")
    data = params.get("data")
    out_dir = params.get("output_dir", "")
    delay = params.get("delay_seconds", 1)
    technique = params.get("technique", "B")

    if not host:
        raise ValueError("sqlmap profile requires hostname")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"port out of range: {port!r}")
    if scheme not in ("http", "https"):
        raise ValueError(f"scheme must be http or https: {scheme!r}")
    if not out_dir.startswith("/tmp/sentinel-sqlmap-"):
        raise ValueError(
            f"output_dir must be under /tmp/sentinel-sqlmap-*: {out_dir!r}"
        )
    if technique != "B":
        raise ValueError(
            f"technique must be 'B' (boolean-blind only); got {technique!r}"
        )
    if not (0.5 <= float(delay) <= 5.0):
        raise ValueError(f"delay_seconds out of range: {delay!r}")
    if data is not None and (not isinstance(data, str) or not data):
        raise ValueError(f"data must be a non-empty string or None: {data!r}")

    url = f"{scheme}://{host}:{port}{path}"
    if query:
        url = f"{url}?{query}"

    argv = [
        executable,
        "-u",
        url,
        "--batch",
        "--flush-session",
        f"--output-dir={out_dir}",
        "--level=1",
        "--risk=1",
        f"--technique={technique}",
        "--threads=1",
        f"--delay={int(float(delay))}"
        if float(delay).is_integer()
        else f"--delay={delay}",
        "--timeout=10",
        "--retries=0",
        "-v",
        "1",
    ]
    if data:
        argv.append(f"--data={data}")
    return argv


register_profile(
    OperationProfile(
        name="sqlmap/detect",
        builder=_build_sqlmap_detect,
        required_params=frozenset(
            {
                "hostname",
                "port",
                "scheme",
                "path",
                "query",
                "output_dir",
                "delay_seconds",
                "technique",
            }
        ),
        prohibited_flags=SQLMAP_PROHIBITED_FLAGS,
        execution_class=3,  # (P0.3) explicit — detection-only but still intrusive
        requires_param_binding=True,
        param_binding_keys=frozenset(
            {
                "hostname",
                "port",
                "scheme",
                "path",
                "query",
                "delay_seconds",
                "technique",
            }
        ),
    )
)

# --- nuclei ---

NUCLEI_TEMPLATES_VERSION = "10.4.0"
NUCLEI_TEMPLATES_DIR = f"/opt/sentinel-templates/nuclei-v{NUCLEI_TEMPLATES_VERSION}"
NUCLEI_TEMPLATES_HASH = (
    "9918870bc62dbfc4870fb36301af79067d90294e0f126c87f029540395ed0503"
)

NUCLEI_ALLOW_TAGS = "exposure,misconfig,tech,panel,takeover,ssl,dns"
NUCLEI_EXCLUDE_TAGS = (
    "dos,fuzz,intrusive,brute-force,headless,file,code,"
    "default-login,cred-stuffing,file-upload,lfi,rce,ssti,xxe,sqli,poc,exploit"
)

NUCLEI_PROHIBITED_FLAGS = (
    "-headless",
    "-code",
    "-fuzz",
    "-dast",
    "-interactsh-url",
    "-interactsh-token",
    "-sf",
    "-store-response",
    "-sr",
    "-store-resp",
    "-update",
    "-update-templates",
    "-markdown-export",
    "-json-export",
    "-html-export",
    "-sarif-export",
)


def _build_nuclei_scan(executable: str, params: dict) -> list[str]:
    host = params.get("hostname", "")
    port = params.get("port")
    scheme = params.get("scheme", "https")
    rate = params.get("rate_limit", 10)
    timeout = params.get("timeout_seconds", 600)

    if not host:
        raise ValueError("nuclei profile requires hostname")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"port out of range: {port!r}")
    if scheme not in ("http", "https"):
        raise ValueError(f"scheme must be http or https: {scheme!r}")
    if not isinstance(rate, int) or not (1 <= rate <= 150):
        raise ValueError(f"rate_limit out of range: {rate!r}")
    if not isinstance(timeout, int) or not (10 <= timeout <= 900):
        raise ValueError(f"timeout_seconds out of range: {timeout!r}")

    target = f"{scheme}://{host}:{port}"
    return [
        executable,
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-no-color",
        "-t",
        NUCLEI_TEMPLATES_DIR,
        "-tags",
        NUCLEI_ALLOW_TAGS,
        "-exclude-tags",
        NUCLEI_EXCLUDE_TAGS,
        "-rate-limit",
        str(rate),
        "-timeout",
        "10",
        "-retries",
        "1",
        "-disable-update-check",
        # NOTE: do NOT pass -headless / -code here. Nuclei's defaults are
        # already false, and those tokens are in NUCLEI_PROHIBITED_FLAGS —
        # emitting them (even as =false) trips the runner's own check,
        # which matches "<flag>" and "<flag>=<value>" alike.
    ]


register_profile(
    OperationProfile(
        name="nuclei/scan",
        builder=_build_nuclei_scan,
        required_params=frozenset(
            {
                "hostname",
                "port",
                "scheme",
                "rate_limit",
                "timeout_seconds",
            }
        ),
        prohibited_flags=NUCLEI_PROHIBITED_FLAGS,
    )
)

# --- metasploit ---
#
# Two profiles, one binary:
#   metasploit/check    -> Class 2, auxiliary/check only, DB-free
#   metasploit/exploit  -> Class 3, gated on intrusive_authorized + lab_environment
#
# Both use `-n` (no database) — the sandbox cannot reach a postgres socket
# (loopback is isolated) and msf works DB-free for single-shot runs.
# Both pre-create a per-run ~/.msf4/ skeleton (initial_setup_complete
# marker + empty database.yml) in the adapter; the profile only builds
# argv.

METASPLOIT_PROHIBITED_FLAGS = (
    # Session/daemon flags we don't want in argv
    "-x",
    "-e",  # -x/-e run commands, but we drive via -r <rc>
    "--rc",  # duplicate of -r (we use -r)
    "--batch",  # we drive via rc; -q is the quiet flag
    "-k",  # shutdown other consoles
    # Post-exploitation modules cannot be distinguished by flag, only by
    # module name. The adapter filters the module against an allowlist
    # (auxiliary/scanner/*, auxiliary/gather/*). A prohibited module name
    # is caught at adapter level, not profile level.
)


def _build_metasploit_check(executable: str, params: dict) -> list[str]:
    module = params.get("module", "")
    host = params.get("hostname", "")
    port = params.get("port")
    scheme = params.get("scheme", "http")
    rc_path = params.get("rc_path", "")
    if not module:
        raise ValueError("metasploit profile requires module")
    if not host:
        raise ValueError("metasploit profile requires hostname")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"port out of range: {port!r}")
    if scheme not in ("http", "https"):
        raise ValueError(f"scheme must be http or https: {scheme!r}")
    if not rc_path.startswith("/tmp/sentinel-msf-"):
        raise ValueError(f"rc_path must be under /tmp/sentinel-msf-*: {rc_path!r}")
    return [executable, "-n", "-q", "-r", rc_path]


def _build_metasploit_exploit(executable: str, params: dict) -> list[str]:
    # Same argv as check — the distinction is enforcement, not argv.
    return _build_metasploit_check(executable, params)


register_profile(
    OperationProfile(
        name="metasploit/check",
        builder=_build_metasploit_check,
        required_params=frozenset(
            {
                "module",
                "hostname",
                "port",
                "scheme",
                "rc_path",
            }
        ),
        prohibited_flags=METASPLOIT_PROHIBITED_FLAGS,
        execution_class=2,
    )
)

register_profile(
    OperationProfile(
        name="metasploit/exploit",
        builder=_build_metasploit_exploit,
        required_params=frozenset(
            {
                "module",
                "hostname",
                "port",
                "scheme",
                "rc_path",
            }
        ),
        prohibited_flags=METASPLOIT_PROHIBITED_FLAGS,
        execution_class=3,
        requires_param_binding=True,
        param_binding_keys=frozenset({"module", "hostname", "port", "scheme"}),
    )
)

# --- ZAP ---
#
# OWASP ZAP baseline: spider + passive scan. Runs `zap-baseline.py`
# which spawns a ZAP daemon on localhost, spiders, waits for passive
# results, writes XML + HTML reports, then kills the daemon.
# Class 2 (spider is GETs; passive scan analyses responses).
# Active scan (-a) prohibited.

ZAP_PROHIBITED_FLAGS = (
    "-a",  # active scan (attack — Class 3)
    "-j",  # ajax spider (headless browser, slow, risky)
    "-s",  # short output (breaks XML parse assumptions)
    "-z",  # arbitrary ZAP options (huge surface)
    "-d",  # debug logging (may leak env)
    "-update",  # network update
    "-quickurl",  # quick scan mode (includes active)
    "-quickout",  # quick scan output
    "-quickprogress",  # quick scan progress
)


def _build_zap_baseline(executable: str, params: dict) -> list[str]:
    target_url = params.get("target_url", "")
    report_xml = params.get("report_xml_path", "")
    report_html = params.get("report_html_path", "")
    scan_minutes = params.get("scan_timeout_minutes", 5)
    spider_minutes = params.get("spider_minutes", 1)

    if not target_url:
        raise ValueError("zap profile requires target_url")
    if not target_url.startswith(("http://", "https://")):
        raise ValueError(f"target_url must start with http(s)://: {target_url!r}")
    if not report_xml or not report_xml.startswith("/tmp/sentinel-zap-"):
        raise ValueError(f"report_xml_path must be /tmp/sentinel-zap-*: {report_xml!r}")
    if not report_html or not report_html.startswith("/tmp/sentinel-zap-"):
        raise ValueError(
            f"report_html_path must be /tmp/sentinel-zap-*: {report_html!r}"
        )
    if not isinstance(scan_minutes, int) or not (1 <= scan_minutes <= 15):
        raise ValueError(f"scan_timeout_minutes out of range: {scan_minutes!r}")
    if not isinstance(spider_minutes, int) or not (1 <= spider_minutes <= 5):
        raise ValueError(f"spider_minutes out of range: {spider_minutes!r}")

    return [
        executable,
        "-t",
        target_url,
        "-x",
        report_xml,
        "-r",
        report_html,
        "-m",
        str(spider_minutes),
        "-I",
    ]


register_profile(
    OperationProfile(
        name="zap/baseline_scan",
        builder=_build_zap_baseline,
        required_params=frozenset(
            {
                "target_url",
                "report_xml_path",
                "report_html_path",
                "scan_timeout_minutes",
                "spider_minutes",
            }
        ),
        prohibited_flags=ZAP_PROHIBITED_FLAGS,
        execution_class=2,
    )
)

# --- theHarvester ---
#
# Passive OSINT discovery. Queries external providers (crt.sh, otx,
# rapiddns) about a domain. Requires_target_connection=False — it does
# not talk to the target, only to providers. Each provider must be
# authorized on the approval's approved_infrastructure_endpoints.
#
# Writes JSON to <out_base>.json. Adapter reads it after subprocess.

THEHARVESTER_PROHIBITED_FLAGS = (
    "-a",  # use ALL sources (pulls in API-key sources, active probes)
    "-s",  # Shodan (needs key)
    "-p",  # port scan (active)
    "-e",  # DNS brute force (active)
    "-t",  # DNS TLD brute (active)
    "-n",  # DNS lookup resolution (active)
    "-c",  # DNS resolution (active)
    "-u",  # DNS bruteforce extension (active)
    "-r",  # recursive (active)
)


def _build_theharvester_passive(executable: str, params: dict) -> list[str]:
    domain = params.get("domain", "")
    sources = params.get("sources", [])
    limit = params.get("limit", 500)
    out_base = params.get("out_base", "")

    if not domain:
        raise ValueError("theHarvester profile requires domain")
    if not isinstance(sources, list) or not sources:
        raise ValueError("sources must be a non-empty list")
    allowed = {"crtsh", "otx", "rapiddns"}
    bad = set(sources) - allowed
    if bad:
        raise ValueError(f"sources {sorted(bad)} not in allowlist {sorted(allowed)}")
    if not isinstance(limit, int) or not (1 <= limit <= 5000):
        raise ValueError(f"limit out of range: {limit!r}")
    if not out_base or not out_base.startswith("/tmp/sentinel-harv-"):
        raise ValueError(f"out_base must be under /tmp/sentinel-harv-*: {out_base!r}")

    # Repeated -b per source (universally supported across 4.x versions).
    argv = [executable, "-d", domain]
    for s in sources:
        argv.extend(["-b", s])
    argv.extend(["-l", str(limit), "-f", out_base])
    return argv


register_profile(
    OperationProfile(
        name="theharvester/passive_discovery",
        builder=_build_theharvester_passive,
        required_params=frozenset({"domain", "sources", "limit", "out_base"}),
        prohibited_flags=THEHARVESTER_PROHIBITED_FLAGS,
        execution_class=1,
    )
)
