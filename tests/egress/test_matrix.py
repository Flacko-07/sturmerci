# SPDX-License-Identifier: Apache-2.0
"""Egress bypass matrix — E-01 through E-14.

Run under sudo:  sudo -E "$(which python)" -m pytest tests/egress/ -v

Every test needs root (namespace creation). The whole file is skipped
unprivileged. The container is a fresh ``run_namespace`` per test, so
each test is independent of the others.

Each test asserts BOTH:
  1. The operation fails (OSError on the child) OR succeeds for E-12..
     E-14 (proving approved destinations still work).
  2. A specific nft counter increments, so a test failure that happens
     because the main netns couldn't route (rather than nft blocked) is
     distinguishable from a real bypass.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from sentinel.netns.namespace import run_namespace
from sentinel.netns import nft


pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="egress tests require root (network namespace creation)",
)


def _have_tools() -> bool:
    return all(shutil.which(t) for t in ("ip", "nft", "dnsmasq"))


if not _have_tools():
    pytestmark = pytest.mark.skip(
        reason="ip, nft, or dnsmasq missing — see docs/egress-test-matrix.md"
    )


def _run_in_ns(
    ns_name: str, argv: list[str], *, timeout: float = 8.0
) -> subprocess.CompletedProcess:
    """Run argv inside the given namespace. Returns the completed process."""
    return subprocess.run(
        ["ip", "netns", "exec", ns_name, *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _child_connect(
    ns_name: str, ip: str, port: int, *, timeout: float = 5.0
) -> subprocess.CompletedProcess:
    """Attempt a TCP connect from inside the namespace using child python."""
    script = (
        "import socket, sys\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.settimeout(2.0)\n"
        "try:\n"
        f"    s.connect(('{ip}', {port}))\n"
        "    print('connected')\n"
        "    sys.exit(0)\n"
        "except Exception as e:\n"
        "    print(f'error: {type(e).__name__}: {e}')\n"
        "    sys.exit(1)\n"
        "finally:\n"
        "    try: s.close()\n"
        "    except Exception: pass\n"
    )
    return _run_in_ns(ns_name, ["python3", "-c", script], timeout=timeout)


def _counter(comment: str) -> int:
    """Current packet count for the rule with ``comment``."""
    return nft.counters().get(comment, 0)


# ---------------------------------------------------------------------------
# E-01 .. E-06: attempts from inside the namespace to reach unapproved
# public destinations must fail, and the specific deny rule must fire.
# ---------------------------------------------------------------------------


def test_e01_direct_public_ip():
    """E-01: direct TCP to a public IP not in the approved set is blocked
    by the catch-all deny."""
    with run_namespace(
        approved=[],
        hostname_records={},
    ) as ns:
        r = _child_connect(ns.ns_name, "1.1.1.1", 443)
        assert r.returncode != 0, f"child should not connect: {r.stdout}"
        assert "error:" in r.stdout
        assert _counter("deny-out") > 0, "deny-out counter did not increment"


def test_e02_dns_nxdomain():
    """E-02: the per-run dnsmasq returns NXDOMAIN for unapproved hostnames."""
    with run_namespace(
        approved=[],
        hostname_records={"probe.test": ["1.1.1.1"]},
    ) as ns:
        r = _run_in_ns(ns.ns_name, ["getent", "hosts", "evil.test"])
        assert r.returncode != 0, f"getent should not resolve evil.test: {r.stdout!r}"
        # Approved hostname still resolves (proves dnsmasq is up, not just silent)
        r2 = _run_in_ns(ns.ns_name, ["getent", "hosts", "probe.test"])
        assert r2.returncode == 0
        assert "1.1.1.1" in r2.stdout


def test_e03_external_dns():
    """E-03: hard-coded external DNS (8.8.8.8:53) is blocked."""
    with run_namespace(approved=[], hostname_records={}) as ns:
        r = _child_connect(ns.ns_name, "8.8.8.8", 53)
        assert r.returncode != 0
        assert _counter("deny-out") > 0


def test_e04_curl_no_proxy():
    """E-04: curl --noproxy '*' cannot reach an unapproved public IP.
    (There is no proxy at all in this design — nft is the sole control.)"""
    with run_namespace(approved=[], hostname_records={}) as ns:
        r = _run_in_ns(
            ns.ns_name,
            [
                "curl",
                "--noproxy",
                "*",
                "--connect-timeout",
                "2",
                "-sS",
                "http://1.1.1.1/",
            ],
            timeout=8.0,
        )
        assert r.returncode != 0, f"curl should fail: {r.stdout}"
        assert _counter("deny-out") > 0


def test_e05_grandchild_socket():
    """E-05: a grandchild process spawned by a child cannot open a socket."""
    script = (
        "import subprocess, sys\n"
        'code = "import socket,sys; s=socket.socket(); s.settimeout(2);\\n'
        "try: s.connect(('1.1.1.1',443)); sys.exit(0)\\n"
        "except Exception: sys.exit(1)\\n"
        'finally: s.close()"\n'
        "r = subprocess.run(['python3', '-c', code], capture_output=False)\n"
        "sys.exit(r.returncode)\n"
    )
    with run_namespace(approved=[], hostname_records={}) as ns:
        r = _run_in_ns(ns.ns_name, ["python3", "-c", script], timeout=10.0)
        assert r.returncode != 0, "grandchild should not connect"
        assert _counter("deny-out") > 0


def test_e06_hardcoded_resolver():
    """E-06: direct connect to an external DNS server on port 53 is blocked.
    Distinct from E-03: E-03 uses the DNS protocol; E-06 is a raw TCP connect
    proving the destination port is blocked regardless of protocol."""
    with run_namespace(approved=[], hostname_records={}) as ns:
        r = _child_connect(ns.ns_name, "9.9.9.9", 53)
        assert r.returncode != 0
        assert _counter("deny-out") > 0


# ---------------------------------------------------------------------------
# E-07 .. E-11: paths that matter specifically on this WSL2 topology.
# ---------------------------------------------------------------------------

WSL_GATEWAY = "172.18.48.1"
DOCKER_GATEWAYS = ("172.17.0.1", "172.19.0.1", "172.20.0.1")
DOCKER_BRIDGE = "172.17.0.2"  # a typical container address


def test_e07_wsl_gateway():
    """E-07: the WSL default gateway (Windows host reachable via WSL) is
    blocked by deny-172.16.0.0/12."""
    with run_namespace(approved=[], hostname_records={}) as ns:
        r = _child_connect(ns.ns_name, WSL_GATEWAY, 80)
        assert r.returncode != 0, f"WSL gateway should be blocked: {r.stdout}"
        assert _counter("deny-172.16.0.0/12") > 0


def test_e08_telemetry():
    """E-08: a vendor telemetry endpoint (semgrep.dev's Cloudflare IP as a
    stand-in for any vendor endpoint) is blocked."""
    with run_namespace(approved=[], hostname_records={}) as ns:
        r = _child_connect(ns.ns_name, "104.18.25.39", 443)
        assert r.returncode != 0, f"telemetry should be blocked: {r.stdout}"
        assert _counter("deny-out") > 0


@pytest.mark.parametrize("gw_ip", DOCKER_GATEWAYS)
def test_e09_docker_gateways(gw_ip):
    """E-09: Docker network gateways are blocked by deny-172.16.0.0/12."""
    with run_namespace(approved=[], hostname_records={}) as ns:
        r = _child_connect(ns.ns_name, gw_ip, 80)
        assert r.returncode != 0, f"{gw_ip} should be blocked: {r.stdout}"
        assert _counter("deny-172.16.0.0/12") > 0


def test_e10_docker_bridge():
    """E-10: Docker bridge (container) address is blocked.

    Requires a live container at DOCKER_BRIDGE for the forward hook to
    fire. Without one, the packet is dropped by routing (no ARP reply)
    — connection blocked but RFC1918 counter stays 0. This distinguishes
    "rule fires" from "no forwarding target" instead of silently passing
    or failing both.

    Prior version of this test depended on an end-to-end run leaving a
    container at 172.17.0.2; removing that container exposed the ambient
    state dependency.
    """
    import subprocess as _sp

    probe = _sp.run(
        [
            "bash",
            "-c",
            f"timeout 1 bash -c 'cat < /dev/tcp/{DOCKER_BRIDGE}/80' 2>/dev/null",
        ],
        capture_output=True,
    )
    if probe.returncode != 0:
        pytest.skip(
            f"no live container at {DOCKER_BRIDGE}:80 — RFC1918 rule "
            f"cannot fire without a forwarding target. "
            f"To make this test run: "
            f"docker run -d --rm busybox:latest sleep 300"
        )
    with run_namespace(approved=[], hostname_records={}) as ns:
        r = _child_connect(ns.ns_name, DOCKER_BRIDGE, 80)
        assert r.returncode != 0, f"bridge {DOCKER_BRIDGE} should be blocked"
        assert _counter("deny-172.16.0.0/12") > 0


def test_e11_resolv_conf_untouched():
    """E-11: the main-netns /etc/resolv.conf is not modified by the run;
    the namespace uses its own bind-mounted copy."""
    main_resolv = Path("/etc/resolv.conf")
    before_stat = main_resolv.stat()
    before_content = main_resolv.read_text()

    with run_namespace(
        approved=[],
        hostname_records={"probe.test": ["1.1.1.1"]},
    ) as ns:
        # Inside the namespace, resolv.conf must be our per-run copy
        r = _run_in_ns(ns.ns_name, ["cat", "/etc/resolv.conf"])
        assert r.returncode == 0
        assert "127.0.0.53" in r.stdout

    after_stat = main_resolv.stat()
    after_content = main_resolv.read_text()
    assert before_content == after_content, "main /etc/resolv.conf changed"
    assert before_stat.st_mtime == after_stat.st_mtime, (
        "main /etc/resolv.conf mtime changed"
    )


# ---------------------------------------------------------------------------
# E-12 .. E-14: the approved path must remain reachable, and the DNS stub
# must answer for approved hostnames. Guards against over-blocking.
# ---------------------------------------------------------------------------


def test_e12_approved_destination_allowed():
    """E-12: an approved external destination is matched by its allow rule
    before the catch-all deny fires.

    The connection itself will time out (no server at 1.1.1.1:443 answers
    our SYN), but the SYN must traverse the forward chain and match the
    allow rule rather than reaching the catch-all deny. This proves the
    allow-before-deny ordering works for external egress.

    We do NOT test local delivery (e.g., binding a listener on the veth
    IP) here -- that path goes through the input chain, not forward, and
    is out of scope for the egress design.
    """
    with run_namespace(
        approved=[("1.1.1.1", 443)],
        hostname_records={},
    ) as ns:
        # Attempt the approved connection. Timeout is expected; we check
        # the counters, not the return code.
        _child_connect(ns.ns_name, "1.1.1.1", 443)

        allow = _counter("allow-1.1.1.1-443")
        deny = _counter("deny-out")
        assert allow > 0, (
            f"allow rule did not fire (allow={allow}); the packet may not "
            f"have reached the forward chain -- check ip_forward"
        )
        assert deny == 0, (
            f"catch-all deny fired on approved traffic (deny={deny}); "
            f"allow rules must precede catch-all in the chain"
        )


def test_e13_approved_hostname_resolves():
    """E-13: dnsmasq returns the pinned A record for an approved hostname."""
    with run_namespace(
        approved=[],
        hostname_records={"probe.test": ["203.0.113.42"]},
    ) as ns:
        r = _run_in_ns(ns.ns_name, ["getent", "hosts", "probe.test"])
        assert r.returncode == 0
        assert "203.0.113.42" in r.stdout
        assert "probe.test" in r.stdout


def test_e14_loopback_inside_namespace():
    """E-14: dnsmasq on 127.0.0.53:53 is reachable from inside the
    namespace (loopback traffic does not traverse the veth, so the
    deny-127.0.0.0/8 rule does not apply)."""
    with run_namespace(
        approved=[],
        hostname_records={"probe.test": ["1.1.1.1"]},
    ) as ns:
        # Use child python — raw UDP query to 127.0.0.53:53 for a known name.
        script = (
            "import socket, struct, sys\n"
            "q = b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00'\n"
            "q += b'\\x05probe\\x04test\\x00\\x00\\x01\\x00\\x01'\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s.settimeout(2.0)\n"
            "try:\n"
            "    s.sendto(q, ('127.0.0.53', 53))\n"
            "    data, _ = s.recvfrom(512)\n"
            "    sys.exit(0 if len(data) > 0 else 1)\n"
            "except Exception as e:\n"
            "    print(f'error: {e}')\n"
            "    sys.exit(2)\n"
            "finally:\n"
            "    s.close()\n"
        )
        r = _run_in_ns(ns.ns_name, ["python3", "-c", script], timeout=6.0)
        assert r.returncode == 0, f"loopback DNS should work: {r.stdout}"


# ---------------------------------------------------------------------------
# E-15 .. E-17: hardening tests added by M4.1
# ---------------------------------------------------------------------------


def test_e15_ipv6_denial():
    """E-15: the namespace cannot reach any IPv6 destination.

    The namespace is v4-only by configuration, but a future change could
    add a v6 route. This test asserts the security property directly:
    no IPv6 connection succeeds, regardless of whether it fails at route
    lookup or at the nft rule.
    """
    script = (
        "import socket\n"
        "results = []\n"
        "for addr in ('::1', '2001:db8::1', 'fe80::1'):\n"
        "    try:\n"
        "        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n"
        "        s.settimeout(0.5)\n"
        "        try:\n"
        "            s.connect((addr, 443))\n"
        "            results.append(f'{addr}=CONNECTED')\n"
        "        except Exception as e:\n"
        "            results.append(f'{addr}={type(e).__name__}')\n"
        "        finally:\n"
        "            s.close()\n"
        "    except Exception as e:\n"
        "        results.append(f'{addr}=setup_{type(e).__name__}')\n"
        "print('|'.join(results))\n"
    )
    with run_namespace(approved=[], hostname_records={}) as ns:
        r = _run_in_ns(ns.ns_name, ["python3", "-c", script], timeout=8.0)
        assert "CONNECTED" not in r.stdout, f"IPv6 leak: {r.stdout}"


def test_e16_protected_ip_cannot_be_approved():
    """E-16: approving an IP inside DENIED_RANGES raises ValueError."""
    from sentinel.netns import nft

    for protected in ("127.0.0.1", "169.254.169.254", "10.1.2.3", "172.18.48.1"):
        with pytest.raises(ValueError, match="protected range"):
            nft.add_approved(protected, 443, comment="should-fail")


def test_e17_dns_only_resolves_exact_hostname():
    """E-17: only the exact approved hostname resolves, not subdomains.

    dnsmasq's address=/x/ matches x AND *.x. host-record=x matches x only.
    Approving app.example.com must not implicitly approve
    sub.app.example.com.
    """
    with run_namespace(
        approved=[],
        hostname_records={"probe.test": ["203.0.113.42"]},
    ) as ns:
        # Exact host resolves
        r = _run_in_ns(ns.ns_name, ["getent", "hosts", "probe.test"])
        assert r.returncode == 0, f"exact host should resolve: {r.stdout}"
        assert "203.0.113.42" in r.stdout
        # Subdomain must NOT resolve
        r = _run_in_ns(ns.ns_name, ["getent", "hosts", "sub.probe.test"])
        assert r.returncode != 0, f"subdomain should NOT resolve, got: {r.stdout}"
        # Unrelated host must NOT resolve
        r = _run_in_ns(ns.ns_name, ["getent", "hosts", "other.test"])
        assert r.returncode != 0


# ---------------------------------------------------------------------------
# E-18, E-21: hardening — concurrency and process cleanup
# ---------------------------------------------------------------------------


def test_e18_concurrent_namespace_refused():
    """E-18: a second run_namespace while one is active raises LockHeldError."""
    from sentinel.netns.lock import LockHeldError

    with run_namespace(approved=[], hostname_records={}):
        # Same process attempts to open a second one
        with pytest.raises(LockHeldError):
            with run_namespace(approved=[], hostname_records={}):
                pytest.fail("second run should have raised before yielding")


def test_e21_namespace_processes_killed_on_exit():
    """E-21: processes bound to the namespace are killed on cleanup.

    Spawns a detached sleep inside the namespace, then exits the context.
    After exit, the sleep must be dead (kernel SIGTERM via
    _kill_namespace_processes). This proves ip netns delete does not
    leave orphan processes in a zombie-free state.
    """
    import tempfile

    tmpdir = Path(tempfile.mkdtemp(prefix="sentinel-e21-"))
    pid_file = tmpdir / "pid"

    bg_pid: int | None = None
    launcher: subprocess.Popen | None = None

    try:
        with run_namespace(approved=[], hostname_records={}):
            script = (
                "import os, subprocess, time\n"
                "p = subprocess.Popen(['sleep', '60'])\n"
                f"open('{pid_file}', 'w').write(str(p.pid))\n"
                "time.sleep(60)\n"
            )
            launcher = subprocess.Popen(
                ["ip", "netns", "exec", ns.ns_name, "python3", "-c", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if pid_file.exists():
                    text = pid_file.read_text().strip()
                    if text:
                        bg_pid = int(text)
                        break
                time.sleep(0.05)

            assert bg_pid is not None, "background process did not start"
            # Confirm the background process is alive BEFORE cleanup
            os.kill(bg_pid, 0)  # raises ProcessLookupError if dead

        # Context exited -- _kill_namespace_processes should have killed it
        time.sleep(0.3)
        with pytest.raises(ProcessLookupError):
            os.kill(bg_pid, 0)
    finally:
        if launcher is not None:
            try:
                launcher.wait(timeout=3)
            except subprocess.TimeoutExpired:
                launcher.kill()
                launcher.wait()
        try:
            pid_file.unlink(missing_ok=True)
        except OSError:
            pass
        import shutil as _sh

        _sh.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# E-20: sysctl restoration after success and failure
# ---------------------------------------------------------------------------


def _sysctl_value(name: str) -> str:
    r = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True)
    return r.stdout.strip()


def test_e20a_sysctls_applied_and_restored_after_success():
    """E-20a: sysctls are set during run and fully restored on clean exit.

    Proves both that the ordering is right (per-iface values survive the
    ip_forward flip) and that restoration restores the operator's values.
    """
    names = (
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.all.accept_local",
    )
    pre = {n: _sysctl_value(n) for n in names}

    with run_namespace(approved=[], hostname_records={}) as ns:
        # During run: values must be the enforced ones
        assert _sysctl_value("net.ipv4.ip_forward") == "1"
        assert _sysctl_value("net.ipv4.conf.all.rp_filter") == "0"
        assert _sysctl_value("net.ipv4.conf.all.accept_local") == "1"
        # Per-iface must have survived the ip_forward flip
        assert _sysctl_value(f"net.ipv4.conf.{ns.veth_main}.rp_filter") == "0"
        assert _sysctl_value(f"net.ipv4.conf.{ns.veth_main}.accept_local") == "1"

    post = {n: _sysctl_value(n) for n in names}
    assert post == pre, f"sysctls not restored after success. pre={pre!r} post={post!r}"


def test_e20b_sysctls_restored_after_exception():
    """E-20b: sysctls restored even when the run body raises.

    The finally block must run. If a scanner crashes mid-run, the host's
    global sysctls must not remain in the permissive state.
    """
    names = (
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.all.accept_local",
    )
    pre = {n: _sysctl_value(n) for n in names}

    with pytest.raises(RuntimeError, match="simulated-scanner-crash"):
        with run_namespace(approved=[], hostname_records={}) as ns:
            # Inside the run: values enforced
            assert _sysctl_value("net.ipv4.conf.all.rp_filter") == "0"
            raise RuntimeError("simulated-scanner-crash")

    post = {n: _sysctl_value(n) for n in names}
    assert post == pre, (
        f"sysctls not restored after exception. pre={pre!r} post={post!r}"
    )
