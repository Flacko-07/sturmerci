# SPDX-License-Identifier: Apache-2.0
"""Per-run network namespace lifecycle.

One namespace per run. The namespace contains:
  - A loopback interface.
  - One end of a veth pair; the other end lives in the main netns.
  - A dnsmasq instance bound to 127.0.0.53:53 (via DnsmasqRunner).

In the main netns, Sentinel's nftables rules gate every packet leaving
the run veth. On exit, the namespace is deleted, which tears down the
veth, dnsmasq, and any process still inside. Idempotent on exception
and on kill-switch.
"""

from __future__ import annotations

import os
import shutil
import time
import signal
import subprocess
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from . import nft
from .dnsmasq import DnsmasqRunner
from .lock import run_lock


class NamespaceError(RuntimeError):
    """Namespace creation, teardown, or veth setup failed."""


@dataclass(frozen=True, slots=True)
class NamespaceHandle:
    ns_name: str
    run_id: str
    veth_main: str
    veth_ns: str
    main_gateway_ip: str
    ns_ip: str
    base_dir: Path


def _ip(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    bin_ = shutil.which("ip")
    if bin_ is None:
        raise NamespaceError("ip binary not found on PATH")
    result = subprocess.run([bin_, *args], shell=False, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise NamespaceError(
            f"ip {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result


def _cleanup_stale() -> None:
    """Remove any veth interfaces or namespaces from a previous crashed run.

    Called at the top of run_namespace. Deleting is best-effort: a clean
    machine has nothing to clean, and a crashed run is fixed by getting
    rid of whatever partial state it left.
    """
    out = _ip("link", "show", check=False)
    for line in out.stdout.splitlines():
        # "12: veth_name: <BROADCAST,MULTICAST,UP,LOWER_UP>..."
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip()
        if name.startswith("snt-"):
            _ip("link", "delete", name, check=False)
    ns_out = _ip("netns", "list", check=False)
    for line in ns_out.stdout.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.startswith("sentinel-run-"):
            # Kill processes bound to the stale namespace before deleting
            # it, otherwise they become orphans of init with no network.
            _kill_namespace_processes(name)
            _ip("netns", "delete", name, check=False)


def _kill_namespace_processes(ns_name: str) -> list[int]:
    """Terminate any processes still bound to the namespace.

    Returns the list of PIDs still alive after SIGKILL + 300ms re-check.
    An empty list means cleanup is complete. A non-empty list means the
    kernel refused to kill them (uninterruptible sleep, or already
    reparented to init — the caller decides what to do).

    ``ip netns delete`` removes the namespace device but does not kill
    processes that still hold file descriptors on its interfaces. Left
    alone, such processes keep running with no network and their
    resources are not reclaimed until they exit. Enumerate via
    ``ip netns pids``, SIGTERM, grace period, SIGKILL, verify.
    """
    out = _ip("netns", "pids", ns_name, check=False)
    if out.returncode != 0:
        return
    pids: list[int] = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pids.append(int(line))
        except ValueError:
            continue
    if not pids:
        return

    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            continue

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        alive: list[int] = []
        for pid in pids:
            try:
                os.kill(pid, 0)
                alive.append(pid)
            except ProcessLookupError:
                continue
            except PermissionError:
                alive.append(pid)
        if not alive:
            return
        time.sleep(0.05)

    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            continue

    # P1.12: verify the SIGKILL actually took effect before returning.
    time.sleep(0.3)
    final = _ip("netns", "pids", ns_name, check=False)
    if final.returncode != 0:
        return []
    remaining: list[int] = []
    for line in final.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            remaining.append(int(line))
        except ValueError:
            continue
    return remaining


def _get_sysctl(name: str) -> str:
    r = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True)
    return r.stdout.strip()


def _set_sysctl(name: str, value: str) -> None:
    subprocess.run(
        ["sysctl", "-w", f"{name}={value}"],
        capture_output=True,
        check=True,
    )


@contextmanager
def run_namespace(
    *,
    approved: list[tuple[str, int] | tuple[str, int, str]],
    hostname_records: dict[str, list[str]],
    start_timeout: float = 2.0,
) -> Iterator[NamespaceHandle]:
    """Create a run namespace, install rules, yield a handle, tear down.

    Exclusive: only one run_namespace may be active per host at a time.
    Concurrent calls raise LockHeldError before any setup occurs.
    """
    run_id = uuid.uuid4().hex[:6]
    ns_name = f"sentinel-run-{run_id}"
    veth_main = f"snt-{run_id}"
    veth_ns = f"snt-{run_id}-n"
    main_ip = "10.99.0.1"
    ns_ip = "10.99.0.2"
    base_dir = Path(f"/tmp/sentinel-run-{run_id}")
    resolv_dir = Path(f"/etc/netns/{ns_name}")

    handle = NamespaceHandle(
        ns_name=ns_name,
        run_id=run_id,
        veth_main=veth_main,
        veth_ns=veth_ns,
        main_gateway_ip=main_ip,
        ns_ip=ns_ip,
        base_dir=base_dir,
    )

    with run_lock():
        _cleanup_stale()
        # (v3 hardening) Sysctl snapshots initialized to None so the OUTER
        # finally can reference them even if setup fails before sysctl
        # capture. Fixes: previously these were local-only inside the try,
        # so a failure before the DnsmasqRunner context left sysctls
        # modified forever.
        orig_fwd: str | None = None
        orig_rp_veth: str | None = None
        orig_rp_all: str | None = None
        orig_al_veth: str | None = None
        orig_al_all: str | None = None
        try:
            _ip("netns", "add", ns_name)
            _ip("link", "add", veth_main, "type", "veth", "peer", "name", veth_ns)
            _ip("link", "set", veth_ns, "netns", ns_name)
            _ip("addr", "add", f"{main_ip}/30", "dev", veth_main)
            _ip("link", "set", veth_main, "up")
            _ip(
                "netns",
                "exec",
                ns_name,
                "ip",
                "addr",
                "add",
                f"{ns_ip}/30",
                "dev",
                veth_ns,
            )
            _ip("netns", "exec", ns_name, "ip", "link", "set", veth_ns, "up")
            _ip("netns", "exec", ns_name, "ip", "link", "set", "lo", "up")
            _ip(
                "netns",
                "exec",
                ns_name,
                "ip",
                "route",
                "add",
                "default",
                "via",
                main_ip,
            )

            resolv_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(resolv_dir, 0o755)
            except OSError:
                pass
            (resolv_dir / "resolv.conf").write_text("nameserver 127.0.0.53\n")

            # (v4.1) Reconcile stale Sentinel state before installing.
            # `cleanup_stale()` removes any veth / namespace / nft table
            # fragment left by a prior run that was SIGKILLed or crashed
            # (a normal finally cannot fire after SIGKILL). Without this,
            # `nft.install()` sees the table already exists and returns
            # early, then per-run rules accumulate atop a stale base.
            nft.cleanup_stale()

            nft.install()
            # (batch A) Normalise: accept 2-tuple (ip, port) -> tcp, or
            # 3-tuple (ip, port, proto). Comment suffix "-udp" only added
            # when proto != tcp, so existing TCP comment-matching tests
            # are unaffected.
            for entry in approved:
                if len(entry) == 2:
                    ip_, port = entry
                    proto = "tcp"
                else:
                    ip_, port, proto = entry
                suffix = "" if proto == "tcp" else f"-{proto}"
                nft.add_approved(
                    ip_,
                    port,
                    protocol=proto,
                    veth=veth_main,
                    comment=f"allow-{ip_}-{port}{suffix}",
                )
            nft.add_default_denies(veth=veth_main)
            nft.add_default_denies(saddr=f"{ns_ip}/32", chain=nft.INPUT_CHAIN)
            nft.add_catchall_deny(veth_main)

            # Ordering matters: setting net.ipv4.ip_forward (alias for
            # conf/all/forwarding) from 0 to 1 resets every per-interface
            # forwarding-related sysctl to conf/default/*. So we enable
            # forwarding FIRST, then set per-iface values that survive.
            # If the order were reversed, rp_filter and accept_local
            # would be wiped on machines where ip_forward starts at 0.
            # Restore order in the finally block is the mirror: per-iface
            # values first, then ip_forward last -- the trailing reset to
            # conf/default/* will restore the operator's original defaults.
            orig_fwd = _get_sysctl("net.ipv4.ip_forward")
            if orig_fwd != "1":
                _set_sysctl("net.ipv4.ip_forward", "1")

            orig_rp_veth = _get_sysctl(f"net.ipv4.conf.{veth_main}.rp_filter")
            orig_rp_all = _get_sysctl("net.ipv4.conf.all.rp_filter")
            if orig_rp_veth != "0":
                _set_sysctl(f"net.ipv4.conf.{veth_main}.rp_filter", "0")
            if orig_rp_all != "0":
                _set_sysctl("net.ipv4.conf.all.rp_filter", "0")

            orig_al_veth = _get_sysctl(f"net.ipv4.conf.{veth_main}.accept_local")
            orig_al_all = _get_sysctl("net.ipv4.conf.all.accept_local")
            if orig_al_veth != "1":
                _set_sysctl(f"net.ipv4.conf.{veth_main}.accept_local", "1")
            if orig_al_all != "1":
                _set_sysctl("net.ipv4.conf.all.accept_local", "1")

            _ip("route", "add", f"{ns_ip}/32", "dev", veth_main, check=False)

            with DnsmasqRunner(
                ns_name=ns_name,
                run_id=run_id,
                hostname_records=hostname_records,
                start_timeout=start_timeout,
            ):
                yield handle
        finally:
            # (v3 hardening) Restore sysctls in the OUTER finally — NOT
            # inside DnsmasqRunner — so they are restored even if
            # DnsmasqRunner.__enter__ raises or any setup step between
            # sysctl-change and DnsmasqRunner fails. Mirror order:
            # per-iface first, ip_forward last (matches the conf/default
            # comment at the sysctl-setup block above).
            # (v4.1) Restore each sysctl in its OWN try block. Prior
            # version wrapped all five in one try/except; one failed
            # restore (e.g. EPERM on ip_forward while per-iface succeeded)
            # aborted the rest, leaving host sysctls partially modified
            # and the exception silently swallowed. Now:
            #   - each restore is independent
            #   - failures are logged with the specific setting and error
            #   - the cleanup continues to teardown (route, netns, veth)
            #   - operator sees an unmistakable warning if any restore
            #     failed, so they know to check host state manually
            import sys as _sys

            _sysctl_restores = [
                (f"net.ipv4.conf.{veth_main}.accept_local", orig_al_veth, "1"),
                ("net.ipv4.conf.all.accept_local", orig_al_all, "1"),
                (f"net.ipv4.conf.{veth_main}.rp_filter", orig_rp_veth, "0"),
                ("net.ipv4.conf.all.rp_filter", orig_rp_all, "0"),
                ("net.ipv4.ip_forward", orig_fwd, "1"),
            ]
            _sysctl_failures: list[str] = []
            for _name, _orig, _noop_val in _sysctl_restores:
                if _orig is None or _orig == _noop_val:
                    continue
                try:
                    _set_sysctl(_name, _orig)
                except Exception as _e:
                    _sysctl_failures.append(
                        f"{_name}={_orig}: {type(_e).__name__}: {_e}"
                    )
            if _sysctl_failures:
                print(
                    "[sentinel-cleanup] WARNING: sysctl restore was "
                    "incomplete — some host settings may still be at "
                    "the modified values. Verify manually before the "
                    "next run. Failed restores: " + "; ".join(_sysctl_failures),
                    file=_sys.stderr,
                    flush=True,
                )
            _ip("route", "delete", f"{ns_ip}/32", "dev", veth_main, check=False)
            # Kill processes still bound to the namespace BEFORE deleting
            # it. ip netns delete removes the device but not the processes
            # using it.
            remaining = _kill_namespace_processes(ns_name)
            if remaining:
                import sys as _sys

                print(
                    f"[sentinel-cleanup] WARNING: {len(remaining)} process(es) "
                    f"still alive in namespace {ns_name!r} after SIGKILL: "
                    f"{remaining}",
                    file=_sys.stderr,
                    flush=True,
                )
            _ip("netns", "delete", ns_name, check=False)
            _ip("link", "delete", veth_main, check=False)
            nft.remove()
            shutil.rmtree(resolv_dir, ignore_errors=True)
            shutil.rmtree(base_dir, ignore_errors=True)
