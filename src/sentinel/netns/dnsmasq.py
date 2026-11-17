# SPDX-License-Identifier: Apache-2.0
"""Per-run dnsmasq lifecycle inside a network namespace.

Each run starts one dnsmasq instance bound to 127.0.0.53:53 inside the
run namespace. It serves only the A/AAAA records the gatekeeper approved
for this run. No upstream, no /etc/hosts, no cache. A hostname not in
the approved set returns NXDOMAIN.

The caller creates the namespace; this module only manages the dnsmasq
process. ``namespace.run_namespace()`` enters this context after
namespace creation and exits before namespace deletion, so the process
is cleaned up even if the namespace is destroyed unexpectedly.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

# Exact-match hostname: letters/digits/hyphen labels, dots between labels,
# no leading/trailing dot, no underscores (dnsmasq rejects them anyway).
# Must also reject commas, slashes, newlines -- any char that would break
# the host-record= directive on a single line.
_VALID_HOSTNAME = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)


class DnsmasqError(RuntimeError):
    """dnsmasq failed to start, died unexpectedly, or was unavailable."""


def _dnsmasq_binary() -> str:
    path = shutil.which("dnsmasq")
    if path is None:
        raise DnsmasqError("dnsmasq binary not found on PATH")
    return path


class DnsmasqRunner:
    """Context manager for a per-run dnsmasq instance in a network namespace."""

    def __init__(
        self,
        ns_name: str,
        run_id: str,
        hostname_records: dict[str, list[str]],
        *,
        start_timeout: float = 2.0,
        stop_timeout: float = 2.0,
    ):
        self.ns_name = ns_name
        self.run_id = run_id
        self.hostname_records = hostname_records
        self.start_timeout = start_timeout
        self.stop_timeout = stop_timeout
        # Full uuid4 hex (32 chars) instead of 6-char prefix, so the temp
        # dir is not predictable to a local observer. veth and ns names
        # still use the short run_id (Linux 15-char limit).
        self.base_dir = Path(f"/tmp/sentinel-run-{run_id}-dns")
        self.conf_path = self.base_dir / "dnsmasq.conf"
        self.log_path = self.base_dir / "dnsmasq.log"
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> "DnsmasqRunner":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def _write_config(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.base_dir, 0o700)
        except OSError:
            pass
        lines = [
            "listen-address=127.0.0.53",
            "port=53",
            "bind-interfaces",
            "no-resolv",
            "no-hosts",
            "cache-size=0",
            "log-queries",
            f"log-facility={self.log_path}",
        ]
        # NOTE: dnsmasq's address=/domain/ip matches domain AND its
        # subdomains (*.domain). host-record= matches the exact hostname
        # only. For per-host scope authorization, host-record is required --
        # otherwise approving app.example.com would resolve
        # unapproved.app.example.com too.
        for hostname, ips in self.hostname_records.items():
            if not _VALID_HOSTNAME.match(hostname):
                raise DnsmasqError(
                    f"invalid hostname (only [a-z0-9.-] labels, no dot at edges): "
                    f"{hostname!r}"
                )
            for ip in ips:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError as e:
                    raise DnsmasqError(
                        f"invalid IP for {hostname!r}: {ip!r} ({e})"
                    ) from e
                lines.append(f"host-record={hostname},{addr}")
        self.conf_path.write_text("\n".join(lines) + "\n")
        try:
            os.chmod(self.conf_path, 0o600)
        except OSError:
            pass

    def start(self) -> None:
        if self.proc is not None:
            raise DnsmasqError("dnsmasq already started")
        self._write_config()
        argv = [
            "ip", "netns", "exec", self.ns_name,
            _dnsmasq_binary(),
            "--no-daemon",
            f"--conf-file={self.conf_path}",
        ]
        self.proc = subprocess.Popen(
            argv,
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Detect immediate crash (bad config, port already bound, etc).
        # We cannot easily probe the port from outside the namespace, so
        # a short liveness check is the pragmatic gate.
        polls = max(1, int(self.start_timeout / 0.05))
        for _ in range(polls):
            if self.proc.poll() is not None:
                raise DnsmasqError(
                    f"dnsmasq exited during startup (code {self.proc.returncode}); "
                    f"see {self.log_path}"
                )
            time.sleep(0.05)

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=self.stop_timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None
        for p in (self.conf_path, self.log_path):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None
