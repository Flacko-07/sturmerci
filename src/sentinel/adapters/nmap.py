# SPDX-License-Identifier: Apache-2.0
"""Nmap TCP connect adapter — first active-assessment adapter (M6.1).

Runs `nmap -sT -Pn -n --max-rate N -p PORTS -oX - <target>` through
SandboxRunner. NSE scripts, OS detection, service-version detection, and
all non-TCP-connect scans are refused by both the argv builder and a
defensive post-construction check.

Findings are written to candidate_assets with asset_type='service' and
canonical_value='<host>:<port>/<proto>'. They are never promoted to
approved_assets automatically; the operator promotes explicitly after
reviewing the output.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from sentinel.assets.store import AssetStore
from sentinel.runner.sandbox_runner import (
    SandboxDenied, SandboxRequest, SandboxResult, run_in_sandbox,
)
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


NMAP_TOOL_NAME = "nmap"
NMAP_VERSION = "7.94"
PROFILE = "tcp_connect_scan"

# Flags that must never appear in a Nmap invocation. If an adapter ever
# constructs argv containing one, we refuse before SandboxRunner sees it.
FORBIDDEN_FLAGS = (
    "--script", "-sC", "-sV", "-A", "-O",
    "-sU", "-sS", "-sA", "-sW", "-sM",
    "--traceroute", "--osscan-limit", "--osscan-guess",
    "-sI", "-b", "--interactive",
)


class NmapAdapterError(ValueError):
    """Adapter refused the request (independent of sandbox denial)."""


@dataclass(frozen=True, slots=True)
class PortObservation:
    host: str
    port: int
    protocol: str
    state: str
    ip: str


@dataclass(frozen=True, slots=True)
class NmapRunResult:
    findings: list[PortObservation]
    open_ports_written: int
    candidates_skipped_duplicate: int
    sandbox: SandboxResult
    execution_status: str = "COMPLETED"


def _assert_no_forbidden_flags(argv: list[str]) -> None:
    for a in argv:
        for forbidden in FORBIDDEN_FLAGS:
            if a == forbidden or a.startswith(forbidden + "="):
                raise NmapAdapterError(
                    f"forbidden Nmap flag in argv: {a!r} "
                    f"(policy prohibits NSE, OS detection, "
                    f"service-version detection, and non-TCP-connect scans)"
                )


def build_argv(
    executable_path: str,
    target: str,
    ports: list[int],
    max_rate: int,
) -> list[str]:
    if not ports:
        raise NmapAdapterError("ports list is empty")
    for p in ports:
        if not isinstance(p, int) or not (1 <= p <= 65535):
            raise NmapAdapterError(f"invalid port: {p!r}")
    if not (1 <= max_rate <= 1000):
        raise NmapAdapterError(f"max_rate out of range: {max_rate}")

    argv = [
        executable_path,
        "-sT",                 # TCP connect() — no raw sockets, no admin
        "-Pn",                 # skip host discovery (ICMP may be blocked)
        "-n",                  # no reverse DNS
        "--max-rate", str(max_rate),
        "-p", ",".join(str(p) for p in sorted(ports)),
        "-oX", "-",            # XML to stdout
        target,
    ]
    _assert_no_forbidden_flags(argv)
    return argv


def parse_output(
    xml: str,
    target_hostname: str,
    *,
    expected_ips: frozenset[str] | None = None,
    expected_ports: frozenset[int] | None = None,
    expected_protocol: str = "tcp",
) -> list[PortObservation]:
    """Parse Nmap XML output. Never raises; malformed XML yields [].

    When expected_ips / expected_ports are provided, observations that
    don't match are dropped and counted as rejected. Defends against:
    - a compromised nmap binary emitting bogus findings
    - DNS races producing findings against IPs we didn't approve
    - Nmap emitting UDP or non-requested ports (shouldn't, but shouldn't trust)
    """
    findings: list[PortObservation] = []
    if not xml or not xml.strip():
        return findings
    if expected_protocol != "tcp":
        raise ValueError(
            f"only 'tcp' protocol is supported, got {expected_protocol!r}"
        )
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        # A capture cap or timeout can cut off the XML document after one
        # or more complete <host> blocks. Recover only individually
        # well-formed complete host elements; never infer observations
        # from a half-written port/host fragment.
        host_elements = _complete_hosts_from_partial_xml(xml)
    else:
        if root.tag != "nmaprun":
            return findings
        host_elements = root.findall("host")
    # Preserve parsed observations when runstats is absent or incomplete;
    # the adapter labels the run PARTIAL/FAILED and never calls it complete.
    for host_el in host_elements:
        addr_el = host_el.find("address")
        ip = ""
        if addr_el is not None:
            ip = addr_el.get("addr") or ""
        # IP validation: if a whitelist was given, reject unknown IPs
        if expected_ips is not None and ip not in expected_ips:
            continue
        for port_el in host_el.findall("ports/port"):
            portid = port_el.get("portid")
            protocol = (port_el.get("protocol") or "tcp").lower()
            if protocol != expected_protocol:
                continue
            try:
                port_int = int(portid)
            except (TypeError, ValueError):
                continue
            if not (1 <= port_int <= 65535):
                continue
            if expected_ports is not None and port_int not in expected_ports:
                continue
            state_el = port_el.find("state")
            state = "unknown"
            if state_el is not None:
                state = (state_el.get("state") or "unknown").lower()
            findings.append(PortObservation(
                host=target_hostname,
                port=port_int,
                protocol=protocol,
                state=state,
                ip=ip,
            ))
    return findings


def _complete_hosts_from_partial_xml(xml: str) -> list[ET.Element]:
    """Extract complete, independently parseable Nmap host elements."""
    hosts: list[ET.Element] = []
    cursor = 0
    while True:
        start = xml.find("<host", cursor)
        if start < 0:
            break
        after_name = start + len("<host")
        if after_name < len(xml) and xml[after_name] not in "\t\r\n />":
            cursor = after_name
            continue
        close = xml.find("</host>", after_name)
        if close < 0:
            break
        end = close + len("</host>")
        try:
            element = ET.fromstring(xml[start:end])
        except ET.ParseError:
            cursor = end
            continue
        if element.tag == "host":
            hosts.append(element)
        cursor = end
    return hosts


def run_nmap(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_hostname: str,
    ports: list[int],
    engagements_root: Path,
    actor: str = "operator",
    timeout_seconds: int = 300,
) -> NmapRunResult:
    """Run pinned Nmap via SandboxRunner.

    Pre-conditions enforced by SandboxRunner:
      - manifest registered, network-capable, class 2, hash-verified
      - approval belongs to engagement and covers every port in `ports`
      - target_hostname is in approved_assets
      - all resolved IPs not in protected ranges
      - gatekeeper decision per port

    Post-conditions:
      - every state='open' finding written to candidate_assets
        (asset_type='service', canonical_value='<host>:<port>/<proto>')
      - duplicate suppression against existing service candidates
      - no write to approved_assets
    """
    db_obj, owns_db = coerce_db(db)
    try:
        manifest = ManifestStore(db_obj).get_by_tool_version(
            NMAP_TOOL_NAME, NMAP_VERSION,
        )
        if manifest is None:
            raise SandboxDenied(
                f"nmap {NMAP_VERSION} not registered — see "
                "docs/operator-guide.md for the registration script"
            )
        if not manifest.manifest.network_access:
            raise SandboxDenied(
                "nmap manifest is not network-capable"
            )

        # Rate limit comes from the approval's request_rate_budget
        from sentinel.approval.store import ApprovalStore
        approval = ApprovalStore(db_obj).get(approval_id)
        if approval is None:
            raise SandboxDenied(f"approval {approval_id!r} not found")
        # P0.5: port scanning targets the resolved infrastructure, not just
        # the logical hostname. Approving a hostname does not auto-approve
        # its CDN or shared-IP tenants. The operator must affirm this.
        if not approval.port_scanning_authorized:
            raise SandboxDenied(
                f"approval {approval_id!r} does not authorize port scanning "
                "of the resolved infrastructure. The program must explicitly "
                "permit scanning the underlying IP, not just the hostname. "
                "Re-issue the approval with port_scanning_authorized=True "
                "after verifying the program's scope covers shared infrastructure."
            )
        rate = max(1, min(int(approval.request_rate_budget), 1000))

        argv = build_argv(
            executable_path=manifest.manifest.executable_path,
            target=target_hostname,
            ports=ports,
            max_rate=rate,
        )

        sorted_ports = sorted(set(ports))
        request = SandboxRequest(
            hostname=target_hostname,
            port=sorted_ports[0],
            protocol="tcp",
            method="connect",
            path="/",
            argv=argv,
            timeout_seconds=timeout_seconds,
            additional_ports=tuple(sorted_ports[1:]),
            estimated_requests=len(sorted_ports),
            # (v4.1) Reserve byte budget: ~500 bytes per open-port
            # fragment in nmap -oX output. Closed ports produce no
            # fragment, so this is a conservative upper bound.
            estimated_output_bytes=len(sorted_ports) * 500,
            operation_profile="nmap/tcp_connect_scan",
            profile_params={
                "target": target_hostname,
                "ports": sorted_ports,
                "max_rate": rate,
            },
        )

        sandbox_result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=NMAP_TOOL_NAME,
            adapter_version=NMAP_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )

        # Validate output against the approved resolution set and port list.
        # Refuses to trust an nmap binary that emitted findings outside scope.
        findings = parse_output(
            sandbox_result.stdout,
            target_hostname,
            expected_ips=frozenset(sandbox_result.resolved_ips),
            expected_ports=frozenset(sorted_ports),
            expected_protocol="tcp",
        )

        seen: set[str] = set()
        written = 0
        duplicates = 0
        asset_store = AssetStore(db_obj)

        with db_obj.transaction() as conn:
            for f in findings:
                if f.state != "open":
                    continue
                canonical = f"{target_hostname}:{f.port}/{f.protocol}"
                if canonical in seen:
                    duplicates += 1
                    continue
                seen.add(canonical)

                existing = conn.execute(
                    "SELECT 1 FROM candidate_assets "
                    "WHERE engagement_id = ? AND canonical_value = ?",
                    (engagement_id, canonical),
                ).fetchone()
                if existing:
                    duplicates += 1
                    continue

                asset_store.add_candidate(
                    engagement_id=engagement_id,
                    raw_value=f"{f.ip}:{f.port}/{f.protocol}",
                    canonical_value=canonical,
                    asset_type="service",
                    discovery_source=f"nmap:{PROFILE}",
                    discovery_metadata={
                        "execution_status": sandbox_result.execution_status,
                        "stdout_truncated": sandbox_result.truncated_stdout,
                        "stderr_truncated": sandbox_result.truncated_stderr,
                        "stdout_bytes": sandbox_result.stdout_bytes,
                        "stderr_bytes": sandbox_result.stderr_bytes,
                        "timed_out": sandbox_result.timed_out,
                        "terminated": sandbox_result.terminated,
                        "exit_code": sandbox_result.exit_code,
                        "output_limit_bytes": sandbox_result.output_limit_bytes,
                    },
                )
                written += 1

        return NmapRunResult(
            findings=findings,
            open_ports_written=written,
            candidates_skipped_duplicate=duplicates,
            sandbox=sandbox_result,
            execution_status=sandbox_result.execution_status,
    )
    finally:
        if owns_db:
            db_obj.close()
