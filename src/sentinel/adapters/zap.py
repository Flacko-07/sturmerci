# SPDX-License-Identifier: Apache-2.0
"""OWASP ZAP adapter — baseline passive scan (Class 2).

Runs `zap-baseline.py` as a single-shot process against a target URL.
The script spawns a ZAP daemon on localhost, spiders, waits for passive
scan results, writes XML + HTML reports, then kills the daemon.

Class 2: spider sends GET requests, passive scan analyses responses.
`-a` (active scan) is on the profile's prohibited flags.

Per-run /tmp/sentinel-zap-<uuid>/ provides HOME (ZAP writes ~/.ZAP),
cwd, and report paths. ACL grants `nobody` write; shutil.rmtree in
finally so `nflacko` can clean up. JAVA_HOME is explicitly set because
the minimal-env allowlist doesn't include it.
"""
from __future__ import annotations

import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from sentinel.adapters._helpers import prepare_sandbox_dir
from xml.etree import ElementTree as ET

from sentinel.approval.store import ApprovalStore
from sentinel.audit.store import AuditStore
from sentinel.evidence.ingest import ingest_evidence, IngestResult
from sentinel.runner.profiles import build_argv_for_profile
from sentinel.runner.sandbox_runner import SandboxRequest, run_in_sandbox
from sentinel.storage.db import Database, coerce_db
from sentinel.tools.manifests import ManifestStore


ZAP_TOOL_NAME = "zap"
ZAP_VERSION = "2.17.0"
PROFILE = "baseline_scan"
ZAP_JAVA_HOME = "/usr/lib/jvm/java-17-openjdk-amd64"

_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}
_CONF = {"0": "false_positive", "1": "low", "2": "medium",
         "3": "high", "4": "confirmed"}


class ZapAdapterError(ValueError):
    """ZAP adapter refused the request."""


@dataclass(frozen=True, slots=True)
class ZapFinding:
    plugin_id: str
    name: str
    risk: str
    confidence: str
    url: str
    cwe_id: str
    instance_count: int


@dataclass(frozen=True, slots=True)
class ZapRunResult:
    findings: list[ZapFinding]
    findings_count: int
    evidence: IngestResult
    process_exit_code: int
    timed_out: bool = False
    report_bytes: int = 0
    execution_status: str = "COMPLETED"


def parse_report(xml_text: str) -> list[ZapFinding]:
    """Parse ZAP v2 XML report. One ZapFinding per alertitem."""
    if not xml_text or not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    out: list[ZapFinding] = []
    for site in root.findall("site"):
        for alert in site.findall("alerts/alertitem"):
            plugin_id = (alert.findtext("pluginid") or "").strip()
            name = (alert.findtext("name") or alert.findtext("alert") or "").strip()
            risk_code = (alert.findtext("riskcode") or "0").strip()
            conf_code = (alert.findtext("confidence") or "2").strip()
            cwe_id = (alert.findtext("cweid") or "").strip()
            instances = alert.findall("instances/instance")
            url = ""
            if instances:
                url = (instances[0].findtext("uri") or "").strip()
            out.append(ZapFinding(
                plugin_id=plugin_id[:20],
                name=name[:300],
                risk=_RISK.get(risk_code, "info"),
                confidence=_CONF.get(conf_code, "medium"),
                url=url[:500],
                cwe_id=cwe_id[:20],
                instance_count=len(instances),
            ))
    return out


def run_zap_baseline(
    *,
    db: Database | Path | str,
    engagement_id: str,
    approval_id: str,
    target_hostname: str,
    port: int,
    scheme: str,
    engagements_root: Path,
    actor: str = "operator",
    timeout_seconds: int = 600,
) -> ZapRunResult:
    """Run ZAP baseline scan against an approved target."""
    db_obj, owns = coerce_db(db)
    run_id = uuid.uuid4().hex[:16]
    run_dir = Path(f"/tmp/sentinel-zap-{run_id}")
    report_xml = run_dir / "report.xml"
    report_html = run_dir / "report.html"
    try:
        approval = ApprovalStore(db_obj).get(approval_id)
        if approval is None:
            raise ZapAdapterError(f"approval {approval_id!r} not found")
        if approval.revoked_at_utc:
            raise ZapAdapterError(f"approval {approval_id!r} revoked")

        manifest = ManifestStore(db_obj).get_by_tool_version(
            ZAP_TOOL_NAME, ZAP_VERSION,
        )
        if manifest is None:
            raise ZapAdapterError(
                f"no manifest for zap {ZAP_VERSION} — register first"
            )
        if not manifest.manifest.network_access:
            raise ZapAdapterError("zap manifest must be network_access=True")

        run_dir.mkdir(parents=True, exist_ok=True)
        prepare_sandbox_dir(run_dir)

        target_url = f"{scheme}://{target_hostname}:{port}"
        scan_minutes = max(2, min(10, timeout_seconds // 60))

        params = {
            "target_url": target_url,
            "report_xml_path": str(report_xml),
            "report_html_path": str(report_html),
            "scan_timeout_minutes": scan_minutes,
            "spider_minutes": 1,
        }
        argv = build_argv_for_profile(
            profile_name="zap/baseline_scan",
            executable_path=manifest.manifest.executable_path,
            params=params,
        )

        request = SandboxRequest(
            hostname=target_hostname, port=port, protocol=scheme,
            method="GET", path="/",
            argv=argv,
            timeout_seconds=timeout_seconds,
            additional_ports=(),
            provider_endpoints=(),
            requires_target_connection=True,
            estimated_requests=100,
            estimated_output_bytes=5000000,
            operation_profile="zap/baseline_scan",
            profile_params=params,
            env_overrides={
                "HOME": str(run_dir),
                "JAVA_HOME": ZAP_JAVA_HOME,
            },
            cwd=str(run_dir),
        )

        result = run_in_sandbox(
            db=db_obj,
            engagement_id=engagement_id,
            approval_id=approval_id,
            adapter_name=ZAP_TOOL_NAME,
            adapter_version=ZAP_VERSION,
            request=request,
            engagements_root=engagements_root,
            adapter_code_path=Path(__file__),
            actor=actor,
        )

        report_text = ""
        if report_xml.is_file():
            try:
                report_text = report_xml.read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                report_text = ""

        findings = parse_report(report_text)

        evidence = ingest_evidence(
            db_obj, engagements_root=engagements_root,
            engagement_id=engagement_id,
            source_name=f"zap_{target_hostname}_{port}.xml",
            content_type="application/xml",
            content=(report_text or "<?xml version='1.0'?><no-report/>").encode("utf-8"),
            actor=actor,
            truncated_output=result.truncated_stdout or result.truncated_stderr,
            execution_status=result.execution_status,
            stdout_bytes=result.stdout_bytes, stderr_bytes=result.stderr_bytes,
            output_limit_bytes=result.output_limit_bytes,
            stdout_truncated=result.truncated_stdout,
            stderr_truncated=result.truncated_stderr,
            timed_out=result.timed_out,
            terminated=result.terminated,
            process_exit_code=result.exit_code,
        )

        AuditStore(db_obj).append(
            engagement_id=engagement_id, actor=actor,
            event_type="zap_run",
            decision="ok" if result.exit_code in (0, 1) else "error",
            details={
                "manifest_id": manifest.id,
                "manifest_hash": manifest.manifest_hash,
                "target": target_url,
                "findings_count": len(findings),
                "process_exit_code": result.exit_code,
                "report_bytes": len(report_text.encode("utf-8")),
                "evidence_id": evidence.evidence_id,
            },
        )

        return ZapRunResult(
            findings=findings,
            findings_count=len(findings),
            evidence=evidence,
            process_exit_code=result.exit_code,
            execution_status=result.execution_status,
            timed_out=False,
            report_bytes=len(report_text.encode("utf-8")),
        )
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
        if owns:
            db_obj.close()
