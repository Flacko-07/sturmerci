# SPDX-License-Identifier: Apache-2.0
"""Tool manifest registration and drift detection."""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sentinel.storage.db import Database, coerce_db


@dataclass(frozen=True, slots=True)
class ToolManifest:
    tool_name: str
    version: str
    executable_path: str
    executable_sha256: str
    execution_class: int
    network_access: bool
    allowed_profiles: tuple[str, ...]
    prohibited: tuple[str, ...]
    limits: dict
    output_format: str
    # Endpoints the tool MAY contact as part of its function (e.g.
    # Subfinder contacts crt.sh). Declaring an endpoint here does NOT
    # authorize it for any engagement -- that requires a separate
    # entry in the approval's approved_infrastructure_endpoints list.
    infrastructure_endpoints: tuple[str, ...] = ()
    extra: dict = field(default_factory=dict)

    def compute_hash(self) -> str:
        payload = {
            "tool_name": self.tool_name,
            "version": self.version,
            "executable_path": self.executable_path,
            "executable_sha256": self.executable_sha256,
            "execution_class": self.execution_class,
            "network_access": self.network_access,
            "allowed_profiles": sorted(self.allowed_profiles),
            "prohibited": sorted(self.prohibited),
            "limits": self.limits,
            "output_format": self.output_format,
            "infrastructure_endpoints": sorted(self.infrastructure_endpoints),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class RegisteredManifest:
    id: str
    manifest: ToolManifest
    manifest_hash: str
    registered_by: str
    registered_at_utc: str


class ManifestStore:
    def __init__(self, db: "Database | Path | str"):
        self._db, self._owns_db = coerce_db(db)

    def register(self, manifest: ToolManifest, *, actor: str) -> RegisteredManifest:
        mh = manifest.compute_hash()
        mid = "tm_" + uuid.uuid4().hex[:16]
        now = datetime.now(timezone.utc).isoformat()
        with self._db.transaction() as conn:
            conn.execute(
                """INSERT INTO tool_manifests
                   (id, tool_name, version, executable_path, executable_sha256,
                    execution_class, network_access, allowed_profiles_json,
                    prohibited_json, limits_json, output_format, manifest_hash,
                    registered_by, registered_at_utc,
                    infrastructure_endpoints_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (mid, manifest.tool_name, manifest.version,
                 manifest.executable_path, manifest.executable_sha256,
                 manifest.execution_class, 1 if manifest.network_access else 0,
                 json.dumps(sorted(manifest.allowed_profiles)),
                 json.dumps(sorted(manifest.prohibited)),
                 json.dumps(manifest.limits, sort_keys=True),
                 manifest.output_format, mh, actor, now,
                 json.dumps(sorted(manifest.infrastructure_endpoints))),
            )
        return RegisteredManifest(
            id=mid, manifest=manifest, manifest_hash=mh,
            registered_by=actor, registered_at_utc=now,
        )

    def get(self, manifest_id: str) -> RegisteredManifest | None:
        row = self._db.connection.execute(
            "SELECT * FROM tool_manifests WHERE id = ?", (manifest_id,)
        ).fetchone()
        if row is None:
            return None
        manifest = ToolManifest(
            tool_name=row["tool_name"], version=row["version"],
            executable_path=row["executable_path"],
            executable_sha256=row["executable_sha256"],
            execution_class=row["execution_class"],
            network_access=bool(row["network_access"]),
            allowed_profiles=tuple(json.loads(row["allowed_profiles_json"])),
            prohibited=tuple(json.loads(row["prohibited_json"])),
            limits=json.loads(row["limits_json"]),
            output_format=row["output_format"],
            infrastructure_endpoints=tuple(
                json.loads(row["infrastructure_endpoints_json"])
            ),
        )
        return RegisteredManifest(
            id=row["id"], manifest=manifest, manifest_hash=row["manifest_hash"],
            registered_by=row["registered_by"],
            registered_at_utc=row["registered_at_utc"],
        )

    def get_by_tool_version(self, tool_name: str, version: str) -> RegisteredManifest | None:
        row = self._db.connection.execute(
            "SELECT id FROM tool_manifests WHERE tool_name = ? AND version = ?",
            (tool_name, version),
        ).fetchone()
        return self.get(row["id"]) if row else None

    def verify(self, manifest_id: str) -> tuple[bool, str]:
        reg = self.get(manifest_id)
        if reg is None:
            return False, "manifest not found"
        recomputed = reg.manifest.compute_hash()
        if recomputed != reg.manifest_hash:
            return False, f"manifest drift: stored {reg.manifest_hash[:12]}… recomputed {recomputed[:12]}…"
        return True, "ok"

    def close(self) -> None:
        if getattr(self, "_owns_db", False):
            self._db.close()
