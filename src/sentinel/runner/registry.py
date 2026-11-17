# SPDX-License-Identifier: Apache-2.0
"""In-process adapter capability metadata.

The persistent tool manifest is authoritative for executable identity,
integrity, and execution policy. This registry is descriptive only; it does
not authorize or launch an adapter.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AdapterManifest:
    name: str
    execution_class: int  # 0..3; see ECR §5.2
    network_access: bool
    enabled: bool = True


_REGISTRY: dict[str, AdapterManifest] = {}


def register(m: AdapterManifest) -> None:
    """Record descriptive metadata; execution still requires a DB manifest."""
    if not m.name:
        raise ValueError("adapter name must not be empty")
    if m.execution_class not in (0, 1, 2, 3):
        raise ValueError(f"unsupported execution class: {m.execution_class!r}")
    _REGISTRY[m.name] = m


def all_adapters() -> list[AdapterManifest]:
    return list(_REGISTRY.values())


def network_capable() -> list[AdapterManifest]:
    return [m for m in _REGISTRY.values() if m.network_access or m.execution_class >= 2]
