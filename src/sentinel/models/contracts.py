# SPDX-License-Identifier: Apache-2.0
"""Strict LLM output contracts. Gate 3.

No field here can authorize scope, set authoritative severity, set finding
lifecycle state, execute commands, or submit a report.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

EvidenceId = Annotated[str, StringConstraints(pattern=r"^ev_[a-f0-9]{16,64}$")]

ReferenceId = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^(CWE-[0-9]{1,5}|"
            r"WSTG-[A-Z0-9][A-Z0-9-]{0,63}|"
            r"API[0-9]{1,2}:20[0-9]{2}|"
            r"MASVS-[A-Z0-9][A-Z0-9-]{0,63}|"
            r"CVE-[0-9]{4}-[0-9]{4,})$"
        )
    ),
]


class FindingTriageOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    task_type: Literal["finding_triage"]
    summary: str
    candidate_category: Literal[
        "access_control",
        "authentication",
        "injection",
        "information_exposure",
        "misconfiguration",
        "dependency",
        "other",
    ]
    possible_references: list[ReferenceId]
    evidence_ids: list[EvidenceId]
    missing_evidence: list[str]
    confidence_hint: Literal["low", "medium", "high"]
    recommended_next_step: str
