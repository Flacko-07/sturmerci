# SPDX-License-Identifier: Apache-2.0
"""Gate 3: model call ledger (G3-T08)."""
import pytest

from sentinel.audit.model_runs import ModelRunStore


def _call_kwargs(**overrides):
    base = dict(
        engagement_id="eng1",
        model_id="qwen3:4b",
        prompt_template_hash="pt_" + "a" * 16,
        sanitized_input_hash="si_" + "b" * 16,
        schema_version="FindingTriageOutput/v1",
        settings={"temperature": 0, "num_ctx": 4096},
        duration_sec=1.23,
        outcome="ok",
    )
    base.update(overrides)
    return base


def test_record_writes_row(tmp_path):
    s = ModelRunStore(tmp_path / "m.db")
    rec = s.record(**_call_kwargs())
    rows = s.all()
    assert len(rows) == 1
    assert rows[0]["model_id"] == "qwen3:4b"
    assert rows[0]["outcome"] == "ok"
    assert rec.duration_sec == 1.23
    s.close()


def test_outcome_constrained(tmp_path):
    s = ModelRunStore(tmp_path / "m.db")
    with pytest.raises(ValueError):
        s.record(**_call_kwargs(outcome="whatever"))
    s.close()


def test_hashes_required(tmp_path):
    s = ModelRunStore(tmp_path / "m.db")
    with pytest.raises(ValueError):
        s.record(**_call_kwargs(prompt_template_hash=""))
    with pytest.raises(ValueError):
        s.record(**_call_kwargs(sanitized_input_hash=""))
    s.close()


def test_dropped_references_recorded(tmp_path):
    s = ModelRunStore(tmp_path / "m.db")
    s.record(**_call_kwargs(dropped_references=3))
    rows = s.all()
    assert rows[0]["dropped_references"] == 3
    s.close()
