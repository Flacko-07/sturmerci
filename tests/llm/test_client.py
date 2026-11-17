# SPDX-License-Identifier: Apache-2.0
"""LLM client tests. No model required — ollama.chat is mocked."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Literal

import pytest
from pydantic import BaseModel, ConfigDict

from sentinel.llm import client as client_mod
from sentinel.llm.client import (
    call_structured,
    LLMError,
    LLMSecretDetected,
    LLMConfigError,
    LLMCircuitOpen,
    _reset_circuit_for_tests,
)
from sentinel.llm.prompts import TRIAGE_V1
from sentinel.storage.db import Database


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    task_type: Literal["finding_triage"]
    summary: str


VALID_JSON = '{"task_type":"finding_triage","summary":"test"}'
INVALID_JSON = '{"task_type":"wrong","summary":"x"}'


@pytest.fixture(autouse=True)
def _clean_env_and_circuit(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    _reset_circuit_for_tests()
    yield
    _reset_circuit_for_tests()


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "sentinel.sqlite3")
    yield d
    d.close()


def _fake_response(content: str):
    return SimpleNamespace(message=SimpleNamespace(content=content))


def test_loopback_default_ok(monkeypatch, db):
    monkeypatch.setattr(
        client_mod,
        "_ollama_chat",
        lambda **kw: _fake_response(VALID_JSON),
    )
    obj, rec = call_structured(
        db=db,
        engagement_id="eng1",
        prompt=TRIAGE_V1,
        user_content="nothing secret",
        schema=_Out,
        schema_version="Out/v1",
    )
    assert obj.task_type == "finding_triage"
    assert rec.outcome == "ok"


@pytest.mark.parametrize(
    "bad_host",
    [
        "0.0.0.0:11434",
        "192.168.1.5:11434",
        "http://0.0.0.0:11434",
        "http://example.com:11434",
        # M8-P0-B: prefix-matching bypass cases
        "127.0.0.1.attacker.invalid:11434",
        "http://127.0.0.1.attacker.invalid:11434",
        "127.0.0.2.nip.io:11434",
    ],
)
def test_loopback_nonlocal_rejected(monkeypatch, db, bad_host):
    monkeypatch.setenv("OLLAMA_HOST", bad_host)
    with pytest.raises(LLMConfigError, match="not loopback"):
        call_structured(
            db=db,
            engagement_id="eng1",
            prompt=TRIAGE_V1,
            user_content="x",
            schema=_Out,
            schema_version="Out/v1",
        )


@pytest.mark.parametrize(
    "good_host",
    [
        "127.0.0.1:11434",
        "localhost:11434",
        "http://127.0.0.1:11434",
    ],
)
def test_loopback_localhost_ok(monkeypatch, db, good_host):
    monkeypatch.setenv("OLLAMA_HOST", good_host)
    monkeypatch.setattr(
        client_mod,
        "_ollama_chat",
        lambda **kw: _fake_response(VALID_JSON),
    )
    obj, _ = call_structured(
        db=db,
        engagement_id="eng1",
        prompt=TRIAGE_V1,
        user_content="x",
        schema=_Out,
        schema_version="Out/v1",
    )
    assert obj.task_type == "finding_triage"


def test_oversize_content_rejected(db):
    big = "a" * (32 * 1024 + 1)
    with pytest.raises(LLMError, match="MAX_USER_CONTENT_CHARS"):
        call_structured(
            db=db,
            engagement_id="eng1",
            prompt=TRIAGE_V1,
            user_content=big,
            schema=_Out,
            schema_version="Out/v1",
        )


def test_secret_in_content_rejected(monkeypatch, db):
    """I3: if the redaction safety net fires, the call is refused.

    In normal operation redact() catches known-secret shapes first, so
    this path only fires if redact is bypassed or has a regression. We
    mock assert_no_known_secrets to raise, which is exactly what the
    client's defense-in-depth check does.
    """

    def _raise(_s):
        raise RuntimeError("known-secret shape found")

    monkeypatch.setattr(client_mod, "assert_no_known_secrets", _raise)
    with pytest.raises(LLMSecretDetected, match="known-secret"):
        call_structured(
            db=db,
            engagement_id="eng1",
            prompt=TRIAGE_V1,
            user_content="anything, the mock intercepts",
            schema=_Out,
            schema_version="Out/v1",
        )


def test_happy_path_writes_model_run(monkeypatch, db):
    monkeypatch.setattr(
        client_mod,
        "_ollama_chat",
        lambda **kw: _fake_response(VALID_JSON),
    )
    _, rec = call_structured(
        db=db,
        engagement_id="eng1",
        prompt=TRIAGE_V1,
        user_content="plain evidence",
        schema=_Out,
        schema_version="Out/v1",
    )
    row = db.connection.execute(
        "SELECT model_id, outcome, retry_count, prompt_template_hash "
        "FROM model_runs WHERE run_id = ?",
        (rec.run_id,),
    ).fetchone()
    assert row is not None
    assert row["model_id"] == "qwen3:1.7b"
    assert row["outcome"] == "ok"
    assert row["retry_count"] == 0
    assert row["prompt_template_hash"] == TRIAGE_V1.hash


def test_retry_on_invalid_then_success(monkeypatch, db):
    calls = {"n": 0}

    def _fake(**kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return _fake_response(INVALID_JSON)
        return _fake_response(VALID_JSON)

    monkeypatch.setattr(client_mod, "_ollama_chat", _fake)
    monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)

    obj, rec = call_structured(
        db=db,
        engagement_id="eng1",
        prompt=TRIAGE_V1,
        user_content="x",
        schema=_Out,
        schema_version="Out/v1",
    )
    assert obj.task_type == "finding_triage"
    assert rec.retry_count == 1

    rows = db.connection.execute(
        "SELECT outcome, retry_count FROM model_runs ORDER BY retry_count"
    ).fetchall()
    outcomes = [r["outcome"] for r in rows]
    assert outcomes == ["schema_invalid", "ok"]


def test_retry_exhausted_raises(monkeypatch, db):
    monkeypatch.setattr(
        client_mod,
        "_ollama_chat",
        lambda **kw: _fake_response(INVALID_JSON),
    )
    monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)

    with pytest.raises(LLMError, match="schema validation failed"):
        call_structured(
            db=db,
            engagement_id="eng1",
            prompt=TRIAGE_V1,
            user_content="x",
            schema=_Out,
            schema_version="Out/v1",
            max_retries=2,
        )
    rows = db.connection.execute("SELECT outcome FROM model_runs").fetchall()
    assert [r["outcome"] for r in rows] == [
        "schema_invalid",
        "schema_invalid",
        "schema_invalid",
    ]


def test_circuit_opens_after_threshold(monkeypatch, db):
    monkeypatch.setattr(
        client_mod,
        "_ollama_chat",
        lambda **kw: (_ for _ in ()).throw(RuntimeError("conn refused")),
    )
    monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)

    # 2 calls * 3 attempts each = 6 failures, exceeds threshold (5)
    for _ in range(2):
        with pytest.raises(LLMError):
            call_structured(
                db=db,
                engagement_id="eng1",
                prompt=TRIAGE_V1,
                user_content="x",
                schema=_Out,
                schema_version="Out/v1",
            )

    # Third call refused at breaker before any model call
    with pytest.raises(LLMCircuitOpen):
        call_structured(
            db=db,
            engagement_id="eng1",
            prompt=TRIAGE_V1,
            user_content="x",
            schema=_Out,
            schema_version="Out/v1",
        )


# --- M8-5: timeout enforced ---


def test_m8p05_timeout_raises_llmerror(monkeypatch, db):
    """HTTP transport timeouts become explicit timeout model-run rows."""
    import httpx

    monkeypatch.setattr(
        client_mod,
        "_ollama_chat",
        lambda **kw: (_ for _ in ()).throw(httpx.ReadTimeout("timed out")),
    )
    with pytest.raises(LLMError, match="timed out"):
        call_structured(
            db=db,
            engagement_id="eng1",
            prompt=TRIAGE_V1,
            user_content="x",
            schema=_Out,
            schema_version="Out/v1",
            timeout_seconds=0.5,
            max_retries=0,
        )
    row = db.connection.execute(
        "SELECT outcome, settings_json FROM model_runs"
    ).fetchone()
    assert row["outcome"] == "timeout"
    assert '"timeout_seconds": 0.5' in row["settings_json"]


# --- M8-6: context budget ---


def test_m8p06_oversize_prompt_rejected(monkeypatch, db):
    """Prompt exceeding 90% of num_ctx is refused before the call.

    Note: content must be > 14744 chars (90% of 4096 tokens at 4 bytes/
    token) but < 32768 chars (MAX_USER_CONTENT_CHARS, which would fire
    first with a different error). 20000 chars hits the target window.
    """
    big = " ".join(f"w{i}" for i in range(3500))  # ~20KB
    assert 14_744 < len(big) < 32_768, f"test content size {len(big)} out of window"
    monkeypatch.setattr(
        client_mod,
        "_ollama_chat",
        lambda **kw: (_ for _ in ()).throw(AssertionError("should not reach model")),
    )
    with pytest.raises(LLMError, match="exceeds 90% of num_ctx"):
        call_structured(
            db=db,
            engagement_id="eng1",
            prompt=TRIAGE_V1,
            user_content=big,
            schema=_Out,
            schema_version="Out/v1",
            num_ctx=4096,
            max_retries=0,
        )


def test_m8p06_normal_size_prompt_ok(monkeypatch, db):
    """Sanity: a normal prompt does not trigger the budget refusal."""
    monkeypatch.setattr(
        client_mod,
        "_ollama_chat",
        lambda **kw: _fake_response(VALID_JSON),
    )
    obj, _ = call_structured(
        db=db,
        engagement_id="eng1",
        prompt=TRIAGE_V1,
        user_content="short evidence",
        schema=_Out,
        schema_version="Out/v1",
        num_ctx=4096,
    )
    assert obj.task_type == "finding_triage"
