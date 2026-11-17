# SPDX-License-Identifier: Apache-2.0
"""Structured calls to the local Ollama model. See docs/llm-client-design.md.

This module is the only sanctioned path from application code to the
model. Direct `ollama.chat()` calls outside this file are a code-review
reject (same policy as SandboxRunner for network adapters).
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar

from ollama import Client as _OllamaClient
from pydantic import BaseModel, ValidationError

from sentinel.audit.model_runs import ModelRunRecord, ModelRunStore
from sentinel.evidence.redact import assert_no_known_secrets, redact
from sentinel.llm.prompts import PromptTemplate
from sentinel.storage.db import Database, coerce_db


T = TypeVar("T", bound=BaseModel)

DEFAULT_MODEL = "qwen3:1.7b"
DEFAULT_NUM_CTX = 4096
DEFAULT_TEMPERATURE = 0.0

# Bound concurrent HTTP requests to the local model service. The synchronous
# HTTP client's timeout closes the request and releases its slot in finally.
# The cap makes service-side queuing visible and bounded within this process.
_MAX_CONCURRENT_OLLAMA_CALLS = 2
_ollama_slots = __import__("threading").BoundedSemaphore(
    _MAX_CONCURRENT_OLLAMA_CALLS
)


def _ollama_chat(*, timeout: float, **kwargs):
    """Perform chat through an Ollama client with a real HTTP timeout."""
    with _OllamaClient(timeout=timeout) as client:
        return client.chat(**kwargs)
DEFAULT_MAX_RETRIES = 2
DEFAULT_TIMEOUT_SECONDS = 180.0
MAX_USER_CONTENT_CHARS = 32 * 1024

CIRCUIT_FAILURE_THRESHOLD = 5
CIRCUIT_WINDOW_SECONDS = 600.0
CIRCUIT_OPEN_SECONDS = 600.0


class LLMError(Exception):
    """Any LLM call failure after exhausting retries."""


class LLMSecretDetected(LLMError):
    """user_content contains a known-secret shape after redaction."""


class LLMConfigError(LLMError):
    """LLM endpoint not loopback, or misconfiguration."""


class LLMCircuitOpen(LLMError):
    """Too many recent failures; circuit breaker is open."""


@dataclass
class _CircuitState:
    failures: list[float] = field(default_factory=list)
    opened_at: float | None = None


_CIRCUIT = _CircuitState()


def _reset_circuit_for_tests() -> None:
    """Test-only. Not part of the public API."""
    _CIRCUIT.failures.clear()
    _CIRCUIT.opened_at = None


def _is_loopback_hostname(host: str) -> bool:
    """True iff host is a loopback IP literal or the literal string 'localhost'.

    Uses ipaddress module, not string prefix matching: '127.0.0.1.evil.test'
    must be rejected. This is M8-P0-B from the review.
    """
    import ipaddress
    from urllib.parse import urlparse

    raw = host.strip()
    # Normalize to a URL for urlparse to handle bracketed IPv6 / port
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
    except ValueError:
        return False
    netloc = parsed.netloc or parsed.path
    if not netloc:
        return False
    # Extract host part (strip port, brackets)
    if netloc.startswith("["):
        end = netloc.find("]")
        if end < 0:
            return False
        hostpart = netloc[1:end]
    else:
        hostpart = netloc.rsplit(":", 1)[0] if ":" in netloc else netloc

    if hostpart.lower() == "localhost":
        return True

    try:
        return ipaddress.ip_address(hostpart).is_loopback
    except ValueError:
        return False


def _verify_loopback_endpoint() -> None:
    raw = os.environ.get("OLLAMA_HOST", "").strip()
    if not raw:
        return
    for prefix in ("http://", "https://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
            break
    if raw.startswith("["):
        end = raw.find("]")
        host = raw[: end + 1] if end > 0 else raw
    elif ":" in raw:
        host = raw.rsplit(":", 1)[0]
    else:
        host = raw
    if not _is_loopback_hostname(host):
        raise LLMConfigError(
            f"OLLAMA_HOST={raw!r} is not loopback. Sentinel's local-only "
            "inference policy (ECR 2.2, 3.5) refuses to send prompts to a "
            "non-local model endpoint. Unset OLLAMA_HOST to use the default."
        )


def _check_circuit() -> None:
    now = time.monotonic()
    if _CIRCUIT.opened_at is not None:
        if now - _CIRCUIT.opened_at < CIRCUIT_OPEN_SECONDS:
            remaining = int(CIRCUIT_OPEN_SECONDS - (now - _CIRCUIT.opened_at))
            raise LLMCircuitOpen(
                f"circuit breaker open; retry in {remaining}s"
            )
        _CIRCUIT.opened_at = None
        _CIRCUIT.failures.clear()


def _record_success() -> None:
    _CIRCUIT.failures.clear()


def _record_failure() -> None:
    now = time.monotonic()
    _CIRCUIT.failures.append(now)
    _CIRCUIT.failures = [
        t for t in _CIRCUIT.failures if now - t < CIRCUIT_WINDOW_SECONDS
    ]
    if len(_CIRCUIT.failures) >= CIRCUIT_FAILURE_THRESHOLD:
        _CIRCUIT.opened_at = now


def _record_timeout_run(
    *,
    db,
    engagement_id: str,
    model: str,
    prompt_hash: str,
    input_hash: str,
    schema_version: str,
    duration: float,
    reason: str,
    timeout_seconds: float,
    outcome: str = "timeout",
) -> None:
    """Record a timeout/limit outcome in model_runs.

    (v4.1) Prior code raised LLMError without writing a model_run row,
    so timeouts were invisible in the audit trail. Every attempt now
    produces an outcome row: 'ok', 'schema_invalid', 'error', or
    'timeout'. Operators can grep model_runs for outcome='timeout' to
    find Ollama slowness.
    """
    from sentinel.storage.db import coerce_db as _coerce
    try:
        db_obj, owns = _coerce(db)
        try:
            store = ModelRunStore(db_obj)
            import uuid as _uuid
            from datetime import datetime as _dt, timezone as _tz
            store.record(
                engagement_id=engagement_id,
                model_id=model,
                prompt_template_hash=prompt_hash,
                schema_version=schema_version,
                sanitized_input_hash=input_hash,
                settings={"timeout_seconds": timeout_seconds,
                          "outcome_reason": reason},
                duration_sec=duration,
                outcome=outcome,
                retry_count=0,
                dropped_references=0,
            )
        finally:
            if owns:
                db_obj.close()
    except Exception:
        # Best-effort. Never mask the primary exception.
        pass


def call_structured(
    *,
    db: Database | Path | str,
    engagement_id: str,
    prompt: PromptTemplate,
    user_content: str,
    schema: type[T],
    schema_version: str,
    prompt_context: dict[str, str] | None = None,
    model: str = DEFAULT_MODEL,
    num_ctx: int = DEFAULT_NUM_CTX,
    temperature: float = DEFAULT_TEMPERATURE,
    max_retries: int = DEFAULT_MAX_RETRIES,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[T, ModelRunRecord]:
    """Call the local Ollama model with structured output."""
    _verify_loopback_endpoint()

    if len(user_content) > MAX_USER_CONTENT_CHARS:
        raise LLMError(
            f"user_content is {len(user_content)} chars; "
            f"MAX_USER_CONTENT_CHARS is {MAX_USER_CONTENT_CHARS}"
        )

    sanitized, _ = redact(user_content)
    try:
        assert_no_known_secrets(sanitized)
    except RuntimeError as e:
        raise LLMSecretDetected(
            f"user_content contains a known-secret shape post-redaction: {e}"
        ) from e

    input_hash = hashlib.sha256(sanitized.encode("utf-8")).hexdigest()

    # Build the full prompt. prompt_context values are substituted BEFORE
    # user_content so an example snippet containing the literal token
    # "{user_content}" cannot smuggle data past redaction.
    full_prompt = prompt.template
    if prompt_context:
        for key, value in prompt_context.items():
            if not isinstance(value, str):
                raise LLMError(
                    f"prompt_context[{key!r}] must be str, "
                    f"got {type(value).__name__}"
                )
            sanitized_ctx, _ = redact(value)
            try:
                assert_no_known_secrets(sanitized_ctx)
            except RuntimeError as e:
                raise LLMSecretDetected(
                    f"prompt_context[{key!r}] contains a known-secret "
                    f"shape post-redaction: {e}"
                ) from e
            full_prompt = full_prompt.replace(f"{{{key}}}", sanitized_ctx)
    full_prompt = full_prompt.replace("{user_content}", sanitized)

    # M8-6: context budget. Ollama counts tokens; we approximate at
    # 4 bytes per token (conservative -- real tokenizers average 3.5-4.5
    # for English). The whole prompt must fit num_ctx or Ollama will
    # silently truncate the front (system instructions), which is worse
    # than refusing. Reserve 10% headroom for the model's own tokens.
    approx_tokens = len(full_prompt.encode("utf-8")) // 4
    budget = int(num_ctx * 0.9)
    if approx_tokens > budget:
        raise LLMError(
            f"prompt ~{approx_tokens} tokens exceeds 90% of num_ctx "
            f"({budget}); reduce user_content or raise num_ctx"
        )

    _check_circuit()

    db_obj, owns_db = coerce_db(db)
    try:
        run_store = ModelRunStore(db_obj)
        settings = {"temperature": temperature, "num_ctx": num_ctx,
                    "timeout_seconds": timeout_seconds}

        for attempt in range(max_retries + 1):
            start = time.monotonic()
            try:
                _kwargs = dict(
                    model=model,
                    messages=[{"role": "user", "content": full_prompt}],
                    format=schema.model_json_schema(),
                    options={"temperature": temperature, "num_ctx": num_ctx},
                )
                _kwargs["timeout"] = timeout_seconds

                # (v4.1) Acquire a slot BEFORE spawning the worker. If no
                # slot is free, fail fast instead of letting Ollama's
                # internal queue build up invisibly.
                if not _ollama_slots.acquire(blocking=False):
                    _record_timeout_run(
                        db=db, engagement_id=engagement_id,
                        model=model, prompt_hash=prompt.hash,
                        input_hash=input_hash,
                        schema_version=schema_version,
                        duration=0.0,
                        reason="concurrent_call_limit",
                        timeout_seconds=timeout_seconds,
                        outcome="error",
                    )
                    raise LLMError(
                        f"concurrent Ollama call limit reached "
                        f"({_MAX_CONCURRENT_OLLAMA_CALLS}); cannot accept "
                        f"another request until a request slot is available."
                    )

                try:
                    response = _ollama_chat(**_kwargs)
                except Exception as _request_error:
                    import httpx as _httpx
                    if isinstance(_request_error, _httpx.TimeoutException):
                        _record_timeout_run(
                            db=db, engagement_id=engagement_id, model=model,
                            prompt_hash=prompt.hash, input_hash=input_hash,
                            schema_version=schema_version,
                            duration=time.monotonic() - start,
                            reason=type(_request_error).__name__,
                            timeout_seconds=timeout_seconds,
                        )
                        _record_failure()
                        raise LLMError(
                            f"LLM HTTP request timed out after "
                            f"{timeout_seconds}s ({type(_request_error).__name__})"
                        ) from _request_error
                    raise
                finally:
                    # HTTPX timeout closes/cancels the request; no worker
                    # thread or semaphore slot remains detached.
                    _ollama_slots.release()
                raw = getattr(response, "message", None)
                content = getattr(raw, "content", "") if raw else ""
                try:
                    validated = schema.model_validate_json(content or "")
                except (ValidationError, ValueError) as e:
                    duration = time.monotonic() - start
                    run_store.record(
                        engagement_id=engagement_id,
                        model_id=model,
                        prompt_template_hash=prompt.hash,
                        sanitized_input_hash=input_hash,
                        schema_version=schema_version,
                        settings=settings,
                        duration_sec=duration,
                        outcome="schema_invalid",
                        retry_count=attempt,
                    )
                    _record_failure()
                    if attempt < max_retries:
                        time.sleep(1.0)
                        continue
                    raise LLMError(
                        f"schema validation failed after {attempt + 1} "
                        f"attempts: {e}"
                    ) from e

                duration = time.monotonic() - start
                run_record = run_store.record(
                    engagement_id=engagement_id,
                    model_id=model,
                    prompt_template_hash=prompt.hash,
                    sanitized_input_hash=input_hash,
                    schema_version=schema_version,
                    settings=settings,
                    duration_sec=duration,
                    outcome="ok",
                    retry_count=attempt,
                )
                _record_success()
                return validated, run_record
            except LLMError:
                raise
            except Exception as e:
                duration = time.monotonic() - start
                try:
                    run_store.record(
                        engagement_id=engagement_id,
                        model_id=model,
                        prompt_template_hash=prompt.hash,
                        sanitized_input_hash=input_hash,
                        schema_version=schema_version,
                        settings=settings,
                        duration_sec=duration,
                        outcome="error",
                        retry_count=attempt,
                    )
                except Exception:
                    pass
                _record_failure()
                if attempt < max_retries:
                    time.sleep(1.0)
                    continue
                raise LLMError(
                    f"LLM call failed after {attempt + 1} attempts: {e}"
                ) from e
    finally:
        if owns_db:
            db_obj.close()
