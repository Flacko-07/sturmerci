# M8.1 — LLM client foundation

**Status:** Implementing
**Date:** 2026-11-14
**Milestone:** M8.1
**Scope:** Single wrapper for structured calls to the local Ollama model.

## 1. What M8.1 delivers

`sentinel.llm.client.call_structured(...)` — the only sanctioned way to
call the LLM from application code. Enforces four invariants per call:
versioned prompt, mandatory model_runs audit, secret-scan before prompt,
loopback-only endpoint. Retries on schema errors. Circuit breaker on
repeated failures.

Not in M8.1: knowledge base (M8.2), triage pipeline (M8.3), prompt
content for OWASP/CWE mapping (M8.3).

## 2. The four invariants

**I1. Versioned prompts.** Every call takes a `PromptTemplate` with
name + version + template text. SHA-256 of `name|version|template` is
recorded as `model_runs.prompt_template_hash`. Editing the prompt
produces a different hash; audit distinguishes outputs before and after
the edit.

**I2. Mandatory model_runs.** Every attempt writes a `ModelRunRecord`.
Retries write one record per attempt. Success writes `outcome="ok"`;
validation failures write `outcome="schema_invalid"`; transport errors
write `outcome="error"`. A call without a model_run is a bug.

**I3. Secret-scan before prompt.** Every `user_content` string is passed
through `redact()` and `assert_no_known_secrets()` before assembly into
the prompt. If a known-secret shape survives redaction, the call is
refused with `LLMSecretDetected`. Prevents Gate 4 from being bypassed.

**I4. Loopback-only endpoint.** If `OLLAMA_HOST` is set to a non-loopback
value, the call is refused before any prompt is assembled. Sentinel's
threat model (ECR 2.2, 3.5) assumes local-only inference.

## 3. Circuit breaker

In-memory, per-process. After 5 failures in a sliding 10-minute window,
the breaker opens for 10 minutes. While open:
- `call_structured()` raises `LLMCircuitOpen` immediately (no model call)
- Model_runs records nothing (call never reached the model)
- Operator resets by restarting the process

## 4. Retry policy

Up to `max_retries` retries (default 2, so 3 attempts total). Retry on:
- Pydantic validation error (model emitted malformed JSON)
- Any exception from `ollama.chat()` (transport)

Do not retry on:
- `LLMSecretDetected`, `LLMConfigError`, `LLMCircuitOpen`

Between attempts: 1 second sleep. After final failure: raise `LLMError`.

## 5. Context budget

Context window: 4096 tokens (measured M0). Client refuses
`user_content` > 32 KiB as a sanity bound.

## 6. Public interface

    def call_structured(
        *,
        db: Database | Path | str,
        engagement_id: str,
        prompt: PromptTemplate,
        user_content: str,
        schema: type[T],
        schema_version: str,
        model: str = "qwen3:1.7b",
        num_ctx: int = 4096,
        temperature: float = 0.0,
        max_retries: int = 2,
        timeout_seconds: float = 180.0,
    ) -> tuple[T, ModelRunRecord]

Returns `(validated_object, final_run_record)`. Raises:
- `LLMSecretDetected` — known-secret shape in user_content post-redaction
- `LLMConfigError` — OLLAMA_HOST non-loopback
- `LLMCircuitOpen` — breaker is open
- `LLMError` — all retries exhausted

## 7. Not in M8.1

- Knowledge retrieval (M8.2)
- Triage pipeline (M8.3)
- Prompt content for specific OWASP/CWE mappings (M8.3)
- Cross-process circuit breaker (M9+)

## 8. Request timeout and concurrency

The current client performs Ollama requests synchronously through the
Ollama HTTP client with a real request timeout. It does not detach worker
threads. A bounded in-process semaphore limits concurrent calls and is
released in a `finally` path. Timeout and concurrency-limit outcomes are
recorded in `model_runs`. This does not terminate a wedged Ollama server,
enforce approval model-token budgets, or coordinate concurrency between
multiple Sentinel processes. These behaviors still require deployment
validation.

## 9. What the model cannot do

The FindingTriageOutput schema has no writable `severity`,
`validation_status`, `scope_allowed`, `approved`, `execute_command`,
`confirmed_vulnerability`, `target`, `resolved_ip`, `budget_override`,
`submit_report` field. The schema is the real defense; the secret scan
and "treat as data" instructions are defense-in-depth.
