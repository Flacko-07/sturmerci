# Sentinel Threat Model

**Version:** v1.2 (v4.3 implementation state, pending independent validation)
**Scope:** Single-operator deployment on one Windows + WSL2/Linux workstation.
**Out of scope:** multi-tenant/cloud deployment, physical access, and compromise of the trusted host/kernel.

## 1. Assets protected

| Asset | Sensitivity |
|---|---|
| Scope, policy snapshots, approvals | High — authorizes active testing |
| Raw evidence | High — may contain target secrets or personal data |
| Sanitized evidence and model output | Medium — still target-derived and potentially hostile |
| Tool binaries, manifests and profiles | High — define executable behavior |
| Knowledge corpus and review history | High — retrieval content can influence triage |
| Audit chain and reference provenance | High — accountability and evidence lineage |
| Credentials | Critical — must not enter scanner env or model prompts |

## 2. Adversaries and controls

### Target service and supplied files

Treat responses, source files, documents, and scanner output as hostile. Controls include bounded process output, per-run network namespaces and egress policy, redaction before model input, strict model schemas, evidence hashes, immutable knowledge review, and read-only staged Class 0 input. Class 0 execution requires bubblewrap with user and network namespace support and fails closed when unavailable.

Residual risk remains for parser/tool vulnerabilities, kernel/namespace defects, and data that passes redaction but contains semantic prompt injection. Local namespace isolation is defense-in-depth, not a VM boundary.

### Local model

The model may hallucinate references or return hostile prose. Reference checks produce verified/unverified/invalid provenance; invalid and malformed entries are retained in provenance even when omitted from candidate output. Model calls are synchronous through an HTTP client timeout, bounded by an in-process semaphore, redacted, and recorded in `model_runs`. The model cannot authorize scope, set lifecycle, launch tools, or submit reports.

Residual risks: prompt injection remains a semantic risk; Ollama server-side process termination is outside the client boundary; token budgets and cross-process concurrency are not enforced; model quality/runtime is deployment-specific.

### Tool binary

Network-capable runs require approved profiles, scope, manifest digest, authorization, namespace policy, audit and budget reservations. Class 0 binaries run with reduced env, UID/GID 65534, read-only staged input and no network namespace. Fail closed if required isolation cannot initialize.

Residual risks include tool or kernel exploits and deployment-specific namespace behavior. Root in the host/WSL environment is trusted and out of scope.

### Operator

The operator can approve incorrectly or modify local state. Approvals bind scope, policy, manifest, adapter and profile. Class 3 requires explicit intrusive/lab authorization and required parameter binding. Audit records actions and denials. Knowledge reviews bind to immutable content hashes.

Reviewer/actor values are labels only; the application has no authenticated multi-user identity. Operator identity assurance remains an open product boundary. The TLS proxy upstream connection is not kernel-isolated; proxy use remains lab-restricted until that separate boundary is implemented and verified.

## 3. Invariants

1. Model output cannot alter scope, approvals, execution, lifecycle, or submission.
2. Raw evidence is never sent to the model; sanitized evidence bytes are hash-checked before triage and report generation.
3. A knowledge document is retrieved only from its current immutable revision with a latest approved review for the same content hash.
4. Network-capable execution is gated by approval, exact profile, manifest/binary verification, current scope and egress boundary.
5. Class 3 requires explicit intrusive and lab authorization plus bound parameters where the profile requires them.
6. Class 0 execution has no unsafe fallback when bubblewrap isolation is absent.
7. Captured process output is bounded, and completion status is retained with evidence, including timeout and truncation.
8. Evidence release and its audit event commit atomically.
9. CVE cache misses remain unverified; transient NVD errors never create invalid records.
10. Privileged egress and deployment-specific behavior remain unverified until operator-controlled tests are recorded.

## 4. Open validation and product limits

- Run privileged egress and adapter integration checks in a controlled lab before relying on network containment.
- Verify bubblewrap and POSIX ACL prerequisites on the deployment host.
- Approval request counts are estimates; byte usage measures captured output, not network traffic.
- Model-token budget enforcement, authenticated actor identities, bulk threat-intelligence sync, PDF rendering, program-policy import/review, and unified operator UI are not implemented.

**Updated:** 2026-11-15. Current implementation validation has not been performed. See `docs/TEST_RESULTS.md`.
