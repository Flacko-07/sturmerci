# Sentinel v1.0.1 — Historical Operator Notes

> This guide contains dated milestone notes and test totals from earlier
> source snapshots. They are historical records, not validation of the
> current v4.3 implementation. Current v4.3 suite results are recorded in
> `docs/TEST_RESULTS.md`; live NVD/Ollama, real-scanner, and end-to-end
> workflows remain unvalidated. The Gate 1–6 and milestone sections below
> are historical notes and may describe superseded behavior. For current use,
> start with `docs/OPERATOR_GUIDE.md` and verify options with `sentinel --help`.

## Gate 1 — parser + canonicalizer (2026-11-13)
- Parser: ada-url 4.0.0 (WHATWG / UTS #46). Preserves trailing dots — correct.
- Canonicalizer strips trailing dots, restricts schemes to http/https/ws/wss,
  strips default ports, rejects control chars.
- `is_safe_wildcard` rejects only domains that ARE public suffixes
  (`*.com`, `*.co.uk`); accepts `*.example.com`, `*.api.example.com`.
- `publicsuffixlist` API: `publicsuffix(domain)` — no `keep_leading_dot` kwarg.

## Gate 2 — approval TTL (2026-11-13)
- `calculate_approval_ttl` raises on short windows, floor 900 s, ceiling 3600 s.

## Gate 3 — model contract (2026-11-13)
- `FindingTriageOutput` uses extra="forbid", strict=True, frozen=True.
- No severity / validation_status / scope_allowed / approved / execute_command /
  submit_report fields.
- evidence_ids: `^ev_[a-f0-9]{16,64}$`
- possible_references: CWE / OWASP pattern

## Gate 4 — redaction (2026-11-13)
- `sentinel.evidence.redact.redact(text) -> (sanitized, RedactionRecord)`
- Rules: aws_access_key, github_token, generic_bearer, private_key_block,
  cookie_header, set_cookie_header, auth_header, email, jwt.
- Unknown-format defense: any long unbroken token (>= 40 chars, alnum+/=_-)
  that survived known rules is replaced and `unknown_format_triggered=True`
  is set. Caller must route such artifacts to human review before prompt
  assembly.
- `assert_no_known_secrets(sanitized)` is the final barrier before the model.

## Historical Gate 6 — no live network in v1.0.1 (2026-11-13)
- This was a milestone-era restriction and is not the current production
  registration mechanism. The runtime no longer checks a marker under
  `tests/`; the persistent tool manifest is authoritative for tool identity
  and integrity, with approval, scope, and sandbox controls governing runs.
- Socket test (`test_no_external_sockets_open`) asserts no ESTABLISHED or
  SYN_SENT sockets outside loopback during the run.
- `httpx` 0.28.1 is a transitive dependency of `ollama`; used only for
  localhost:11434. Any direct call to httpx against non-loopback violates
  Gate 6 and must be flagged in code review.

## Milestone 0 — model benchmark (historical result)
- Date: 2026-11-13 (historical baseline)
- ollama version: 0.40.3
- GPU: RTX 3050 Laptop, 4096 MiB, idle 175 MiB
- ctx: 4096, temperature: 0, think: false
- schema-valid: 20 / 20
- peak VRAM: 2519 MiB
- median latency: 4.3 s
- placement (ollama ps): 20% CPU / 80% GPU
- decision: default model = qwen3:4b ; context = 4096

## §16 release rule reminder
- No httpx adapter, Nmap, Nuclei, or ZAP until Gates 1–6 pass AND the v1.1
  egress design is separately reviewed.
- Installing a library is not the same as enabling a capability.

## v1.0.1 completion — Gate 2 additions (2026-11-13)
- `sentinel.approval.store.ApprovalStore`: SQLite table, issue/get/revoke.
  Approval binds policy, scope-lock, target-set, tool/adapter/manifest,
  egress profile, ports, protocols, methods, path profile, budgets.
- `sentinel.approval.gatekeeper.check_request`: per-request revalidation of
  every field above plus expiry and revocation. Reason string returned on
  every denial for audit.
- `sentinel.assets.store.AssetStore`: separate `candidate_assets` and
  `approved_assets` tables. Promotion changes `target_asset_ids_hash`.
- Tests: test_gate2_approvals.py (14), test_gate2_assets.py (3).

## v1.0.1 completion — Gate 3 additions (2026-11-13)
- `sentinel.knowledge.refs`: local KB (CWE/OWASP/API/MASVS), structural +
  existence validation. Unresolved references dropped; count logged to
  model_runs.
- `sentinel.audit.model_runs.ModelRunStore`: per-call ledger with model_id,
  digests, prompt/input hashes, schema_version, settings, tokens, duration,
  outcome, retry_count, dropped_references.
- `contracts.ReferenceId` aligned to v1.0.2 pattern.
- Tests: test_gate3_refs.py (8), test_gate3_model_runs.py (4).

## Milestone 0 — measured baseline (2026-11-13)
- schema-valid: 20/20
- peak VRAM: 2519 MiB / 4096
- median latency: 4.3 s
- ollama ps placement: 20% CPU / 80% GPU
- decision (model + context): qwen3:4b, 4096 tokens

### Tuning attempt — outcome (2026-11-13)
- Config: OLLAMA_FLASH_ATTENTION=1, OLLAMA_KV_CACHE_TYPE=q8_0
- schema-valid: 20 / 20 (unchanged)
- median latency: ~4.3 s (was ~5.5 s) — 22% improvement
- peak VRAM: 2519 MiB / 4096 MiB (unchanged)
- RAM used: 2.72 GB / 11.68 GB (was 2.85 GB)
- placement: 20% / 80% CPU/GPU (was 27% / 73%)
- model footprint: 2.9 GB (was 3.2 GB)
- cold load call 01: 24.6 s (was 66.1 s; second run benefited from page cache)

### Decision
- ADOPT tuned config as the default. Update `/etc/systemd/system/ollama.service.d/override.conf`.
- DO NOT force 100% GPU via num_gpu=99 or OLLAMA_GPU_OVERHEAD=0. Rationale:
  the benchmark's 3-field output leaves the KV cache nearly empty; realistic
  Sentinel evidence prompts (2-3k tokens) will fill it. A config that barely
  reaches 100% GPU at empty KV cache will OOM at realistic fill.
  The 20/80 split has 1.5 GB VRAM headroom, which is the safe point.
- DO NOT downgrade to qwen3:1.7b. Schema-valid 100% at 4.3 s satisfies Gate 3.
- Milestone 0 CLOSED.

### Ollama config to persist (in /etc/systemd/system/ollama.service.d/override.conf)
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_KEEP_ALIVE=5m"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"

## Milestone 2A — CLOSED (2026-11-13)
- Consolidated SQLite at data/sentinel.sqlite3 (WAL, FKs on, migrations).
- Migration 0001_initial.sql applied, schema_migrations tracks versions.
- EngagementStore lifecycle: draft → scope_review → active|paused|closed.
- Per-engagement directories at engagements/{eng_id}/ with mode 0700.
- Evidence pipeline: size cap 25 MB, UTF-8 + content-type allowlist,
  redaction before persistence, unknown-format → held_for_review,
  atomic file write, audit event, cleanup on failure.
- Cross-engagement evidence reference rejected by assert_in_engagement().
- Operational log table separate from audit_events; both redacted.
- ManifestStore: hash-pinned manifests; verify() detects DB-side drift.
- Refactored stores (audit, approval, assets, model_runs) accept
  Database | Path | str; backward-compatible with existing tests.
- All tests green.

## Milestone 2A — post-migration fixes applied
- FK constraints on approvals/candidate_assets/approved_assets caught 18
  test fixtures inserting synthetic engagement_id="eng1" with no parent row.
- Fix: autouse `_seed_engagement` fixture in test_gate2_approvals.py and
  test_gate2_assets.py seeds eng1 into the same tmp_path DB.
- store._conn → store._db.connection in test_gate5.py tamper tests after
  the store refactor.
- Schema unchanged; tests were wrong, not the schema.

## Next: Milestone 2B — Gitleaks
- Install pinned binary, verify SHA-256 against upstream release page.
- Register via ManifestStore.register() (execution_class=0,
  network_access=False).
- Manual run against tests/fixtures/gitleaks_repo with --redact.
- Verify fake keys absent from JSON output.
- Capture JSON schema in docs/gitleaks-schema-<version>.md.
- Write adapter; test end-to-end via ingest_evidence().
- Gitleaks was initially integrated through the in-memory registry. The
  current adapter relies on the persistent manifest and its class/network
  checks; the in-memory registry is descriptive only.

## Milestone 2A — application foundation (2026-11-13)
- Consolidated SQLite at data/sentinel.sqlite3 (Database class, WAL, FKs, migrations).
- Migration 0001_initial.sql holds all tables; schema_migrations tracks versions.
- EngagementStore: lifecycle draft -> scope_review -> active|paused|closed.
- Per-engagement dirs under engagements/{eng_id}/{artifacts,artifacts_raw,findings,reports,logs}, mode 0700.
- Evidence ingestion pipeline: size cap 25 MB, UTF-8 content-type allowlist,
  redact() before persistence, unknown-format -> held_for_review, atomic write,
  audit event on success, cleanup on failure.
- assert_in_engagement() rejects cross-engagement evidence IDs.
- OpsLogger: separate table, redact + final barrier, never creates audit events.
- ManifestStore: hash-pinned tool manifests, verify() detects DB drift.
- 102 tests green.

## Milestone 2B — Gitleaks installation (2026-11-13)
- Version: 8.30.1
- Source: https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1
- Binary: tools/gitleaks (chmod +x applied)
- SHA-256 of gitleaks_8.30.1_linux_x64.tar.gz verified against
  gitleaks_8.30.1_checksums.txt from the same release page before extraction.
- Registered via ManifestStore.register() as execution_class=0,
  network_access=False. This is the first adapter to enter tool_manifests.
- Manifest hash, ID, and verify() result recorded from registration output.
- Historical milestone note; the current Gitleaks adapter is implemented and
  manifest-gated. The registry no longer depends on test files.

## Corrected test count (2026-11-13)
- Milestone 2A closed at 102 tests, not "~100".
- Breakdown: Gates 1–6 (76) + Milestone 2A additions (26).

## Milestone 2B - Gitleaks manual run (2026-11-13)
- First fixture attempt (AKIAIOSFODNN7EXAMPLE, wJalrXUtnFEMI/..., ghp_000...,
  postgres://admin:hunter2@...) produced 0 findings. All four values are in
  Gitleaks' documentation-example allowlist. Tool behaved correctly (refused
  to false-positive); the fixture was wrong.
- Corrected fixture uses a PEM private-key block, non-example AWS access key
  (AKIAQ3EGVZ7J4M2KPL5N), non-zero GitHub PAT (ghp_9fK2mN8...), and a
  synthetic JWT.
- Diagnostic run (no --redact): findings=5 across rules private-key,
  generic-api-key (x2), aws-access-token, github-pat.
- With --redact: all four fake secret strings return 0 grep matches in
  /tmp/gitleaks_output.json. REDACTED marker count=10. Both `Match` and
  `Secret` fields are replaced with the literal `REDACTED`.
- JSON schema captured at docs/gitleaks-schema-8.30.1.md.
- Ready for adapter.

## Milestone 2B - CLOSED (2026-11-13)
- 128 policy tests green. Breakdown:
  - Milestone 2A baseline: 102
  - Gitleaks parser unit tests (test_gitleaks_parser.py): 14
  - Gitleaks adapter integration (test_gitleaks_adapter.py): 7
  - Redaction-suffix rule (test_redact_suffix.py): 5
- Zero failures, zero skips.

## Gate 4 behavior — redaction output form (2026-11-13)
- All redaction rules replace matches with the placeholder
  `[REDACTED:<rule_id>]` — never the literal string `REDACTED`.
  Example: `AKIAIOSFODNN7EXAMPLE` -> `[REDACTED:aws_access_key]`.
- This is deliberate: the placeholder lets the audit trail reconstruct
  WHICH rule fired without preserving WHAT it matched. It also means
  `assert_no_known_secrets()` has a single uniform marker to look for.
- Test assertions must verify the security property
  ("no fragment of the secret survives") rather than a specific string.
  test_redact_suffix.py asserts `kP4 not in out`, not `out == "...REDACTED..."`.

## Milestone 2B — evidence of what was verified
- Gitleaks 8.30.1 tarball SHA-256 verified against upstream checksums.txt.
- Binary SHA-256 pinned in tool_manifests; class 0, network_access=False.
- Manual scan (no --redact): 5 findings across private-key, generic-api-key (x2),
  aws-access-token, github-pat.
- Manual scan (--redact): Secret == "REDACTED" exactly; Match retains context
  and sometimes preserves last 4 chars of the secret as a fingerprint.
- Adapter refuses any finding whose Secret is not exactly "REDACTED".
- Adapter accepts any Match containing "REDACTED"; the pipeline's
  redacted_suffix rule strips the suffix before persistence.
- Six adapter preconditions are checked before subprocess launch:
  engagement active, manifest registered,
  manifest class 0 / no network, ManifestStore.verify() ok,
  on-disk binary SHA-256 matches manifest, source directory exists.
- Audit event "gitleaks_run" written on every scan.
- Historical Gate 6 note; current runtime capability is defined by the
  persistent manifest and sandbox/approval path, not this test registry.

## What stays off-limits (v1.0.1 release rule)
- No httpx adapter, Nmap, Nuclei, or ZAP registered or installed.
- Adding one requires Gates 1-6 to pass AND the v1.1 egress design
  reviewed (Milestone 3).

## Milestone 2B - path containment hardening (2026-11-13)
- Source-path step in run_gitleaks() previously used
  (engagements_root / engagement_id / scan_subdir).resolve() and only
  checked exists()/is_dir(). A scan_subdir of "../..." or "/etc" or a
  symlink pointing outside the engagement would pass those checks.
- Fix: resolve engagement_root first, then compare with
  source.is_relative_to(engagement_root). One check covers traversal,
  absolute path, and symlink escape, because .resolve() collapses
  symlinks and dot-segments before the comparison.
- Four new tests in test_gitleaks_adapter.py:
  - test_refuses_on_traversal (../other_engagement)
  - test_refuses_on_absolute_path (/etc)
  - test_refuses_on_symlink_escape (engagement/source -> /etc)
  - test_allows_nested_subdir_inside_engagement (regression guard
    against over-rejection of valid nested paths)
- 132 policy tests green. No code path in the adapter launches a
  subprocess when containment fails.

## Milestone 4 — egress enforcement (2026-11-13)
- src/sentinel/netns/: namespace.py, nft.py, dnsmasq.py
- tests/egress/: 20 tests passing (E-00a-d, E-01..E-14)
- Enforcement mechanism: per-run network namespace + veth + dnsmasq +
  Sentinel-owned nftables table, coexisting with Docker's tables.
- Six design amendments recorded in egress-architecture-v1.1.md §11:
  11.1 chain priority -10 (Docker's filter table priority 0 runs first
       otherwise, silently killing our packets)
  11.2 ip_forward=1 during run (else packets die at route lookup before
       netfilter sees them)
  11.3 INPUT chain required (Docker gateways are local main-ns addresses)
  11.4 E-09 verifies either deny rule fired OR destination is linkdown
  11.5 counters() must read both chains (nftables -j per-chain query)
  11.6 INPUT rules match ip saddr, not iifname (local delivery to
       dev lo rewrites iifname)
- Source IP matching (ip saddr) is robust against kernel rerouting that
  iifname cannot survive. This is the primary scoping mechanism for
  INPUT chain rules.
- Kill switch: netns delete is atomic and complete.
- Docker coexistence verified: E-00b, E-09, E-10 prove Docker's tables
  survive a Sentinel run.

## M4.1 — CLOSED (2026-11-13)
- Egress suite: 27 tests (E-00a-d + E-01..E-14 + E-15..E-18 + E-20a/b + E-21)
- Policy suite: 134 tests
- Total: 161 tests green

### Fixes applied in M4.1
- Fix 1: dnsmasq uses host-record= (exact host), not address=/ (domain+subdomains)
- Fix 1: DNS input validated via ipaddress + hostname regex
- Fix 1: temp dirs use full uuid suffix (unpredictability)
- Fix 2: IPv6 catch-all deny in both chains (defense in depth)
- Fix 3: add_approved() rejects CIDR and protected-range IPs before
  installing allow rules (E-16)
- Fix 5: ordering confirmed -- ip_forward enabled BEFORE per-iface sysctls,
  so the kernel's "0->1 reset to conf/default/*" cannot wipe rp_filter or
  accept_local. Restore order mirrors: per-iface first, ip_forward last.
  E-20a proves success path, E-20b proves exception path.
- Fix 6: _kill_namespace_processes enumerates pids via `ip netns pids`,
  SIGTERM then SIGKILL after 2s grace, verified before `ip netns delete`.
  Also runs in _cleanup_stale for crashed-run recovery. E-21.
- Fix 7: fcntl.flock on /tmp/sentinel-run.lock serializes concurrent
  runs. Released automatically on process exit. E-18.

### Deferred to M5 (per reviewer approval)
- P0 #1: SandboxRunner as the enforcement boundary. The `.release-gate`
  marker still gates registration; the runner will gate execution.
  E-22 will prove it in M5.
- L7 path/method enforcement (requires HTTP proxy in front of scanner).
- Privilege dropping for scanner processes (needs an actual scanner).
- Operating Mode Manager (post-M5).

## M5.1 — SandboxRunner — CLOSED (2026-11-13)
- `src/sentinel/runner/sandbox_runner.py` — the only permitted entry
  point for network-capable subprocesses. Enforces, before any
  subprocess spawn:
  1. manifest exists, network_access=True, DB hash verifies, binary
     digest matches
  2. approval exists and belongs to this engagement
  3. argv[0] resolves to the manifest's pinned executable
  4. request hostname is in approved_assets for this engagement
  5. RequestContext built from *current* state; gatekeeper check covers
     policy hash, scope lock, target set, tool/adapter/manifest/egress
     hashes, port, protocol, method, path, expiry, revocation
  6. resolved IP is not in any DENIED_RANGES entry
  Only after all six pass does it call `run_namespace()` and spawn
  the subprocess. Every denial writes a `sandbox_denied` audit event;
  success writes `sandbox_ok` with full provenance.
- Tests: 13 in test_sandbox_runner.py — E-22b×3, E-22c, E-22d×4,
  manifest/argv/hostname denials, happy path, and a meta-test that
  no subprocess launches on any denial path.
- Total suite: 40 egress + 134 policy = 174 tests.
- Design decision record: docs/sandbox-runner-design.md.

## What M5.1 does NOT do (deferred, documented)
- L7 method/path enforcement at wire level (needs HTTP proxy). The
  gatekeeper refuses if the *approval* doesn't permit them; the sandbox
  cannot verify what a tool actually sends over TLS.
- Privilege dropping (needs a scanner that requires it; M6).
- Adapter-level "must use SandboxRunner" lint enforcement
  (code review + E-22 meta-test for M5.1; linter is M5.4).

## M5.2c — Subfinder adapter — CLOSED (2026-11-13)
- `src/sentinel/adapters/subfinder.py` — first network-capable adapter.
  Uses SandboxRunner with `provider_endpoints=("crt.sh",)`.
  argv: `subfinder -d <target> -sources crtsh -silent -json -nc`.
- Writes every valid finding to `candidate_assets` with
  `discovery_source="subfinder:crtsh"`. Never writes to `approved_assets`.
- Rejects: wildcards, non-subdomain hosts, invalid hostnames, duplicates
  (within run and against existing candidates).
- Manifest `subfinder 2.6.7` registered with execution_class=2,
  network_access=True, infrastructure_endpoints=("crt.sh",).
  SHA-256 pinned in tool_manifests.
- Approval must list `crt.sh` in `approved_infrastructure_endpoints`;
  SandboxRunner refuses execution if approval.providers ⊄ manifest.providers
  or request.providers ⊄ approval.providers.
- Tests: 15 unit (parse + validate), 2 integration (fake subfinder
  binary through the full sandbox). Total suite: 196 tests green
  (134 policy + 45 egress + 17 adapters).
- Provider disclosure is audited: one `sandbox_provider_contact` event
  per provider, with target hostname, provider, target IP, provider IPs,
  and namespace.

## M5.2c — test-fix note (2026-11-13)
- `candidate_assets` persists rows across the candidate → approved
  transition (review_state becomes 'approved', row remains). Queries
  that mean "newly discovered in this run" must filter on
  review_state='pending'. The integration test was corrected to do so
  after a false-positive assertion failure.

## M6.1 — Nmap TCP connect adapter — CLOSED (2026-11-13)
- `src/sentinel/adapters/nmap.py` — first active-assessment adapter.
  argv: `nmap -sT -Pn -n --max-rate N -p PORTS -oX - <target>`
  through SandboxRunner with `additional_ports` for multi-port scans.
- Writes each state='open' finding to candidate_assets with
  asset_type='service', canonical_value='<host>:<port>/<proto>',
  discovery_source='nmap:tcp_connect_scan'. Never writes to approved_assets.
- Manifest `nmap 7.94` registered with execution_class=2,
  network_access=True, infrastructure_endpoints=() (Nmap's MAC-vendor DB
  ships with the binary; no network fetch during scan).
- Refused at adapter level (defence in depth, independent of sandbox):
  `--script*`, `-A`, `-O`, `-sC`, `-sV`, `-sU`, `-sS`, `-sA`, `-sW`,
  `-sM`, `--traceroute`, `-sI`, `-b`, `--interactive`. Full list in
  `FORBIDDEN_FLAGS`; tested per-flag.
- Rate limit: from approval's `request_rate_budget`, injected as
  `--max-rate N`. Userspace rate limiting chosen over `tc` because it
  matches Nmap's own probe discipline and is auditable in the argv
  (recorded in audit details).

### Design decisions baked in (flag for review)
1. **Ports**: explicit list from approval, no ranges. Ranges would need a
   schema change; deferred.
2. **Class 2, not 3**: `-sT -Pn` against approved ports is "active
   low-impact" per ECR §5.2. Class 3 (intrusive) would require a new
   adapter type and is out of scope for M6.1.
3. **Rate limits**: `--max-rate` argv constraint (userspace), not kernel
   `tc`. Documented in audit.
4. **NSE**: none permitted. `--script*` is a policy violation at the
   adapter; SandboxRunner would also refuse if the manifest ever
   permitted it, but the manifest doesn't.

### Tests
- ~22 unit (argv construction, forbidden-flag rejection per flag,
  XML parsing including malformed input).
- 2 integration (fake nmap through the full sandbox; unapproved port
  denied before spawn).
- Total suite: ~220 tests (134 policy + 45 egress + ~41 adapters).

## M6.1 — Nmap TCP connect adapter — CLOSED (2026-11-14)
- `src/sentinel/adapters/nmap.py` — first active-assessment adapter.
  argv: `nmap -sT -Pn -n --max-rate N -p PORTS -oX - <target>` via
  SandboxRunner with `additional_ports` for multi-port scans.
- Open ports written to candidate_assets (asset_type='service',
  canonical_value='<host>:<port>/<proto>'). Never to approved_assets.
- Manifest `nmap 7.94`, execution_class=2, network_access=True,
  infrastructure_endpoints=().
- Adapter-level refusals (independent of sandbox): --script*, -A, -O,
  -sC, -sV, -sU, -sS, -sA, -sW, -sM, --traceroute, -sI, -b, --interactive.
  Full list tested per-flag.
- Rate limit from approval.request_rate_budget, injected as --max-rate.

### Four design decisions flagged for review
1. Class 2, not 3: -sT -Pn is connect() only (no raw sockets, no
   admin). ECR §5.2 fits this to "active low-impact".
2. Ports: explicit list from approval, no ranges (schema change
   deferred). Ranges may be required for real bug-bounty work.
3. Rate limits: --max-rate (userspace), not tc (kernel).
4. NSE: refused entirely, not allowlisted.

### Test totals
228 green: 134 policy + 45 egress + 49 adapters (nmap 32, subfinder 17).

## M6.1.1a — Sandbox and authorization hardening — CLOSED (2026-11-14)
- Privilege dropping: scanners run as `nobody:nogroup` via
  `setpriv --no-new-privs --clear-groups --reuid=nobody --regid=nogroup`.
  Binary must be world-executable; parent dirs world-traversable.
- Real approval verification (previously stubs):
  - scope_lock_hash: SHA-256 of current approved_assets set
  - adapter_code_sha256: SHA-256 of adapter_code_path (new required param)
  - egress_profile_id: hash of current nft config + DENIED_RANGES
  - provider_hash: recomputed and compared to stored
  - tool_name + tool_version: explicit match against manifest
- Audit fail-closed: pre-spawn `sandbox_start` event and every
  `sandbox_provider_contact` event MUST write or the run aborts.
  Audit decision classification corrected:
  started / completed / denied / failed / revoked.
- IPv4-only resolver: AF_INET, not AF_UNSPEC.
- Multi-IP approved: every resolved IPv4 for the target is added to
  approved destinations, not just the first.
- Nmap output validation: rejects observations whose IP is not in the
  approved resolved set, port not in approved ports, or protocol != tcp.
- nft remove ownership check: refuses to delete `inet sentinel` unless
  its chains match CHAIN or INPUT_CHAIN.
- Test suite: 228 green.
  Egress: 45 (unchanged; scope_lock_hash values now real hashes).
  Adapters: 49 (30 nmap unit + 2 nmap integration + 15 subfinder unit
    + 2 subfinder integration). Integration binaries live under /tmp
    (world-traversable for nobody) with chr(10) newlines to avoid
    shell-heredoc escaping corruption.

### Deferred to M6.1.1b
- P0.4: real external connectivity test against operator-owned endpoint.
- P0.5: shared-IP authorization (needs approval schema decision).
- P1.7: aggregate budget manager (per-engagement runtime).
- P1.8: revocation watchdog (post-spawn termination).
- P1.11: Subfinder provider-only egress (drop target :443 from approved
  destinations; Subfinder only needs crt.sh).
- P1.12: post-SIGKILL verification via /proc enumeration.
- P1.13: registry marker cleanup (`.release-gate` still gates register,
  but SandboxRunner is now the real execution gate).

## M6.1.1b — CLOSED (2026-11-14)
- P1.7 budget manager: approval_usage table + check_available +
  record_usage. SandboxRunner refuses when any dimension would exceed
  the ceiling; records actual bytes/runtime after every run
  (including timeouts). Adapters declare estimated_requests (nmap:
  len(ports); subfinder: len(providers)).
- P1.8 revocation watchdog: separate thread with its own Database
  connection polls approval state every 2s; kills the namespace on
  revoke/expire/engagement-inactive. SandboxRevoked raised.
- P1.11 Subfinder provider-only: requires_target_connection=False;
  target IP not added to nft approved destinations.
- P1.12 post-SIGKILL verification: _kill_namespace_processes returns
  remaining PIDs; run_namespace warns to stderr if any survive.
- P1.13 registry docstring reconciled: `.release-gate` gates
  REGISTRATION; `run_in_sandbox()` gates EXECUTION. Both needed.
- Tests: 48 egress + 50 adapters + 134 policy = 232 green.

### P0.4 (real positive connectivity) — deferred to deployment
The reviewer asked for a "controlled endpoint that you own." That is
an operator deployment task, not a code item. A test against the
veth gateway would prove packet delivery across the loopback-equivalent
link, not external reachability — the counter-based tests (E-01,
E-07) already prove the firewall rule fires.

**Operator runbook for the first real engagement:**
1. Deploy a controlled HTTP listener on a public IP you own
   (e.g. `python -m http.server 8443` on a VPS, or an S3 static
   bucket on a FQDN).
2. Create an approval for that FQDN with the corresponding port
   and `port_scanning_authorized=False`.
3. Run `httpx -u https://<your-endpoint>/ -silent` (or curl via a
   class-2 manifest) through `run_in_sandbox`.
4. Verify: response is received, audit shows `sandbox_ok`, budget
   usage incremented, `sandbox_start` + `sandbox_ok` events present.
5. Attempt the same against an unapproved FQDN; verify
   `sandbox_denied` + reason "not in approved_assets".
6. Revoke the approval mid-run; verify `sandbox_revoked` + namespace
   torn down within 2× the watchdog poll interval.

This is a per-operator onboarding step, not a CI test. Include it
in the reviewer handoff as "verification not covered by unit tests."

## M8.1 — LLM client foundation — CLOSED (2026-11-14)
- `src/sentinel/llm/client.py` — `call_structured()` is the only
  sanctioned path from application code to the model. Direct
  `ollama.chat()` calls outside this file are a code-review reject.
- `src/sentinel/llm/prompts.py` — `PromptTemplate` with hash-based
  versioning. Editing a prompt produces a different hash; audit
  distinguishes outputs before/after the edit.
- Four invariants enforced per call:
  I1: versioned prompt (`name|version|template` SHA-256)
  I2: mandatory `model_runs` row per attempt (ok / schema_invalid / error)
  I3: `redact()` + `assert_no_known_secrets()` before prompt assembly;
      `LLMSecretDetected` raised if a known-secret shape survives
  I4: `OLLAMA_HOST` must be loopback; `LLMConfigError` otherwise
- Circuit breaker: in-memory, 5 failures in 10 min -> 10 min open.
  `LLMCircuitOpen` while open. Reset by process restart.
- Retry policy: up to `max_retries` (default 2). Retry on Pydantic
  validation error and transport exceptions. Do not retry on
  LLMSecretDetected / LLMConfigError / LLMCircuitOpen.
- Context ceiling: 32 KiB `user_content`.
- Design record: `docs/llm-client-design.md`.
- Tests: 14 in `tests/llm/test_client.py`, all model calls mocked.
- Suite total: **341** (14 llm + 45 l7 + 53 egress + 94 adapters
  + 135 policy).

### Not in M8.1 (deferred)
- Knowledge retrieval (FTS5) — M8.2
- Triage pipeline (evidence -> LLM -> validated candidate) — M8.3
- Prompt content for specific OWASP/CWE mappings — M8.3
- Cross-process circuit breaker — M9+

## M8.2 — Knowledge base — CLOSED (2026-11-14)
- `src/sentinel/knowledge/fts.py` — FTS5 search with BM25 ranking.
  `_sanitize_query()`: preserves CVE/CWE identifiers, lowercases regular
  tokens, drops stopwords, AND-joins quoted terms. Empty/all-stopword
  queries return "" (caller gets no hits).
- `src/sentinel/knowledge/ingest.py` — frontmatter parsing + idempotent
  upsert. Unchanged content is a no-op; changed content replaces the
  FTS row.
- Migration 0006 creates `knowledge_entries` + `knowledge_fts` (FTS5
  virtual, unicode61 with remove_diacritics 2).
- Seed corpus: 6 documents (SQLi, BOLA, XSS, SSRF, misconfiguration,
  sensitive data exposure).
- Search tests prove: SQLi query finds SQLi doc; BOLA query finds BOLA
  doc; irrelevant queries return empty; topic filter works; snippets
  contain `<<`/`>>` markers.
- Not in M8.2: LLM consuming KB (M8.3), embeddings (M9+ if needed).
- Tests: 23 in tests/knowledge/test_fts.py.
- Suite total: 364 (14 llm + 45 l7 + 53 egress + 94 adapters
  + 135 policy + 23 knowledge).

## M8.5 — Knowledge base expansion — CLOSED (2026-11-14)
- Recursive ingest: `ingest_directory()` uses `rglob("*.md")` so
  `knowledge/<domain>/*.md` structure is ingested.
- 14-domain scaffold created at `knowledge/` with subdirectories for
  every collection the M8 review named.
- 36 curated documents across ALL 14 domains (final state; per-domain
  counts in `docs/knowledge-base-coverage.md`). See that document for
  what is and is not covered. Reviewers should treat the coverage
  doc as authoritative rather than this milestone note.
- Retrieval benchmark (`tests/knowledge/test_benchmark.py`): 23 queries
  with expected top-3, plus a mean-reciprocal-rank assertion
  (MRR >= 0.5). Measures whether the KB actually serves triage.
- AND-then-OR fallback in `search()`: preserves precision for
  single-doc queries, recovers recall for multi-token queries that
  name a concept the doc describes in different words. Implements
  the reviewer's "staged search" recommendation.
- Every document is a curator summary, not verbatim — source_url,
  publisher, version, license, review_status required. Prevents
  fabricated content from being cited as authoritative.

## M8.4b — Few-shot from validated findings — CLOSED (2026-11-14)
- `sentinel.llm.fewshot.retrieve_similar_examples()` — k-nearest
  validated findings for the same engagement, ranked by token
  overlap (Jaccard-style, MIN_SCORE=0.10).
- Only `lifecycle_state IN ('human_validated', 'report_ready',
  'resolved')` are eligible. Candidates and rejected findings are
  excluded. The operator's judgment is the training signal.
- Cross-engagement isolation: SQL filter on `engagement_id`.
  Program A's findings never leak into Program B's triage.
- `TRIAGE_V2` prompt has `{examples}` slot. `call_structured()`
  substitutes `prompt_context` before `{user_content}`, applying
  redaction to both.
- Pipeline integration: `use_fewshot=True` opt-in. Default V1
  behavior unchanged. Old model_runs remain distinguishable
  by prompt_template_hash.
- `TriageResult.examples_used` records which findings were shown.
- Deferred: end-to-end few-shot test requires real `human_validated`
  findings, which only exist after a real assessment. The mechanism
  is tested with synthetic validated rows; production activation
  happens organically as the operator validates findings.

## State at M8 closure (historical snapshot)
- 482 tests green at that M8 snapshot (135 policy, 60 egress, 94 adapter unit,
  8 adapter integration, 68 l7, 17 runner, 29 llm, 52 knowledge,
  19 triage).
- At that snapshot, 4 of 14 knowledge domains were populated, 10 scaffolded.
- Few-shot learning mechanism ready; activates on first real
  validated finding.
- M6/M7/M8 reviewer items were marked closed at that time; see the current
  project audit for privileged validation and knowledge provenance gaps.

## M9a — audited finding lifecycle — implementation unit complete (2026-11-14)
- `sentinel.findings.FindingStore` enforces the allowed candidate-to-review
  lifecycle transitions. Triage continues to create only `candidate` rows.
- `ready_for_review`, `human_validated`, `report_ready`, and `submitted`
  require at least one same-engagement artifact whose redaction status is
  `clean` or `redacted`.
- Each state change and its `finding_transition` audit event commit in the
  same SQLite transaction. Audit failure rolls back the state change.
- Direct promotion skips are rejected; final states are terminal except
  `report_ready` may return to `human_validated` for revision.
- Actor label is mandatory, but currently supplied by the calling code;
  this does not authenticate identity. Integrate an operator identity
  layer with the future UI before multi-user use.
- Tests: 6 focused finding tests pass. Full suite: 442 passed, 66 skipped,
  0 failed. The 66 skips require root for network namespace creation; see
  `docs/TEST_RESULTS.md`.
- Remaining M9 work: authenticated operator workflow, deterministic CVSS
  4.0, and sanitized Markdown/PDF report generation.

## v4.3 trust and execution integrity notes

The v4.3 implementation adds `sentinel knowledge list` to find entry IDs and show the latest review state. After ingestion, review entries with `sentinel knowledge review <entry_id> --decision approved --rationale "..." --reviewer <distinct-label>`. Reject untrusted entries explicitly. Reviewer labels are audit attribution only and are not authenticated identities. Changing a document creates a new immutable revision and removes it from retrieval until that revision is reviewed. Existing entries are migrated as unverified.

Class 0 local scanners require bubblewrap user/network namespace support and POSIX ACL tooling for their separate output directory. If the isolation boundary cannot be created, the scanner refuses to run; do not bypass this by running the tool manually against untrusted input. Execution status (COMPLETED, PARTIAL, TIMED_OUT, FAILED) is shown in CLI output and stored with evidence. Partial and timed-out evidence must not be treated as complete coverage.

Before applying migrations 0016–0021 to a valued database, take a backup and inspect the migrations on a disposable copy. The implementation agent did not run tests, scanners, network lookups, Ollama, or privileged workflows. Follow `TEST_RESULTS.md` for independent verification steps.
