# ECR v1.0.2 — Class 3 Authorization Amendment

**Parent:** SENTINEL-ECR-001 v1.0.1
**Date:** 2026-11-14
**Status:** Adopted
**Supersedes:** v1.0 §2.2 (Non-goals) exclusion of exploitation tools

## 1. What changed

ECR v1.0.1 §2.2 excluded all exploitation tools:

> "High-risk capabilities such as credential extraction, C2, reverse
> shells, persistence, social engineering, denial-of-service and
> destructive exploitation are not autonomous features of v1.0."

This is reinterpreted. The key word was **autonomous**. It does not
prohibit an operator from running sqlmap against an authorized target
in a bug-bounty scope that permits SQLi demonstration.

Sentinel now permits Class 3 tools under new hard gates, while
preserving the invariant that **the model never authorizes,
executes, or reports autonomously**. The human is still the only
actor that can approve and run a Class 3 operation.

## 2. What is now permitted

| Tool | Classification | Where it may run | Constraints |
|---|---|---|---|
| sqlmap | Class 3 (intrusive) | Authorized bug-bounty targets where the program permits SQLi demonstration | `--batch`, `--risk=1`, `--level=1`, `--technique=BEUSTQ`, `--no-cast`, proof-only (`--dump` restricted, no full tables, no dump-all) |
| metasploit-framework | Class 3 (intrusive) | **Lab environments only** — no real targets, ever, in v1.0.x | `msfconsole` with an approved workspace; `exploit` and `run` require a second confirmation flag that is only set when `lab_environment=True` |

Note on metasploit: the tool's own capability envelope includes
persistence, C2, reverse shells, and lateral movement primitives
that cannot be turned off. Even a benign `auxiliary/scanner/`
module can be chained into exploitation. Therefore metasploit is
**not** permitted against real HackerOne targets in any capacity,
only against isolated labs (DVWA, Metasploitable, custom VMs, or
local Docker).

## 3. What is still excluded

The following remain non-goals in v1.0.x regardless of program scope:

- **Autonomous exploitation.** Every Class 3 tool launch requires a
  fresh `intrusive_authorized=True` approval issued by the operator
  within the current engagement.
- **Credential extraction as a task.** sqlmap's `--passwords`,
  `--privileges`, and `--roles` are refused. Reading a password hash
  as proof of SQLi (one row) is permitted; dumping the user table is
  not.
- **Persistence, C2, reverse shells against real targets.**
  Metasploit sessions on real targets are refused. Lab sessions are
  permitted with documented scope.
- **Denial of service.** Any tool flag that causes load-based
  degradation (`sqlmap --threads > 1`, metasploit DoS modules) is
  refused.
- **Data exfiltration.** The proof-only rule: the operator must stop
  at the minimum evidence that demonstrates impact. No
  `--dump-all`, no full table extraction, no PII beyond one
  demonstrative row.
- **Social engineering.** Phishing, vishing, and physical are out of
  scope; no adapter exists.

## 4. New authorization fields

Two fields are added to `approvals` (migration 0010):

- **`intrusive_authorized: bool`** — default False. Must be True for
  the SandboxRunner to permit a Class 3 tool to launch. The CLI
  requires the operator to pass `--intrusive` at approval issuance,
  which must be preceded by an interactive confirmation prompt
  (`I understand this approval authorizes active exploitation
  testing: [yes/N]`).
- **`lab_environment: bool`** — default False. Must be True for any
  Class 3 tool that has demonstrated high-risk default behavior
  (metasploit today; sqlmap does not require this flag since its
  default behavior can be constrained to proof-only via flags).
  Issuing an approval with `lab_environment=True` requires the
  engagement to be marked as a lab engagement (`platform='lab'`),
  not a bounty/VDP/client engagement.

## 5. SandboxRunner gate (the enforcement)

Before any Class 3 subprocess launch, SandboxRunner checks in order:

1. `manifest.manifest.execution_class >= 3` → proceed to checks below.
2. `approval.intrusive_authorized is True` → else refuse with audit
   event `sandbox_denied` reason `class3_no_intrusive_auth`.
3. If the tool requires lab mode (metasploit): `approval.lab_environment
   is True` → else refuse with `class3_lab_required`.
4. `engagement.platform == 'lab'` when `lab_environment=True` → else
   refuse with `class3_not_lab_engagement`.
5. All existing approval checks (policy hash, scope, expiry, target
   set, budgets) apply unchanged.

Failure at any check writes an audit event with the reason. No
subprocess is launched on any failure.

## 6. Why this is safe(r) than the original "no exploitation" rule

The original rule was "we don't have these tools, so no one can use
them." That rule was easily circumvented by running sqlmap outside
Sentinel — with no audit trail, no evidence capture, no triage.
The new rule is "we have these tools, but they only run through the
same sandbox, approval, evidence, and audit pipeline that every
other tool runs through." Every Class 3 launch is:

- Bound to a specific engagement
- Bound to a specific target set
- Time-limited (default 30 min)
- Budget-limited (default 100 requests)
- Rate-limited
- Captured as evidence
- Audited as a `sandbox_ok` event with full provenance

The audit trail now covers what would previously happen entirely
outside Sentinel's visibility. That's a net improvement.

## 7. What this amendment does NOT authorize

- Adding sqlmap or metasploit as *registered manifests* is still a
  separate step. Registering a manifest does not enable a tool; the
  operator must explicitly approve a Class 3 operation for each
  engagement, and the runner will refuse without the fields above.
- Neither adapter exists in code yet. Building them is the next
  phase of work (see `docs/class3-roadmap.md`).
- Existing enforcement — no autonomous execution, no report
  submission, no credential extraction — is unchanged.

## 8. Acceptance criteria for enabling a Class 3 adapter

An adapter for sqlmap or metasploit is considered ready when:

1. Manifest registered with `execution_class=3`, `network_access=True`.
2. Operation profile defined with the exact pinned argv the adapter
   will produce (from `src/sentinel/runner/builtin_profiles.py`).
3. Integration test with a fake binary proves the profile /
   argv path / audit trail.
4. End-to-end test against an isolated lab target (DVWA, Metasploitable,
   or a controlled VM) demonstrates:
   - Approval with `intrusive_authorized=True` succeeds.
   - Approval without that field refuses with the right audit reason.
   - `lab_environment` check fires when required.
   - Evidence and audit events are written correctly.
   - The proof-only constraint holds (evidence captured shows the
     minimum proof, not full extraction).
5. Operator guide documents the manual steps for authorizing and
   running a Class 3 tool against the specific lab.

Until all five hold, the adapter stays out of the registry (or
registered but disabled). The registry's existing refusal gate
(`register()` refuses `execution_class >= 2` without the
`.release-gate` marker) applies to Class 3 as well.
