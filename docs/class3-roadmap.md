# Class 3 Adapter Roadmap

**Adopted:** 2026-11-14
**Companion:** docs/ecr-v1.0.2-class3-amendment.md

## Status

Class 3 authorization infrastructure is complete:
- Two new approval fields (`intrusive_authorized`, `lab_environment`)
- SandboxRunner gate refuses Class 3 without both
- 3 integration tests proving the gate fires

**sqlmap and metasploit adapters are NOT yet built.** They require
new adapter infrastructure that doesn't exist today. This roadmap
estimates what each needs.

## sqlmap — estimated 3 sessions

### What exists that helps

- SandboxRunner with Class 3 gate
- Operation profile pattern (argv construction)
- Evidence ingestion
- Audit chain

### What's missing

1. **HTTP POST body support.** sqlmap's primary technique against
   login forms and JSON APIs requires POST bodies. Current
   `SandboxRequest` has a `path` field for GET but no `body` field
   with content-type. Class 3 adapters need a body-bearing
   operation profile. Session 1.

2. **Proof-only output parser.** sqlmap output is chatty and can
   include hundreds of lines per finding. The adapter must:
   - Parse the `--batch` output for the specific finding (injection
     point, technique, DBMS, some proof row)
   - Discard everything else from the model-runs evidence
   - Refuse to persist anything that looks like a full table dump
   Session 2.

3. **Safety flag enforcement at the profile level.**
   Operation profile must produce exactly:
   `sqlmap --url=<target> --batch --risk=1 --level=1
   --technique=BEUSTQ --no-cast --no-escape --threads=1
   --timeout=30 --retries=1 --dump --stop=1` (one row)`
   Anything more is refused by the profile builder, not just by
   convention. Session 2.

4. **Approval schema extension** — sqlmap may need a new field
   `proof_only_confirmed=True` at approval issuance (an extra click
   beyond `intrusive_authorized`). Session 3.

5. **End-to-end lab test** against DVWA or a controlled Juiceshop
   SQLi endpoint. Session 3.

## metasploit — estimated 5 sessions

metasploit is architecturally different from every current adapter.
Current adapters are stateless one-shot tools. metasploit is a
persistent interactive console with sessions, listeners, workspaces,
and multi-step workflows. It needs:

1. **Session management** — `msfconsole` doesn't exit after `run`;
   it waits for input. Two options:
   - `msfconsole -r script.rc` with an RC resource file; session
     lives until script completes.
   - A new "session supervisor" component that manages long-lived
     msfconsole subprocesses across multiple CLI invocations.
   The second is more powerful and more dangerous. Session 1.

2. **Workspace isolation** — metasploit stores data in its own
   PostgreSQL-backed workspace. Each engagement needs its own
   workspace to prevent cross-engagement data bleed. Session 2.

3. **RC script generation** — the adapter builds an RC file, not
   an argv. Operation profile pattern needs extension to support
   "generated-input files" not just "argv construction."
   Session 3.

4. **Lab-environment hard gate** — the SandboxRunner gate already
   refuses metasploit without `lab_environment=True` and
   `platform='lab'`. But the CLI must refuse to even *register* the
   metasploit manifest against a non-lab engagement. Session 4.

5. **End-to-end lab test** against Metasploitable 2 in an isolated
   VM. Session 5.

## Non-negotiables that constrain the roadmap

1. **Both adapters refuse to run against real HackerOne targets** in
   v1.0.x. sqlmap could be enabled for real targets later via an
   ECR v1.0.3 amendment; metasploit should not be, ever, given its
   default capability envelope.

2. **No autonomous chain execution.** The operator launches each
   sqlmap / metasploit run explicitly. The triage pipeline may
   *suggest* a Class 3 follow-up to an operator, but cannot execute
   it.

3. **Proof-only is enforced at the profile builder, not by prompt.**
   A model change cannot make the adapter produce a `--dump-all`.
   The profile's `_build_*` function is the boundary.

4. **Every run audited as `sandbox_ok` with full provenance.**
   Including the RC file contents (for metasploit), the exact
   payload if applicable, the destination, and the exit code.

## Sequence recommendation

Do NOT start sqlmap or metasploit until:

- A real HackerOne engagement has been completed end-to-end with the
  existing 6 adapters (proves the workflow and reveals what's
  actually needed).
- The M8.6 knowledge sync work has closed (so CVE references in
  findings from sqlmap/metasploit are verifiable).
- The report renderer exists (M9b) — otherwise SQLi findings would
  need to be formatted manually.

That sequencing means: **finish the current application first, run
one real engagement, then come back for Class 3 adapters.**

## Not on this roadmap

- `metasploit-pro` — commercial; not integrated; the open-source
  framework is what's documented above.
- `msfvenom` payload generation — separate from metasploit; would be
  a Class 3 capability of its own; not scoped for v1.0.x.
- Custom C2 infrastructure — out of scope per ECR §2.2.
- Reverse shells against real targets — out of scope per ECR §2.2;
  lab-only if added later.
