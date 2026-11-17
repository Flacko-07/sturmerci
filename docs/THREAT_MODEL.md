# Threat Model

The historical source document [threat-model.md](threat-model.md) describes
adversaries and invariants. This page indexes the current security boundary;
validate each control against the implementation and operating system before
use.

## Protected assets

Authorization and scope records, tool manifests, approval tokens and budgets,
evidence, findings, audit records, local model prompts/results, credentials,
and the operator's host.

## Threats addressed in application design

Out-of-scope target selection, stale or revoked approvals, manifest/binary
drift, over-budget execution, scanner output abuse, evidence secrets, and
unaudited operations are addressed through scope matching, approval checks,
manifest verification, limits, redaction, and audit-chain records.

## Residual risks

Controls rely on correct operator authorization, protected local storage,
trusted host kernel, correctly installed firewall/network tools, and trustworthy
external scanner binaries. TLS proxy upstream isolation, universal Class 0
no-network execution, and complete hostile-host containment are not
implemented. No public security guarantee or production-readiness claim is
made.
