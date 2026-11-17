# Security Model

Sturmer is an operator-controlled assessment workbench. It does not establish
legal authorization, guarantee safe operation, or make an exposed target
eligible for scanning. Assess only systems the operator owns or is explicitly
authorized to test.

## Enforced controls

- Engagement scope and lifecycle are stored separately from tool manifests.
- Approvals bind engagement/scope and operation details, with profile-specific
  gates, budgets, expiry, and revocation checks.
- Tool registration records identity and binary integrity metadata; the runner
  checks the expected manifest and adapter code identity before execution.
- Network-capable operations route through the runner and Linux network
  controls where configured; subprocesses use privilege dropping and output
  limits in the applicable paths.
- Evidence is redacted and linked to integrity/audit records. Audit writes
  required before execution fail closed when configured by the call path.
- Intrusive Class 3 profiles require additional authorization and are intended
  for controlled labs.

## Limits and trust assumptions

Some guarantees are application-level and depend on correct configuration.
Kernel-level isolation of TLS proxy upstream connections and fully
unprivileged/no-network Class 0 staging remain deferred. Root/administrator
setup may be required for network namespaces and firewall rules. A compromised
host, malicious external scanner, incorrect tool manifest, operator error, or
incomplete target authorization can defeat intended safety. Local Ollama model
output is untrusted and requires human review. Evidence can contain sensitive
data; protect data directories and exports.

See [Threat Model](threat-model.md), [Egress Architecture](EGRESS_ARCHITECTURE.md),
[Authorization and Approvals](AUTHORIZATION_AND_APPROVALS.md), and
[Technical Debt](TECHNICAL_DEBT.md).
