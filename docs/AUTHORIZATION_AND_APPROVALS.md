# Authorization and Approvals

The operator must own the systems assessed or hold explicit authorization from
the system owner. A public IP, accessible service, API key, bug-bounty account,
or broad policy URL does not by itself authorize a specific operation.

The CLI creates an engagement, adds scope, activates the engagement, and issues
an approval that can bind the operation to tool identity, profile, target,
parameters, budgets, and expiry. The runner revalidates the applicable state
and revocation before execution. Class 3 operations require additional gates
and are intended for controlled labs. An approval is an application control;
it cannot prove legal authority or override a program's exclusions.

Use exact, minimal target scope. Review current written authorization and
prohibited actions before every operation. Revoke approvals when the authorized
window ends. See [operator-guide.md](operator-guide.md) for current command
workflow and [Security Model](SECURITY_MODEL.md) for limitations.
