
## 8. Amendment — infrastructure providers (M5.2)

### 8.1 The distinction

Some network tools contact destinations beyond the assessment target.
Subfinder is the first: it queries certificate-transparency services
(crt.sh, etc.) *about* the target. Those providers are third parties
that learn something about the research interest. They must be
authorized separately from the target itself.

Three collections are now distinct:

| Collection | Declares | Authorized by |
|---|---|---|
| `manifest.infrastructure_endpoints` | What the **tool** can query | Tool vendor / reviewer at registration |
| `approval.approved_infrastructure_endpoints` | What the **operator** authorized for this engagement | Operator at approval issuance |
| `request.provider_endpoints` | What **this specific run** will query | Adapter (declares what argv actually uses) |

All three must agree:
- Every `request.provider_endpoints` entry must be in `approval.approved_infrastructure_endpoints`
- Every approved endpoint must be in `manifest.infrastructure_endpoints`
- Nothing outside the request is contacted (enforced by nft — see §8.4)

### 8.2 Why separate

Querying crt.sh discloses the target domain to crt.sh's operators. Under
some programs that is acceptable; under others it is a policy violation.
The approval record makes the disclosure explicit and auditable. A tool
being approved does not automatically approve every source it *could*
query — the operator names the sources, every time.

### 8.3 Operational model

Approving Subfinder with `-sources crtsh` requires:
1. Manifest declares `infrastructure_endpoints=("crt.sh",)`
2. Approval's `approved_infrastructure_endpoints=["crt.sh"]`
3. Adapter's `SandboxRequest.provider_endpoints=("crt.sh",)`

SandboxRunner:
- Validates the three sets nest correctly
- Resolves every provider hostname + the target hostname
- Passes all IPs (target + providers) to `run_namespace(approved=[...])`
- Includes all hostnames in `hostname_records`
- Writes one `sandbox_provider_contact` audit event per provider

### 8.4 Defence in depth

If an adapter misrepresents its request (declares crt.sh but argv actually
uses censys.io), the nft rules still block. SandboxRunner only approved
crt.sh's IPs; censys.io's IPs are not in the approval set, so
`deny-out` fires. The audit shows the attempt.

### 8.5 Not in M5.2

- Per-source budget tracking (M5.3)
- Provider credentials / API keys (M5.3+; crt.sh is unauthenticated)
- Provider approval *delegation* (e.g. "any CT log") — M5.2 requires
  exact hostname match
