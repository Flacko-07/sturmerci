# Licensing Review

## Owner decision

The project owner selected **Apache License 2.0 (SPDX: `Apache-2.0`)** for
first-party source code. The complete unmodified official text is in the root
[LICENSE](../LICENSE) and is available from the
[Apache Software Foundation](https://www.apache.org/licenses/LICENSE-2.0.txt).
The package metadata declares the SPDX expression and a compatible setuptools
minimum. First-party Python and SQL files in `src/sentinel/`, `tests/`, and the
root benchmark script carry SPDX identifiers. No copyright owner or author
identity has been invented.

The licence does not cover third-party tools, dependencies, knowledge
documents, templates, or assets unless their own rights permit that treatment.
Apache 2.0 does not grant rights to the product name, logo, or other marks.

## Practical comparison retained for contributor context

| Model | Commercial use and modification | Redistribution / network use | Patent / contribution considerations |
|---|---|---|---|
| Apache 2.0 — selected | Permits commercial use and modification under its conditions. | Permits redistribution; no special network-source offer. | Includes an express contributor patent grant and termination clause; contributions are under the licence absent a separate agreement. |
| MIT | Permissive commercial use and modification. | Permits redistribution with notice; no special network-source offer. | No express patent grant; contributions do not have Apache's explicit patent terms. |
| AGPLv3 | Permits commercial use and modification subject to copyleft. | Network users of modified versions must be offered corresponding source under its conditions. | Patent provisions and contributor terms differ from Apache; evaluate compatibility of bundled components. |
| Source-available commercial model | Rights depend on custom terms; commercial use may be limited. | Redistribution and network use can be restricted by contract. | Requires owner-authored terms and legal review; it is not generally an open-source licence. |

These are high-level descriptions, not legal advice. The Apache decision has
been implemented for first-party source, but provenance and third-party rights
must still be resolved before publication.

## Provenance and quarantine review

The supplied workspace has no `.git` directory. Consequently, commit history,
contributor identities, and past removals cannot be reviewed. Existing
first-party source files contain no conflicting copyright/SPDX headers or
obvious copied-code attribution markers in the searched source/test paths. This
working-tree inspection cannot establish copyright ownership or prove that no
third-party contribution exists. Owner confirmation of authority to license
the first-party contribution set remains required.

Do not include the following knowledge files in a public release until their
provenance and redistribution rights are confirmed. They remain in place as
research material and are listed here rather than silently deleted.

| File(s) | Current metadata | Reason held |
|---|---|---|
| `knowledge/our_research/finding-triage-patterns.md` | `Internal` | Owner decision required. |
| `knowledge/windows_security/active-directory-basics.md`, `knowledge/windows_security/windows-privilege-model.md` | `Proprietary-MS-Docs-Summarized` | Microsoft-derived summaries; redistribution rights not established. |
| `knowledge/cloud_security/aws-iam-basics.md` | `Proprietary-AWS-Docs-Summarized` | AWS-derived summary; redistribution rights not established. |
| `knowledge/cloud_security/storage-misconfiguration.md`, `knowledge/mobile_security/android-vs-ios.md` | `Proprietary-Docs-Summarized` | Source/derivative rights unclear. |
| `knowledge/wireless_security/bluetooth-le-security.md` | `Proprietary-SIG-Summarized` | Bluetooth SIG-derived summary; redistribution rights not established. |
| `knowledge/linux_security/linux-services.md` | `LGPL-2.1` | Document's derivation and applicability of the stated licence need review. |
| `knowledge/linux_security/linux-permissions.md` | `GPL-2.0-doc` | Documentation licence and source/attribution need review. |
| `knowledge/wireless_security/wifi-security.md` | `CC-BY-4.0-summarized` | Metadata is not a standard licence identifier and attribution/source need verification. |
| `knowledge/vulnerability_intel/cve-and-cvss.md` | `Public` | Source and public-domain basis are not identified in the label alone. |
| `config/wordlists/common.txt` | No licence/provenance header | Origin and redistribution rights are unclear; omitted from wheels pending review. |
| All documents labelled `IETF-Trust` | `IETF-Trust` | Confirm exact source, applicable Trust Legal Provisions, and attribution. |
| All documents labelled `Public-Domain-US-Federal` | US federal public-domain claim | Verify authorship and that no third-party material is included. |
| `knowledge/api_security/api-rate-limiting.md`, `knowledge/mobile_security/masvs-overview.md`, `knowledge/reconnaissance/passive-recon.md`, `knowledge/api_security/api-authentication.md`, `knowledge/api_security/broken-access-control.md`, `knowledge/network_security/tls-configuration.md`, `knowledge/api_security/mass-assignment.md`, `knowledge/methodologies/wstg-overview.md`, `knowledge/web_security/open-redirect.md`, `knowledge/web_security/sensitive-data-exposure.md`, `knowledge/web_security/xss-reflected.md`, `knowledge/web_security/ssrf.md`, `knowledge/web_security/cors-misconfiguration.md`, `knowledge/web_security/csrf.md`, `knowledge/web_security/sql-injection.md`, `knowledge/web_security/security-misconfiguration.md` | `CC-BY-SA-4.0` | Verify exact source text, authorship, attribution, licence version, and share-alike obligations for each file. |
| `knowledge/vulnerability_intel/cwe-overview.md`, `knowledge/methodologies/ptes-overview.md`, `knowledge/threat_intelligence/mitre-attack-overview.md` | `CC-BY-4.0` | Verify source, authorship, attribution, and licence version for each file. |
| `knowledge/reconnaissance/dns-fundamentals.md`, `knowledge/network_security/tcp-fundamentals.md` | `IETF-Trust` | Confirm exact RFC/source, applicable Trust Legal Provisions, and attribution. |
| `knowledge/forensics/evidence-handling.md`, `knowledge/forensics/log-analysis.md`, `knowledge/threat_intelligence/indicators-of-compromise.md`, `knowledge/methodologies/nist-800-115-overview.md` | `Public-Domain-US-Federal` | Verify federal authorship and that no third-party content is included. |

The specific current CC-labelled files can be listed with:
`rg -l '^license: (CC-BY|IETF-Trust|Public)' knowledge`.
Do not infer that metadata alone proves compliance.

## External dependency and tool decisions

The dependency list and unresolved tool mappings are in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). A release SBOM, exact
resolved versions, notices, and redistribution review are still required.

## Publication gates

- Confirm the owner has authority to license all first-party source and that
  third-party contributions, if any, are appropriately licensed.
- Resolve or exclude the knowledge documents and tool payloads listed above.
- Complete dependency licence and SBOM review.
- Trademark and reputation clearance is pending; Apache 2.0 grants no rights
  to the Sturmer name or logo.
