# Sturmer Cyber Intelligence

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

**Sturmer** is a local-first security assessment workbench for controlled,
explicitly authorized engagements. It coordinates existing security tools,
records their outputs as evidence, and supports analyst-led triage and findings
review. The operator remains responsible for authorization and every assessment
decision.

The project currently uses the Python import package `sentinel` and the
`sentinel` command for compatibility. The distribution metadata uses the
selected product name. Repository slug proposed by the owner:
`sturmercyberintelligence`.

The default ffuf wordlist remains available in a source checkout but is
excluded from wheels until its provenance and redistribution rights are
confirmed. Installed deployments can set `SENTINEL_WORDLIST_DIR` to an
operator-managed wordlist directory.

## What is implemented

- Engagement, scope, approval, budget, and audit-chain stores backed by SQLite.
- Adapter modules for local analysis, passive reconnaissance, active scanning,
  and explicitly gated intrusive operations. Scanner executables are separate
  dependencies and are not supplied as part of the Python package.
- A sandbox runner with manifest and binary verification, execution profiles,
  network namespace and egress controls, privilege dropping, output limits,
  approval revocation handling, and audit events. Some isolation properties
  remain deferred; see [Security Model](docs/SECURITY_MODEL.md) and
  [Technical Debt](docs/TECHNICAL_DEBT.md).
- Evidence ingestion, redaction, integrity metadata, knowledge retrieval,
  local Qwen/Ollama triage, candidate findings, and report generation.

The source tree contains adapters for tools such as Nmap, httpx, ffuf, Nuclei,
ZAP, SQLMap, Metasploit, Gitleaks, Semgrep, Trivy, Bandit, ExifTool, WHOIS,
`dig`, Subfinder, theHarvester, Nikto, and SCION. A module's presence does not
mean its external executable is installed or that its operation has been
validated on a particular host. See [Adapter Catalog](docs/ADAPTER_CATALOG.md).

## Requirements and installation

The package declares Python 3.12 or newer. The implementation uses SQLite and
local Ollama for its LLM integration. Scanner binaries and any required system
services must be installed separately. The current code includes Linux network
namespace and nftables integrations; do not infer support for other operating
systems from the Python package metadata.

```sh
git clone https://github.com/Flacko-07/sturmerci.git
cd sturmerci
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
sentinel init
```

`<OWNER>` is a placeholder and must be replaced by the repository owner before
publication. Data paths and installation details are described in
[Installation](docs/INSTALLATION.md).

## Controlled local-lab example

Use a disposable local service that you own. These commands illustrate the
current CLI flow; create and verify the tool registration and approval for the
chosen adapter before execution.

```sh
sentinel engagement create --platform lab --program local-lab
sentinel engagement activate <engagement-id>
sentinel scope add <engagement-id> --value 127.0.0.1 --type ip
```

Then issue an approval for the exact tool, profile, target, and required
budgets, and run only against the local lab target. Review resulting evidence
and findings before creating a report. The operator guide documents the
approval and run workflow. Possession of an API key, public IP address, or
network access is not authorization to assess a system.

## Architecture and safety

The CLI routes operations through adapters and the sandbox runner. The runner
checks tool manifests and hashes, execution profile, approval and scope
bindings, target restrictions, and configured budgets before launching a tool.
Evidence is ingested and redacted, linked to audit records, and may be reviewed
with local Qwen/Ollama triage. Triage suggestions are not validated findings;
human review is required.

These controls have limits. Kernel-level isolation of TLS proxy upstream
connections and fully unprivileged, no-network execution for every Class 0
scanner remain deferred. CVSS 4.0 calculation, PDF reporting, and bulk
NVD/CWE/CAPEC/ATT&CK ingestion are also incomplete. Read the security and
technical-debt documents before operating the software.

## Documentation

- [Installation](docs/INSTALLATION.md) · [Configuration](docs/CONFIGURATION.md)
- [Documentation Index](docs/README.md) · [Release Checklist](docs/RELEASE_CHECKLIST.md)
- [Operator Guide](docs/operator-guide.md) · [Developer Guide](docs/DEVELOPER_GUIDE.md)
- [Architecture](docs/ARCHITECTURE.md) · [Security Model](docs/SECURITY_MODEL.md)
- [Repository Inventory](docs/REPOSITORY_INVENTORY.md) · [Adapter Catalog](docs/ADAPTER_CATALOG.md)
- [Testing](docs/TESTING.md) · [Technical Debt](docs/TECHNICAL_DEBT.md)
- [Licensing Review](docs/LICENSING_REVIEW.md) · [Third-Party Notices](THIRD_PARTY_NOTICES.md)

## Project status

This repository is being prepared for independent technical review. Historical
test results are recorded in [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md);
they are not a substitute for maintainer validation of the current checkout.
No claim of production readiness, complete isolation, trademark clearance, or
legal clearance is made.

## Licensing and brand

The owner selected Apache License 2.0 for first-party source code. The licence
does not automatically apply to third-party tools, knowledge documents,
templates, or assets; see [Licensing Review](docs/LICENSING_REVIEW.md) and
[Third-Party Notices](THIRD_PARTY_NOTICES.md). Apache 2.0 does not grant rights
to the Sturmer name or logo. Trademark and reputation clearance remains
pending. This project is not affiliated with BlackArch Linux.

## Contributing and security reports

Contribution requirements are in [CONTRIBUTING.md](CONTRIBUTING.md). Do not
report vulnerabilities in public issues. The private disclosure contact has
not yet been configured; see [SECURITY.md](SECURITY.md). That missing contact
is a publication blocker.
