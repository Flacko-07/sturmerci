# Adapter Catalog

This catalog inventories the adapter modules present in `src/sentinel/adapters/`.
The source module's presence is not proof that an executable is installed or
that a particular scan mode has been validated. Every operation remains
subject to engagement scope, tool manifest, approval, and runner gates.

| Adapter | Module | Purpose / external dependency | Typical mode and limitations |
|---|---|---|---|
| Bandit | `adapters/bandit.py` | Python static analysis; `bandit` executable. | Local Class 0 analysis; fully unprivileged no-network staging remains deferred. |
| dig | `adapters/dig.py` | DNS query; `dig`. | Network query; requires exact authorization/scope and applicable approval. |
| ExifTool | `adapters/exiftool.py` | Local metadata analysis; `exiftool`. | Local Class 0; input evidence must be authorized. |
| ffuf | `adapters/ffuf.py` | Web content discovery; `ffuf`. | Active Class 2; exact host/port, approval, wordlist, and budgets required. |
| Gitleaks | `adapters/gitleaks.py` | Secret scanning; `gitleaks`. | Local Class 0; findings may contain sensitive data. |
| httpx | `adapters/httpx.py` | HTTP probing; ProjectDiscovery `httpx`. | Active network Class 2; external tool required. |
| Metasploit | `adapters/metasploit.py` | Service checks and exploit framework integration; `msfconsole`/related tools. | Profiles include intrusive behavior; Class 3 is gated and lab-oriented. |
| Nikto | `adapters/nikto.py` | Web server checks; Nikto/Perl runtime. | Active Class 2; external tool and templates/data required. |
| Nmap | `adapters/nmap.py` | Port/service scanning; `nmap`. | Active network operation; privileges and scan profile affect behavior. |
| Nuclei | `adapters/nuclei.py` | Template-based checks; `nuclei` and separately managed templates. | Active Class 2; template rights and authorization must be reviewed. |
| SCION | `adapters/scion.py` | SCION network information integration. | External runtime/network behavior depends on local environment. |
| Semgrep | `adapters/semgrep.py` | Source-code static analysis; `semgrep`. | Local Class 0; rules and input repository determine coverage. |
| SQLMap | `adapters/sqlmap.py` | SQL injection testing; `sqlmap`. | Intrusive Class 3; lab-only profile and explicit approvals required. |
| Subfinder | `adapters/subfinder.py` | Subdomain discovery; `subfinder`. | Passive recon; DNS/provider configuration may cause network access. |
| theHarvester | `adapters/theharvester.py` | Public-source asset discovery; `theHarvester`. | Passive/provider-backed; APIs and network behavior are environment-dependent. |
| Trivy | `adapters/trivy.py` | Filesystem/container vulnerability analysis; `trivy`. | Local analysis may use remote databases unless configured offline. |
| WHOIS | `adapters/whois.py` | Domain registration lookup; `whois`. | Network query; scope and authorization policy still apply. |
| ZAP | `adapters/zap.py` | Web application testing; OWASP ZAP. | Active Class 2; daemon/runtime and target authorization required. |

All adapters use operator authorization and the applicable approval path before
execution; local adapters still require an authorized engagement and valid
inputs. Approval requirements are enforced by the runner and profile-specific
gates. The external tools are not included as licensed Sturmer code. This
catalog is a source-path inventory and must be reconciled against the
production manifest and tests before publication.
