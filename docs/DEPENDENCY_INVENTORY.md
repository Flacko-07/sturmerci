# Dependency Inventory

This is a source-declared inventory from `pyproject.toml`, not a resolved
lockfile or SBOM. Exact transitive versions and licences remain to be captured
at release time.

## Python runtime dependencies

| Package | Constraint | Used for / notes |
|---|---|---|
| `ada-url` | `==4.0.0` | URL parsing/canonicalization dependency. |
| `publicsuffixlist` | unpinned | Public suffix handling. |
| `pydantic` | `>=2.14` | Data validation/contracts. |
| `ollama` | `>=0.6` | Local Ollama client. |
| `psutil` | `>=7.0` | Process and system inspection. |
| `idna` | `>=3.4` | IDNA handling. |
| `typer` | `>=0.12` | CLI framework. |
| `rich` | `>=13.0` | CLI presentation. |
| `cvss` | `>=3.6` | CVSS library integration. |

Development extras are `pytest` and `pywhatwgurl`. No dependency lockfile is
present in this snapshot. Licence identifiers and resolved versions must be
collected from package metadata and reviewed before release; see
[Third-Party Notices](../THIRD_PARTY_NOTICES.md).

## External and native runtime requirements

The adapters invoke external tools including Bandit, `dig`, ExifTool, ffuf,
Gitleaks, ProjectDiscovery httpx, Metasploit, Nikto, Nmap, Nuclei, SCION,
Semgrep, SQLMap, Subfinder, theHarvester, Trivy, WHOIS, and ZAP. Tool versions
and install channels vary; none should be assumed bundled or redistributable.
Linux namespace and nftables features require operating-system support and
privileges. Ollama and a compatible local Qwen model are separately managed.
The source-checkout ffuf wordlist has no provenance/licence metadata and is
excluded from wheels pending rights review; set `SENTINEL_WORDLIST_DIR` to an
operator-managed directory when using an installed wheel.

## Review status

Not complete for publication: no resolved SBOM, native library inventory,
version-locked external scanner inventory, or complete per-component licence
mapping is available in this checkout. See
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
