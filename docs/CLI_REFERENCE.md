# CLI Reference

The entry point is `sentinel = sentinel.cli:app` in `pyproject.toml`. The
implementation keeps the `sentinel` command for backward compatibility.
Obtain option details from the installed CLI's `--help`; command arguments
and approval requirements vary by operation.

Command groups and command names defined in `src/sentinel/cli.py` include:

- Root: `init`, `status`.
- `engagement`: `create`, `list`, `show`, `activate`.
- `scope`: `add`, `list`.
- `approval`: `issue`, `list`, `revoke`.
- `scan`: `gitleaks`, `httpx`, `subfinder`, `nmap`, `bandit`, `dig`, `ffuf`,
  `semgrep`, `trivy`, `whois`, `nikto`, `scion`, `sqlmap`, `nuclei`,
  `metasploit`, `exiftool`, `zap`, `theharvester`.
- `triage`: `run`, `findings`, `show`, `transition`.
- `report`: `generate`.
- `evidence`: `release`.
- `knowledge`: `sync-cve`, `list-cves`, `list`, `review`.
- `findings`: `list`, `show`, `transition` (compatibility aliases).

The CLI uses local engagement, scope, approval, and database state. It is not
an authorization provider. Only use it for systems that the operator owns or
is explicitly authorized to assess. Historical examples may not match the
current options; prefer `sentinel <group> <command> --help`.
