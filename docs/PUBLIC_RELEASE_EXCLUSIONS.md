# Public Release Exclusions and Quarantine

This list records working-tree material that must be excluded from a public
source release unless the relevant owner confirms redistribution rights. The
files are retained locally for review; they have not been silently deleted.

## Mutable/private data and generated artifacts

- `data/sentinel.sqlite3` and its WAL/SHM sidecars.
- `data/benchmark_qwen3_4b.jsonl`, a local Qwen timing output, until its
  provenance and suitability as a reproducible public fixture are reviewed.
- Everything under `engagements/`, including local evidence, reports, logs,
  and exports.
- Python bytecode, virtual environments, egg-info/build output, test caches,
  local logs, model checkpoints, and generated reports.
- Egress packet-capture fixtures under `tests/egress/release-artifacts/` from
  the code-only review archive. Decide separately whether synthetic captures
  should be distributed with tests.

## Scanner payloads

- `tools/gitleaks`, `tools/httpx`, `tools/subfinder`, and `tools/trivy` are
  payloads whose version/provenance/right-to-redistribute mapping is not
  confirmed in this snapshot.
- `tools/nikto/` contains third-party code/data and notices. Its licence and
  all bundled component terms require separate review.
- `tools/LICENSE` and `tools/LICENSE.md` must remain intact; their exact
  payload mapping needs confirmation.

Install scanner tools separately from official channels until their exact
licences, versions, and redistribution conditions are established.

## Knowledge documents held for rights review

- `knowledge/our_research/finding-triage-patterns.md` (`Internal`).
- `knowledge/windows_security/active-directory-basics.md` and
  `knowledge/windows_security/windows-privilege-model.md`
  (`Proprietary-MS-Docs-Summarized`).
- `knowledge/cloud_security/aws-iam-basics.md`
  (`Proprietary-AWS-Docs-Summarized`).
- `knowledge/cloud_security/storage-misconfiguration.md` and
  `knowledge/mobile_security/android-vs-ios.md` (`Proprietary-Docs-Summarized`).
- `knowledge/wireless_security/bluetooth-le-security.md`
  (`Proprietary-SIG-Summarized`).
- `knowledge/linux_security/linux-services.md` (`LGPL-2.1`) and
  `knowledge/linux_security/linux-permissions.md` (`GPL-2.0-doc`).
- `knowledge/wireless_security/wifi-security.md` (`CC-BY-4.0-summarized`).
- `knowledge/vulnerability_intel/cve-and-cvss.md` (`Public`) until its source
  and rights basis are recorded.
- Any IETF Trust, CC-BY/CC-BY-SA, or US federal public-domain-labeled file
  whose exact source text, version, author attribution, and applicable terms
  have not been checked file by file.
- `config/wordlists/common.txt` until its author/source and redistribution
  rights are established. The source checkout keeps it for local compatibility;
  the built wheel omits it.

See [Licensing Review](LICENSING_REVIEW.md) for the policy and detailed
categories. Do not apply the root Apache licence to these materials.

## Git history limitation

This workspace snapshot has no `.git` directory. No history-based exclusion or
secret audit can be completed here. Do not treat `.gitignore` as removing
already committed content.
