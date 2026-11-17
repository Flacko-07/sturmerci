# Third-Party Notices

Sturmer's first-party Python package source and SQL migrations are identified
with `SPDX-License-Identifier: Apache-2.0` and covered by the root
[LICENSE](LICENSE). Third-party software, scanner tools, knowledge documents,
and assets are not relicensed by that grant.

## Python dependencies

The package declares these runtime dependencies in `pyproject.toml`:

| Dependency | Declared version | Licence / distribution status |
|---|---:|---|
| ada-url | `==4.0.0` | Licence not verified in this repository; resolve from package metadata before release. |
| publicsuffixlist | Unpinned | Licence and version not verified here. |
| pydantic | `>=2.14` | Licence and resolved version not recorded in this source snapshot. |
| ollama | `>=0.6` | Licence and resolved version not recorded in this source snapshot. |
| psutil | `>=7.0` | Licence and resolved version not recorded in this source snapshot. |
| idna | `>=3.4` | Licence and resolved version not recorded in this source snapshot. |
| typer | `>=0.12` | Licence and resolved version not recorded in this source snapshot. |
| rich | `>=13.0` | Licence and resolved version not recorded in this source snapshot. |
| cvss | `>=3.6` | Licence and resolved version not recorded in this source snapshot. |

Development extras are `pytest` and `pywhatwgurl`; their versions and licence
metadata are also unresolved. This table is a declared dependency list, not a
complete resolved SBOM. Generate and review a lockfile/SBOM before release.

## Scanner tools and vendored material

The Python package invokes external tools; it does not establish a right to
redistribute them. The current working tree also contains files or directories
under `tools/` named `gitleaks`, `httpx`, `nikto`, `subfinder`, and `trivy`, plus
`tools/LICENSE`, `tools/LICENSE.md`, and `tools/README.md`.

- The Nikto tree contains its own `COPYING`, attribution headers, and bundled
  components. Preserve those files and their component-specific terms. Do not
  apply Apache-2.0 to it.
- `tools/LICENSE.md` identifies ProjectDiscovery copyright and MIT terms; the
  exact correspondence between that notice and every nearby payload must be
  confirmed before redistribution.
- `tools/LICENSE` identifies a separate MIT copyright notice. Its exact
  component mapping must be confirmed.
- The tool payloads' versions, hashes, provenance, and redistribution status
  are not established by this source snapshot. Exclude these payloads from a
  public source release until individually verified. Install tools separately
  from their official distribution channels.

## Knowledge documents and other content

Knowledge documents have per-file metadata and are not covered by the root
Apache licence. The following labels require owner/legal review before
redistribution: `Internal`, `Proprietary-*`, `GPL-2.0-doc`, `LGPL-2.1`,
`CC-BY-4.0-summarized`, and any `Public`, `IETF-Trust`, or public-domain claim
whose source and attribution have not been verified. See the file-by-file
quarantine list in [LICENSING_REVIEW.md](docs/LICENSING_REVIEW.md).

Preserve all third-party notices and licence terms if any such content is
eventually included. Do not interpret a curator summary or a source URL as
permission to redistribute derived text.

The default ffuf list at `config/wordlists/common.txt` has no provenance or
licence statement in this snapshot. It is therefore excluded from the wheel
and must not be included in a public release until its origin and
redistribution rights are confirmed. `SENTINEL_WORDLIST_DIR` supports an
operator-managed list in an installed deployment.
