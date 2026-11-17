# Installation

## Supported package requirements

`pyproject.toml` declares Python `>=3.12`. The source integrates Linux network
namespaces, nftables, privilege management, SQLite, external scanners, and
Ollama. Only Linux/WSL2 operation is described in the existing operator guide;
other platforms are not claimed as supported.

## Source checkout

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
sentinel init
```

The CLI entry point remains `sentinel` for compatibility. Installing Python
dependencies does not install scanner executables, configure network
namespaces/firewall services, or install a Qwen model. Follow
[operator-guide.md](operator-guide.md) and verify the tool-specific manifests
and system prerequisites before an authorized lab operation.

## User data

For new installations, mutable application data is stored under
`$XDG_DATA_HOME/sturmercyberintelligence` when `XDG_DATA_HOME` is an absolute
path, and otherwise under `~/.local/share/sturmercyberintelligence`. The
database is `sentinel.sqlite3`; engagement evidence is stored in the
`engagements/` child. Database and engagement directories are restricted by
the application where the filesystem supports POSIX modes.

For compatibility, if the legacy checkout-local database or engagement
directory already exists, the application continues using that existing path
until an explicit override is set. New installations do not create writable
data under the Python installation or source checkout.

Overrides are `SENTINEL_DB_PATH` and `SENTINEL_ENGAGEMENTS_ROOT`. Set them to
private writable paths before running the CLI. Do not use a shared directory
for engagement evidence.

## Wheel status

The wheel includes SQL migrations as package resources and retains the
`sentinel` console entry point. The default ffuf
wordlist remains in the source checkout and is not included in a distributable
wheel until its provenance and redistribution rights are confirmed. An
installed deployment can set `SENTINEL_WORDLIST_DIR` to a privately managed
wordlist directory. Knowledge documents are also not embedded because their
redistribution rights are unresolved. The package has not been runtime
validated from an installed wheel as part of this documentation change. See
[Release Audit](PUBLIC_RELEASE_AUDIT.md) for required structural and runtime
checks.
