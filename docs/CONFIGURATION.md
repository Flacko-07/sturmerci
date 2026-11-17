# Configuration

Configuration is currently supplied through CLI options, environment
variables, tool manifests, approval records, and operator-managed external
services. The source declares these data-path variables:

| Variable | Purpose | Default |
|---|---|---|
| `XDG_DATA_HOME` | XDG base for writable Sturmer data; used only when absolute. | `~/.local/share` |
| `SENTINEL_DB_PATH` | SQLite database path. | `<data-home>/sturmercyberintelligence/sentinel.sqlite3` |
| `SENTINEL_ENGAGEMENTS_ROOT` | Root for engagement files and evidence. | `<data-home>/sturmercyberintelligence/engagements` |
| `SENTINEL_WORDLIST_DIR` | Operator-managed ffuf wordlists if the licensed resource is unavailable. | Source checkout's `config/wordlists/`; no wheel default pending rights review. |

An existing checkout-local `data/sentinel.sqlite3` or `engagements/` directory
is retained as a compatibility fallback when no explicit corresponding path
override is set. New installations use the XDG path described above.
Environment variables are read when the CLI process imports its path
configuration, so set overrides before starting `sentinel`.

The package retains the existing `sentinel` CLI and `sentinel` Python import.
The CLI requires explicit engagement scope and applicable approval. Scanner
executables, Ollama endpoint/model settings, and Linux network controls have
their own external configuration; consult the operator guide and the relevant
source modules. Do not place secrets in command history or public issue
reports.
