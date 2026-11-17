# Database Schema

SQLite schema is built by ordered SQL files under
`src/sentinel/storage/migrations/`, executed by `sentinel.storage.migrate`.
Migration versions are their filename stems. Persistent changes require a new
migration; do not edit migrations already applied to user databases.

The migration set defines engagement and scope/asset records, policy snapshots,
approvals and budget usage/reservations, registered tool manifests, evidence
artifacts and redactions, operational logs, audit events, model runs, knowledge
entries/revisions/reviews and CVE records, findings/evidence links, and
provenance/status tables. See each migration for authoritative columns,
constraints, and indexes.

The database is stored in the user data directory by default, uses SQLite WAL,
foreign keys and a busy timeout, and is created with restrictive filesystem
modes where supported. Backup by stopping writers and using SQLite's backup
mechanism; do not copy a live database without accounting for WAL/SHM files.
