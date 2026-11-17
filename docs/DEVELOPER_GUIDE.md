# Developer Guide

## Layout

Application code is under `src/sentinel/`; tests are grouped by subsystem in
`tests/`; SQL migrations are ordered files under
`src/sentinel/storage/migrations/`. See [Repository Inventory](REPOSITORY_INVENTORY.md)
and [Architecture](ARCHITECTURE.md).

## Change workflow

Install the development extra using [Installation](INSTALLATION.md). Keep
authorization, scope, approval, audit, evidence integrity, and fail-closed
behavior intact. Add regression coverage for changed security properties.
Database changes require a new numbered migration; do not edit a migration
that has shipped to an installation. Update operator/developer documentation
when user-visible behavior changes.

## Adding an adapter

Review the existing adapter modules, tool manifest implementation, execution
profiles, and approval checks before adding code. Bind the adapter to the
manifest identity and binary hash. Do not run a scanner outside the normal
runner. Add tests for parsing and authorization gates, then document the
external executable, network behavior, evidence output, and limitations in
[Adapter Catalog](ADAPTER_CATALOG.md). Never use a public target for
development or CI.

## Licensing

First-party source with established provenance uses
`SPDX-License-Identifier: Apache-2.0`. Do not add that identifier to vendor
code, knowledge documents, or unclear-provenance material. Preserve existing
copyright and licence notices. See [Licensing Review](LICENSING_REVIEW.md).
