# Release Checklist

Do not publish until all applicable items are reviewed and cleared.

## Code and validation

- [ ] Confirm source ownership and contribution provenance.
- [ ] Run current regression, egress, privileged integration, and authorized
  lab validation from [TESTING.md](TESTING.md).
- [ ] Build wheel/sdist and validate installed-wheel behavior in a clean
  environment.
- [ ] Review security boundaries and technical debt against source.

## Rights and identity

- [ ] Resolve all items in [Licensing Review](LICENSING_REVIEW.md) and
  [Public Release Exclusions](PUBLIC_RELEASE_EXCLUSIONS.md).
- [ ] Generate/review resolved dependency SBOM and scanner-tool inventory.
- [ ] Complete Sturmer trademark/reputation clearance and confirm GitHub slug.
- [ ] Confirm approved project owner/copyright attribution if required.

## Operations and community

- [ ] Configure and test private vulnerability reporting.
- [ ] Configure repository owner, issue/discussion settings, support contact,
  and action permissions.
- [ ] Review CI action provenance and permissions; confirm no privileged or
  external-target scanning runs in public CI.
- [ ] Remove local databases, engagement evidence, logs, model files, secrets,
  and generated artifacts from the staged release.
- [ ] Complete the all-document factual/link review and refresh the public
  release audit.
