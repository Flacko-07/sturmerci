# Egress Architecture

The detailed design and test matrix remain in
[egress-architecture-v1.1.md](egress-architecture-v1.1.md) and
[egress-test-matrix.md](egress-test-matrix.md). Current execution code is under
`src/sentinel/netns/` and `src/sentinel/runner/`.

For applicable network operations, the runner provisions a per-run Linux
network namespace and veth, configures DNS behavior and a Sentinel-owned
nftables policy, then starts the scanner through its constrained process path.
Exact enforcement depends on host support and privileges. The default design
aims to allow only approved target IP/port pairs; confirm the active profile
and host rules before use. Test-only fixtures must not be treated as runtime
configuration.

Kernel-level isolation of TLS proxy upstream connections remains deferred.
Read the design document for failure paths and known host-specific limits;
do not infer that every profile has identical egress guarantees.
