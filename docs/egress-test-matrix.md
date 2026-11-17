# Egress Test Matrix — v1.1 Historical Release-Gate Plan

> This document records the earlier milestone release-gate plan. The
> production adapter registry no longer reads `tests/egress/.release-gate`;
> test artifacts do not enable or disable production registration. Egress
> tests remain validation, while tool manifests, approvals, scope checks, and
> the runner enforce execution controls.

**Status:** Specification (blocks Milestone 4)
**Date:** 2026-11-13
**Companion:** `docs/egress-architecture-v1.1.md`

Defines the tests that must pass before any network-capable adapter
is registered. They live in `tests/egress/test_matrix.py`, gated on
`sentinel.netns` existing (Milestone 4).

## Expected API

`sentinel.netns.run_namespace` is a context manager:

    with run_namespace(
        approved=[("203.0.113.42", 443)],
        hostname_records={"app.example.test": ["203.0.113.42"]},
    ) as ns:
        # current process is inside the run namespace
        ...

Semantics:
- Creates `ip netns sentinel-run-<id>`.
- Creates veth pair, moves one end into namespace, assigns
  `10.99.0.1/24` (main) and `10.99.0.2/24` (namespace).
- Starts dnsmasq inside namespace with `hostname_records`.
- Applies Sentinel-owned nftables rules in the main namespace.
- On exit: deletes namespace, removes nft rules. Idempotent on
  exception and on kill-switch.

Skipped via `pytest.importorskip("sentinel.netns")` until M4.

## Test roster

| ID | Test function | Destination | Reason |
|---|---|---|---|
| E-01 | test_e01_direct_public_ip | 1.1.1.1:443 | direct public TCP |
| E-02 | test_e02_dns_nxdomain | evil.test | no upstream resolver |
| E-03 | test_e03_external_dns | 8.8.8.8:53 | external DNS blocked |
| E-04 | test_e04_curl_no_proxy | http://1.1.1.1/ | proxy bypass impossible |
| E-05 | test_e05_grandchild_socket | 1.1.1.1:443 from grandchild | process tree inherits |
| E-06 | test_e06_hardcoded_resolver | /etc/resolv.conf=8.8.8.8 | resolver override fails |
| E-07 | test_e07_wsl_gateway | 172.18.48.1:80 | Windows host via WSL |
| E-08 | test_e08_telemetry | semgrep.dev:443 | vendor telemetry blocked |
| E-09 | test_e09_docker_gateways | 172.17.0.1 / 172.19.0.1 / 172.20.0.1 | Docker host endpoints |
| E-10 | test_e10_docker_bridge | 172.17.0.2:80 | Docker containers unreachable |
| E-11 | test_e11_resolv_conf_untouched | /etc/resolv.conf mtime | main file not modified |

## Negative-of-the-negative tests

Guard against over-blocking. If these fail, the rules are too
aggressive and the design would look "secure" but be unusable.

| ID | Test function | Proves |
|---|---|---|
| E-12 | test_e12_approved_destination_allowed | approved IP:port passes |
| E-13 | test_e13_approved_hostname_resolves | dnsmasq returns pinned A |
| E-14 | test_e14_loopback_inside_namespace | dnsmasq on 127.0.0.53 reachable |

## Local environment probes (E-00)

Run today, before M4. Validate the machine, not Sentinel.

| ID | Check | Command |
|---|---|---|
| E-00a | unshare -n isolates network | sudo unshare -n ping -c 1 -W 1 1.1.1.1 (must fail) |
| E-00b | Docker nft tables intact | sudo nft list tables \| grep -c "table ip" (>= 3) |
| E-00c | dnsmasq present | command -v dnsmasq (must succeed) |

E-00a confirmed 2026-11-13. E-00b and E-00c re-run at M4 start.

## CI integration

`tests/egress/` requires root (namespace creation). CI runs
`sudo pytest tests/egress/` in a dedicated job. `tests/policy/`
continues to run unprivileged.

## Release gate

Milestone 4 closes only when:

- E-01 through E-11 all pass.
- E-12 through E-14 all pass.
- Packet captures exist for E-01, E-04, E-07 in release artifacts.
- `docs/egress-architecture-v1.1.md` §9 is signed off.

The historical plan proposed having `sentinel.runner.registry.register()`
refuse `execution_class >= 2` until `tests/egress/.release-gate` existed. That
design was retired because production runtime must not depend on test-only
files. The current registry is descriptive metadata only.
