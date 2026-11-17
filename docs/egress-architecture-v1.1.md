# Egress Architecture — v1.1 Design Decision Record

**Status:** Draft for review (revised after WSL topology probes)
**Author:** <operator>
**Date:** 2026-11-13
**Scope:** Milestone 3 of SENTINEL-ECR-001 / v1.0.2
**Blocks:** Any network-capable adapter (httpx, Nmap, Nuclei, ZAP)

## 1. Purpose

Selects, justifies, and specifies the mechanism Sentinel uses to ensure no
child process reaches a destination outside the gatekeeper-approved target
set. Design record, not implementation.

No network-capable adapter may be registered in `sentinel.runner.registry`
until this document is reviewed and its bypass matrix is reproduced as
executable tests in `tests/egress/`.

## 2. Measured environment

Milestone 0 measurements:

| Resource | Idle | Under load |
|---|---|---|
| System RAM | ~2.1 GB | 2.72 GB used of 11.68 GB |
| VRAM | 175 MiB | 2519 MiB peak |
| Model placement | — | 20% CPU / 80% GPU |

WSL topology probe (2026-11-13):

| Property | Value |
|---|---|
| wsl.conf | `[boot] systemd=true`; `[user] default=nflacko` |
| Network mode | NAT (no `[network]` section) |
| eth0 | `172.18.51.215/20` |
| Default route | `172.18.48.1 dev eth0` |
| `/etc/resolv.conf` | `nameserver 10.255.255.254` (WSL-managed) |
| nftables | Present; Docker owns `table ip nat` with DNAT for 3 networks |
| Docker networks | `172.17.0.0/16`, `172.19.0.0/16`, `172.20.0.0/16` |
| iptables FORWARD | Policy DROP (Docker default) |

Implications for design:

- Docker rules must **not** be replaced. Sentinel owns a separate table.
- Egress restrictions must be scoped to the child process, not to all of
  WSL, or Docker's DNS/routing breaks. This mandates network namespaces.
- The `10.255.255.254` resolver is a Windows-side forwarding stub. Sentinel
  cannot rely on it during a run.
- The WSL gateway `172.18.48.1` is a live path to Windows services and must
  be blocked for child processes.
- The three Docker subnets are reachable network ranges and must be blocked.

Any mechanism adding more than ~500 MB to system RAM is rejected on this
hardware (rules out a full isolated VM as default).

## 3. Threat model

**In scope (the egress layer must mitigate):**

- A compromised or misbehaving tool attempting outbound traffic.
- A tool honoring `HTTP_PROXY` for one destination but not another.
- A tool resolving via an alternate resolver and reaching an unapproved
  address.
- DNS rebinding: gatekeeper resolves to IP A, tool re-resolves to IP B.
- A tool spawning a child process that opens the socket.
- WSL2's localhost forwarding being used as an egress path.
- **Docker network escape:** a tool inside WSL reaching a container
  network (`172.17/16`, `172.19/16`, `172.20/16`) and pivoting from there.
- **Windows host gateway escape:** a tool connecting to `172.18.48.1`
  to reach services bound to Windows.

**Out of scope for v1.1:**

- An attacker with local root in WSL (assumed trusted).
- A compromised Windows host.
- Physical access.

## 4. Candidate mechanisms

### 4.1 Option A — Windows host firewall + HTTP CONNECT proxy

Child processes as normal Windows processes. Windows Firewall outbound-block
rules plus a proxy on `127.0.0.1:8080`.

**Pros:** zero RAM. Simple to set up (already have admin).

**Cons:** HTTP proxy is not a universal control — Nmap raw sockets, `curl
--noproxy`, Go binaries with custom transports bypass it. Windows Firewall
rules cannot be scoped to a child-process tree. Elevated rule changes on
every run. Method/path revalidation without MITM is not possible.

**Verdict:** Insufficient for Nmap and non-HTTP tools. Rejected as primary.

### 4.2 Option B — WSL2 per-run network namespace + nftables + DNS stub

Each child process runs inside a dedicated network namespace created for
the run. The namespace contains:

- A loopback interface.
- A `veth` pair to the main WSL namespace.
- `dnsmasq` listening on `127.0.0.53:53` inside the namespace, configured
  with A/AAAA records only for the gatekeeper-approved hostnames.
- A `/etc/resolv.conf` bind-mounted from a per-run file pointing at
  `127.0.0.53`.

In the main WSL namespace, nftables rules (in a Sentinel-owned table,
coexisting with Docker's `table ip nat`) gate every packet leaving the
`veth`:

- Allow TCP/53, UDP/53 to `127.0.0.53` in the namespace (contained).
- Allow the approved destination IP:port set for this run.
- Allow established/related for return traffic.
- **Drop** `169.254.0.0/16`, all RFC1918 ranges that are not the approved
  set, `172.18.48.0/20`, `172.17.0.0/16`, `172.19.0.0/16`, `172.20.0.0/16`.
- Default drop with logging.

The namespace is destroyed at run end (`ip netns delete`), which also tears
down the veth and the dnsmasq instance.

**Pros:**
- Kernel-level enforcement scoped to the child process. Docker and Ollama
  in the main namespace are unaffected.
- DNS rebinding closed by construction: the child process never sees the
  real resolver.
- WSL gateway and Docker networks explicitly blocked at the veth.
- Kill switch is `ip netns delete`, which is atomic and complete.
- No RAM cost — network namespaces are kernel objects, not VMs.

**Cons:**
- Requires root in WSL (already true for Ollama setup).
- The orchestration process must resolve IPs and configure dnsmasq before
  the tool starts (already the design).
- Docker networks must be blocked at the veth, not the main namespace —
  but this is naturally satisfied since only the veth carries traffic.

**Verdict:** Selected.

### 4.3 Option C — Isolated Linux VM

Dedicated VM with iptables + dnsmasq.

**Pros:** strongest isolation, kernel-independent, no WSL forwarding vector.

**Cons:** +1.5–2 GB RAM. On this hardware with Windows + WSL2 + Ollama
resident, this collapses the RAM budget. Model reload after VM start
adds 24–60 s of cold-load.

**Verdict:** Rejected on this hardware. Revisit on 32 GB RAM.

## 5. Decision

**Adopt Option B: per-run network namespace + nftables + DNS stub.**

Consequences that must be built in Milestone 4:

1. A `sentinel.netns` module that creates and destroys the run namespace.
2. An nftables ruleset in a Sentinel-owned table, coexisting with Docker.
3. A dnsmasq launcher configured from gatekeeper-pinned records.
4. A `resolv.conf` bind-mount into the namespace.
5. Kill-switch integration: `ip netns delete` on activation.

If any of E-01 through E-11 cannot be made to pass, Milestone 4 is blocked
until resolved. There is no fallback to Option A for non-HTTP tools.

## 6. Namespace and DNS stub design

### 6.1 Run namespace creation

At run start, the run controller:

1. Creates a name: `ip netns add sentinel-run-<id>`.
2. Creates a veth pair: `ip link add veth-sentinel-<id> type veth peer name
   veth-sentinel-<id>-ns`.
3. Moves one end into the namespace: `ip link set veth-sentinel-<id>-ns
   netns sentinel-run-<id>`.
4. Assigns addresses: `10.<run_id>:1/24` in the main namespace on
   `veth-sentinel-<id>`, `10.<run_id>:2/24` on the namespace end.
5. Brings both ends up.
6. In the namespace: `ip netns exec sentinel-run-<id> ip route add default
   via 10.<run_id>:1`.
7. Starts dnsmasq inside the namespace on `127.0.0.53:53`.
8. Bind-mounts `/tmp/sentinel-run-<id>/resolv.conf` over `/etc/resolv.conf`
   inside the mount namespace of the child.
9. Applies nftables rules to `veth-sentinel-<id>` in the main namespace.

At run end, in reverse: nft rules removed, namespace deleted (which removes
veth, dnsmasq, and any process still inside).

### 6.2 DNS stub configuration

`/tmp/sentinel-run-<id>/dnsmasq.conf`:

    listen-address=127.0.0.53
    bind-interfaces
    no-resolv
    no-hosts
    address=/app.example.test/203.0.113.42

No upstream — dnsmasq returns NXDOMAIN for anything not in the A/AAAA
records. This is intentional: DNS exfiltration is impossible if dnsmasq
never forwards.

`/tmp/sentinel-run-<id>/resolv.conf`:

    nameserver 127.0.0.53

### 6.3 nftables ruleset sketch

Sentinel-owned table (coexists with Docker):

    table inet sentinel {
        chain veth_run {
            type filter hook forward priority 0; policy drop;
            # allow return traffic for approved flows
            ct state established,related accept
            # allow approved destinations (added per-run)
            # ip daddr <approved_ip> tcp dport <approved_port> accept
            # block known-bad ranges explicitly (defense in depth)
            ip daddr 169.254.0.0/16 drop
            ip daddr 172.18.48.0/20 drop
            ip daddr 172.17.0.0/16 drop
            ip daddr 172.19.0.0/16 drop
            ip daddr 172.20.0.0/16 drop
            ip daddr 10.0.0.0/8 drop
            ip daddr 192.168.0.0/16 drop
            ip daddr 127.0.0.0/8 drop
            log prefix "sentinel-egress-blocked: " level info
            drop
        }
    }

The per-run approved rules are inserted into this chain by the run
controller before the tool starts and removed at run end.

Docker's `table ip nat` is untouched.

## 7. Bypass-test matrix

Each test asserts one of: process fails with `ECONNREFUSED`/`ETIMEDOUT`,
or packet capture shows zero bytes leaving the veth toward the destination.

| ID | Test | Pass condition |
|---|---|---|
| **E-01** | Direct `socket.connect(("1.1.1.1", 443))` | `ENETUNREACH` or dropped; capture confirms |
| **E-02** | `getaddrinfo("evil.test")` returns NXDOMAIN | dnsmasq returns NXDOMAIN; no outbound DNS |
| **E-03** | `dig @8.8.8.8 example.com` | Timeout; no packet to `8.8.8.8:53` |
| **E-04** | `curl --noproxy '*' http://1.1.1.1/` | Fails at nftables, not at proxy |
| **E-05** | Tool spawns a grandchild that opens a socket | Grandchild is inside the same namespace; blocked |
| **E-06** | Tool hard-codes `/etc/resolv.conf` to `8.8.8.8` | nftables blocks `:53` to anything but `127.0.0.53` |
| **E-07** | Tool tries `172.18.48.1:<port>` (WSL gateway to Windows) | Dropped; no packet leaves veth |
| **E-08** | Tool reaches a telemetry endpoint (e.g. `semgrep.dev`) | Not on approved set → dropped |
| **E-09** | Tool reaches `172.17.0.1`, `172.19.0.1`, `172.20.0.1` (Docker network gateways) | Dropped |
| **E-10** | Tool attempts Docker bridge addresses directly (`172.17.0.2`) | Dropped |
| **E-11** | WSL `resolv.conf` is unchanged on main namespace after run | Run uses namespace-local mount; main file untouched |

All eleven must pass before Milestone 4 closes.

## 8. Limitations

- **Root inside WSL can delete the namespace and any nft rules.** Assumed
  trusted per threat model.
- **Docker daemon restarts reset Docker's own nft rules but not Sentinel's
  table.** Sentinel's `table inet sentinel` survives Docker restarts.
  However, a Docker restart between Sentinel runs may leave `veth-sentinel-*`
  interfaces behind; the run controller must clean stale veths at start.
- **The HTTP proxy is not present in this design.** All egress controls are
  at the namespace/nft layer, which is stronger. If a tool requires a proxy
  to function (e.g. `httpx -proxy`), a local proxy in the namespace can be
  added; it does not replace the nft control.
- **TLS is not inspected.** Method/path revalidation for HTTPS remains at
  the CONNECT-authority level. Body inspection is v1.2 with a trusted CA.
- **DNS is frozen for the run.** CDN edge rotation mid-run fails the run;
  re-approval required. This is the correct security behavior.
- **`10.255.255.254` (WSL DNS forwarding) is not used.** If Sentinel ever
  needs to fetch from the internet during a run — it must not — the design
  would need to open a specific path and re-review.

## 9. Review sign-off

Reviewed by: nflacko (self-review)
Review date: 2026-11-13
Accepted / Accepted with changes / Rejected: Accepted
Milestone 4 may begin: yes — with the caveat that a second reviewer
should examine this document before any real HackerOne target is
assessed. M4 may proceed against local lab targets only until then.

## 10. Verification log

Hardware and kernel verification performed 2026-11-13:

| Check | Result |
|---|---|
| `ip netns` available | `/usr/sbin/ip` present; `ip netns list` succeeds |
| `unshare -n` isolates network | `ping 1.1.1.1` inside new namespace returns `Network is unreachable` |
| namespace create/delete | `ip netns add sentinel-probe` / `ip netns delete` both succeed |
| `dnsmasq` installed | `/usr/sbin/dnsmasq` present |
| veth create/delete | `ip link add veth-probe-a type veth peer name veth-probe-b` succeeds; delete succeeds |
| Docker nft tables present | `table ip nat`, `table ip filter`, `table ip6 nat`, `table ip6 filter`, `table ip raw` |

Conclusion: the per-run network namespace + veth + dnsmasq + Sentinel-owned
nftables table model is supported on this WSL2 environment. No blocker for
Milestone 4.

Note: the fresh-namespace ping returning "Network is unreachable" is the
critical confirmation. If a fresh namespace had egress, the model would be
unsound. It does not.

## 11.5 Amendment — counters() must read both chains

Sentinel's table now has two chains (forward_run, input_run). The
counters() helper must issue `nft -j list chain` per chain, not
`nft -j list table`, because nftables JSON returns chains separately
and the counter expression lives inside rule["expr"][], not at
rule["counter"]. This was discovered when 12 of 14 tests reported
counter=0 after the sysctl fixes were in place — the enforcement was
working, but the observability was reading the wrong field.

## 11.6 Amendment — INPUT chain rules match ip saddr, not iifname

Local delivery to a main-ns address reroutes the packet through
`dev lo`, which causes the kernel to rewrite the effective iifname
to "lo" before the INPUT hook. Rules of the form
`iifname "snt-xxx"` never fire for such packets. The INPUT chain
uses `ip saddr 10.99.0.2/32` instead, which is stable per run and
unaffected by routing decisions.

This distinction matters: FORWARD chain uses iifname (correct,
because traffic being forwarded has an unchanged ingress interface);
INPUT chain uses saddr (correct, because local delivery can rewrite
the ingress interface).


## 11.7 Amendment — proxy egress enforcement (batch-6 disposition)

The L7 TLS proxy (`src/sentinel/l7/proxy.py`) runs in the **main netns**,
not inside the per-run sandbox namespace. Its upstream connect
(`socket.create_connection(...)` at `proxy.py:426`) therefore goes out
via the WSL default route and is **not** filtered by the per-run nft
ruleset. This was flagged by the reviewer as Priority 3.

### What the proxy DOES enforce (proxy code level)

| Control | Where | What it stops |
|---|---|---|
| **Host allowlist** | `_allowed_connect_hosts` check at `_handle_client_inner` | CONNECT to a hostname not in `approval.canonical_hostnames` → 403 |
| **Pinned upstream IPs** | `_pinned_upstreams` from gatekeeper resolution | DNS rebinding — the proxy connects only to the IPs the gatekeeper resolved at approval time |
| **TLS verification** | `ssl.SSLContext` with `upstream_ca_bundle` | MITM between proxy and upstream |
| **Method/path filter** | `gatekeeper_filt` on every request | Any HTTP request that does not match the approval's method/path |
| **Body refusal** | `_assert_no_request_body` | Any request with a body (413) |
| **Rate/duration caps** | `_max_relay_bytes`, `_max_connection_duration` | Runaway relay |

### What the proxy does NOT enforce (kernel level)

The proxy's upstream TCP connect is governed by the operator's own
firewall, not by Sentinel's per-run nft ruleset. A compromised proxy
process could in principle connect to any IP reachable from the WSL
default route, not just the pinned upstreams.

### Why this is a documented tradeoff, not a fix-in-batch

Kernel-level enforcement would require either:

1. **Second veth + second netns** — spawn a second network namespace
   for the proxy's upstream leg, with its own nft ruleset for the pinned
   upstream IPs. This doubles the netns setup cost per run and requires
   rebuilding `netns/namespace.py` to handle two namespaces. ~2-3
   sessions of work plus new tests.

2. **Bind the proxy's outbound socket to a specific source IP** — use
   `socket.bind((10.99.0.X, 0))` before connect, with nft OUTPUT rules
   on that source IP. Requires a second veth for the proxy's outbound
   leg anyway (the current veth is sandbox-facing only).

### Disposition

**Do not enable external path-restricted HTTP assessment yet.** The
reviewer's guidance stands. When path-restricted approvals are needed
for a real engagement:

- The operator must accept the tradeoff documented here (the audit
  record includes `sandbox_proxy_started` with `connect_hosts` so the
  enforcement scope is auditable).
- Any kernel-level hardening is future work.

### What this means for `use_tls_proxy=True`

The flag remains usable — `tests/l7/` and `tests/egress/` exercise the
proxy end-to-end — but **no production adapter sets it to True**. The
`httpx` adapter passes `use_tls_proxy=False` (default). Enabling
path-restricted approvals is a deliberate operator decision documented
in the approval record, not an adapter default.

