# SPDX-License-Identifier: Apache-2.0
"""Sentinel-owned nftables ruleset. Coexists with Docker's tables.

The Sentinel table (``inet sentinel``) is separate from any table that
Docker, Ollama, or the host system creates. It is only ever created,
modified, or deleted by this module. On teardown the table is deleted
wholesale, so a crashed process leaves no half-configured ruleset
behind -- ``namespace.run_namespace()`` calls ``remove()`` in its
``finally`` block.

The forward chain is the egress gate: packets arriving from the run
namespace's veth pass through ``forward`` (in the main netns) on their
way out. ``policy drop`` plus explicit accepts means a packet only
leaves if a rule explicitly permits it.

All subprocess calls use ``shell=False`` with argument arrays. No user
input is ever interpolated into a shell string.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


TABLE = "sentinel"
CHAIN = "forward_run"
INPUT_CHAIN = "input_run"

# Ranges a child process must never reach. Explicit drop rules with
# counters so the test matrix can assert that a specific attempt
# incremented a specific rule.
DENIED_RANGES = (
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",  # covers 172.17/16, 172.18.48.0/20, 172.19/16, 172.20/16
    "192.168.0.0/16",
    "169.254.0.0/16",  # link-local, cloud metadata
    "100.64.0.0/10",  # CGNAT
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved
    "0.0.0.0/8",
)


class NftError(RuntimeError):
    """nft exited non-zero or is unavailable."""


def _nft_binary() -> str:
    path = shutil.which("nft")
    if path is None:
        raise NftError("nft binary not found on PATH")
    return path


def _nft(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [_nft_binary(), *args],
        shell=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise NftError(
            f"nft {' '.join(args)} failed ({result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return result


def _quote_comment(comment: str) -> str:
    """nft requires comment values to be a double-quoted string token.
    subprocess(shell=False) does not apply shell quoting, so we add it
    here. Any embedded double quotes and backslashes are escaped."""
    escaped = comment.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def is_installed() -> bool:
    if shutil.which("nft") is None:
        return False
    out = _nft("list", "tables", check=False)
    return f"table inet {TABLE}" in out.stdout


def install() -> None:
    """Create the sentinel table and its forward chain. Idempotent."""
    if is_installed():
        return
    # Priority -10: runs BEFORE Docker's filter chains (priority 0).
    # Equal priority would mean registration-order evaluation, and Docker
    # registers first -- so its policy-DROP would silently kill our
    # packets before our rules ran, and our counters would never fire.
    # Priority -10 puts us first; our drop is terminal, so Docker never
    # sees the packet. Packets not matching our veth-scoped rules fall
    # through to policy accept and reach Docker's chains normally.
    #
    # policy accept, not drop, so that Docker's inter-container traffic
    # (which reaches the same forward hook) is unaffected. All denial is
    # via explicit catch-all drop rules scoped to the run veth.
    script = (
        f"table inet {TABLE} {{\n"
        f"    chain {CHAIN} {{\n"
        f"        type filter hook forward priority -10; policy accept;\n"
        f"        ct state established,related accept\n"
        f"    }}\n"
        f"    chain {INPUT_CHAIN} {{\n"
        f"        type filter hook input priority -10; policy accept;\n"
        f"        ct state established,related accept\n"
        f"    }}\n"
        f"}}\n"
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".nft", delete=False, prefix="sentinel-nft-"
    ) as f:
        f.write(script)
        tmp_path = f.name
    try:
        _nft("-f", tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def remove() -> None:
    """Delete the sentinel table ONLY if it looks like ours.

    Refuses if the table exists but doesn't contain either of our chain
    names — protects against deleting an unrelated table with the same
    name (e.g. a manually created one, or a future tool that reuses
    the name).
    """
    if not is_installed():
        return
    out = _nft("-j", "list", "table", "inet", TABLE, check=False)
    if out.returncode != 0:
        return
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        raise NftError(f"refusing to delete table {TABLE}: cannot parse table JSON")
    chains = set()
    for entry in data.get("nftables", []):
        chain = entry.get("chain")
        if chain:
            chains.add(chain.get("name"))
    if CHAIN not in chains and INPUT_CHAIN not in chains:
        raise NftError(
            f"refusing to delete table {TABLE}: chains {sorted(chains)} "
            f"do not match sentinel's {CHAIN!r} or {INPUT_CHAIN!r}"
        )
    _nft("delete", "table", "inet", TABLE)


def add_approved(
    ip: str,
    port: int,
    *,
    protocol: str = "tcp",
    veth: str | None = None,
    saddr: str | None = None,
    chain: str = CHAIN,
    comment: str,
    allow_protected: bool = False,
    insert: bool = False,
) -> None:
    """Allow TCP to ``ip:port``. Comment is a test-matrix marker.

    Scoping:
      - veth: iifname match (FORWARD chain, traffic from the run veth)
      - saddr: ip saddr match (INPUT chain, local delivery via lo)

    Validation: destination must be a single IP. Protected-range check
    is on by default; ``allow_protected=True`` is the documented escape
    used for the M7.2 proxy (whose listen IP is on the veth subnet, which
    falls inside 10.0.0.0/8). Every protected allow MUST be justified
    by a call-site comment and a matching audit event.

    ``insert=True`` uses ``nft insert rule`` (head placement) instead of
    ``add rule`` (tail placement). Required for the proxy's INPUT rule:
    the INPUT chain already contains ``ip saddr <ns>/32 ip daddr 10.0.0.0/8
    drop`` which matches the proxy's 10.99.0.1. An appended accept rule
    would never be reached.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as e:
        raise ValueError(
            f"approved destination must be a single IP (not CIDR): {ip!r}"
        ) from e
    if not allow_protected:
        for rng in DENIED_RANGES:
            if addr in ipaddress.ip_network(rng):
                raise ValueError(
                    f"refusing to approve {ip}: inside protected range {rng}"
                )

    if protocol not in ("tcp", "udp"):
        raise ValueError(
            f"approved destination protocol must be tcp or udp, got {protocol!r}"
        )
    rule = ["insert" if insert else "add", "rule", "inet", TABLE, chain]
    if saddr is not None:
        rule += ["ip", "saddr", saddr]
    if veth is not None:
        rule += ["iifname", veth]
    rule += ["ip", "daddr", str(addr), protocol, "dport", str(port)]
    rule += ["counter", "accept", "comment", _quote_comment(comment)]
    _nft(*rule)


def add_deny(
    ip: str,
    port: int | None = None,
    *,
    veth: str | None = None,
    saddr: str | None = None,
    chain: str = CHAIN,
    comment: str = "",
) -> None:
    """Add an explicit drop rule with a counter.

    Either ``veth`` (iifname) or ``saddr`` (ip saddr) scopes the rule to
    the run. For INPUT chain rules where the kernel may rewrite iifname
    to ``lo`` on local delivery, use ``saddr``; for FORWARD, ``veth``.
    """
    rule = ["add", "rule", "inet", TABLE, chain]
    if veth is not None:
        rule += ["iifname", veth]
    if saddr is not None:
        rule += ["ip", "saddr", saddr]
    rule += ["ip", "daddr", ip]
    if port is not None:
        rule += ["tcp", "dport", str(port)]
    rule += ["counter", "drop"]
    if comment:
        rule += ["comment", _quote_comment(comment)]
    _nft(*rule)


def add_default_denies(
    *,
    veth: str | None = None,
    saddr: str | None = None,
    chain: str = CHAIN,
) -> None:
    """Install explicit drop rules for every range in DENIED_RANGES."""
    for rng in DENIED_RANGES:
        add_deny(rng, veth=veth, saddr=saddr, chain=chain, comment=f"deny-{rng}")


def add_catchall_deny(veth: str) -> None:
    """Add catch-all drop rules for the run veth in BOTH chains.

    FORWARD chain handles traffic being routed through the main netns
    (e.g. to 1.1.1.1, 8.8.8.8). INPUT chain handles traffic destined
    for *local* main-netns addresses (e.g. Docker gateways 172.17.0.1,
    which are bound to docker0). Without the INPUT catch-all, a child
    could reach a service listening on a Docker gateway.

    Must be added AFTER all allow and deny rules.
    """
    # FORWARD: from and to the child
    _nft(
        "add",
        "rule",
        "inet",
        TABLE,
        CHAIN,
        "iifname",
        veth,
        "counter",
        "drop",
        "comment",
        _quote_comment("deny-out"),
    )
    _nft(
        "add",
        "rule",
        "inet",
        TABLE,
        CHAIN,
        "oifname",
        veth,
        "counter",
        "drop",
        "comment",
        _quote_comment("deny-in"),
    )
    # INPUT: packets from the child destined for local main-ns addresses.
    # Match on ip saddr, not iifname, because local delivery via "dev lo"
    # can cause the kernel to rewrite the effective iifname to "lo",
    # silently bypassing an iifname rule. The source IP (10.99.0.2) is
    # stable per run and does not depend on routing behaviour.
    _nft(
        "add",
        "rule",
        "inet",
        TABLE,
        INPUT_CHAIN,
        "ip",
        "saddr",
        "10.99.0.2/32",
        "counter",
        "drop",
        "comment",
        _quote_comment("deny-out-in"),
    )
    # IPv6: block all v6 traffic from the run veth. The namespace only
    # has v4 addresses, but a future change could add a v6 default route.
    # The drop is explicit so tests can assert on it.
    _nft(
        "add",
        "rule",
        "inet",
        TABLE,
        CHAIN,
        "iifname",
        veth,
        "meta",
        "nfproto",
        "ipv6",
        "counter",
        "drop",
        "comment",
        _quote_comment("deny-out-v6"),
    )
    _nft(
        "add",
        "rule",
        "inet",
        TABLE,
        INPUT_CHAIN,
        "iifname",
        veth,
        "meta",
        "nfproto",
        "ipv6",
        "counter",
        "drop",
        "comment",
        _quote_comment("deny-in-v6"),
    )


def counters() -> dict[str, int]:
    """Return ``{comment: packets}`` summed across both chains."""
    result: dict[str, int] = {}
    for chain in (CHAIN, INPUT_CHAIN):
        out = _nft("-j", "list", "chain", "inet", TABLE, chain, check=False)
        if out.returncode != 0 or not out.stdout.strip():
            continue
        try:
            data = json.loads(out.stdout)
        except json.JSONDecodeError:
            continue
        for entry in data.get("nftables", []):
            rule = entry.get("rule")
            if not rule:
                continue
            comment = rule.get("comment")
            if not comment:
                continue
            packets = 0
            for expr in rule.get("expr") or []:
                if isinstance(expr, dict) and "counter" in expr:
                    packets = int(expr["counter"].get("packets", 0))
                    break
            result[comment] = result.get(comment, 0) + packets
    return result


def chain_rules() -> str:
    """Return the raw ``nft list chain`` output. Debug aid, not for tests."""
    out = _nft("list", "chain", "inet", TABLE, CHAIN, check=False)
    return out.stdout


def cleanup_stale() -> None:
    """Remove Sentinel's table if a previous run left it behind."""
    remove()
