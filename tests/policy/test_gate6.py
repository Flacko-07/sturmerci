# SPDX-License-Identifier: Apache-2.0
"""Capability metadata registry tests; execution remains manifest-gated."""

import socket

from sentinel.runner.registry import (
    AdapterManifest,
    register,
    all_adapters,
    network_capable,
)
from sentinel.runner import registry as _reg


def test_network_adapter_metadata_registers_without_test_artifacts():
    m = AdapterManifest(
        name="test_httpx_metadata",
        execution_class=2,
        network_access=True,
        enabled=False,
    )
    register(m)
    try:
        assert "test_httpx_metadata" in {x.name for x in all_adapters()}
        assert m in network_capable()
    finally:
        _reg._REGISTRY.pop("test_httpx_metadata", None)


# --- Invariants across the whole suite ---


def test_local_adapter_metadata_registers():
    m = AdapterManifest(
        name="test_local_always_ok",
        execution_class=0,
        network_access=False,
        enabled=False,
    )
    register(m)
    try:
        assert "test_local_always_ok" in {x.name for x in all_adapters()}
    finally:
        _reg._REGISTRY.pop("test_local_always_ok", None)


def test_no_network_capable_adapters_left_behind():
    """Tests must clean up the descriptive registry's shared state."""
    assert network_capable() == []


# --- Socket policy test ---


def test_no_external_sockets_open():
    """Verify no external TCP sockets are active in this process.

    Loopback (127.0.0.0/8, ::1) is permitted — that is Ollama.
    Anything else is unexpected in this offline test process.
    """

    def is_loopback(addr):
        if not addr:
            return True
        host = addr[0] if isinstance(addr, tuple) else addr
        if host in ("127.0.0.1", "::1", "0.0.0.0", "::"):
            return True
        try:
            if host.startswith("127."):
                return True
            if host.startswith("::ffff:127."):
                return True
        except Exception:
            pass
        return False

    import psutil

    proc = psutil.Process()
    offenders = []
    for c in proc.net_connections(kind="inet"):
        if c.type != socket.SOCK_STREAM:
            continue
        if c.status not in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT):
            continue
        laddr_ok = is_loopback(c.laddr)
        raddr_ok = is_loopback(c.raddr)
        if not (laddr_ok and raddr_ok):
            offenders.append((c.laddr, c.raddr, c.status))
    assert offenders == [], f"external sockets: {offenders}"
