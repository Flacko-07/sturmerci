# SPDX-License-Identifier: Apache-2.0
"""Unit tests for Nmap adapter. No root needed."""

import pytest

from sentinel.adapters.nmap import (
    build_argv,
    parse_output,
    _assert_no_forbidden_flags,
    NmapAdapterError,
    FORBIDDEN_FLAGS,
)


# --- build_argv ---


def test_build_argv_basic():
    argv = build_argv("/usr/bin/nmap", "probe.test", [22, 80, 443], 50)
    assert argv[0] == "/usr/bin/nmap"
    assert "-sT" in argv
    assert "-Pn" in argv
    assert "-n" in argv
    assert "-oX" in argv
    assert "--max-rate" in argv
    assert "50" in argv
    assert "22,80,443" in argv
    assert argv[-1] == "probe.test"


def test_build_argv_sorts_ports():
    argv = build_argv("/nmap", "t.test", [443, 22, 80], 10)
    i = argv.index("-p")
    assert argv[i + 1] == "22,80,443"


def test_build_argv_rejects_empty_ports():
    with pytest.raises(NmapAdapterError, match="empty"):
        build_argv("/nmap", "t.test", [], 10)


@pytest.mark.parametrize("bad", [0, 65536, -1])
def test_build_argv_rejects_invalid_port(bad):
    with pytest.raises(NmapAdapterError, match="invalid port"):
        build_argv("/nmap", "t.test", [bad], 10)


def test_build_argv_rejects_bad_rate():
    with pytest.raises(NmapAdapterError, match="max_rate"):
        build_argv("/nmap", "t.test", [80], 0)
    with pytest.raises(NmapAdapterError, match="max_rate"):
        build_argv("/nmap", "t.test", [80], 10000)


# --- forbidden flag detection ---


@pytest.mark.parametrize("flag", FORBIDDEN_FLAGS)
def test_forbidden_flag_rejected(flag):
    with pytest.raises(NmapAdapterError, match="forbidden"):
        _assert_no_forbidden_flags(["/nmap", flag, "target"])


def test_forbidden_flag_with_value_rejected():
    with pytest.raises(NmapAdapterError, match="forbidden"):
        _assert_no_forbidden_flags(["/nmap", "--script=foo", "target"])


# --- parse_output ---

SAMPLE_OPEN = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="1.1.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished exit="success" time="1500"/>
  </runstats>
</nmaprun>"""


def test_parse_open_and_closed():
    findings = parse_output(SAMPLE_OPEN, "probe.test")
    assert len(findings) == 2
    states = {f.port: f.state for f in findings}
    assert states[22] == "open"
    assert states[80] == "closed"
    assert all(f.ip == "1.1.1.1" for f in findings)
    assert all(f.host == "probe.test" for f in findings)


def test_parse_empty_xml_returns_empty():
    assert parse_output("", "probe.test") == []
    assert parse_output("   ", "probe.test") == []


def test_parse_malformed_xml_returns_empty():
    assert parse_output("<not xml", "probe.test") == []


def test_parse_no_ports_returns_empty():
    xml = '<nmaprun><host><address addr="1.2.3.4"/></host><runstats><finished exit="success" time="1500"/></runstats></nmaprun>'
    assert parse_output(xml, "probe.test") == []


def test_parse_skips_invalid_portid():
    xml = """<nmaprun><host><address addr="1.2.3.4"/><ports>
      <port protocol="tcp" portid="abc"><state state="open"/></port>
      <port protocol="tcp" portid="0"><state state="open"/></port>
      <port protocol="tcp" portid="80"><state state="open"/></port>
    </ports></host><runstats><finished exit="success" time="1500"/></runstats></nmaprun>"""
    findings = parse_output(xml, "t.test")
    assert len(findings) == 1
    assert findings[0].port == 80


def test_parse_filters_to_open():
    # Verify the caller can distinguish; parser itself returns all states
    findings = parse_output(SAMPLE_OPEN, "probe.test")
    opens = [f for f in findings if f.state == "open"]
    assert len(opens) == 1
    assert opens[0].port == 22


# --- M6-05: partial scans rejected ---

SAMPLE_WITH_RUNSTATS_OK = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.1.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/></port>
    </ports>
  </host>
  <runstats>
    <finished exit="success" time="100"/>
  </runstats>
</nmaprun>"""


def test_m6p05_successful_scan_accepted():
    findings = parse_output(SAMPLE_WITH_RUNSTATS_OK, "probe.test")
    assert len(findings) == 1
    assert findings[0].port == 80


def test_partial_scan_without_runstats_preserves_observation():
    """Observations survive but the result status separately marks partial."""
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="1.1.1.1"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
      </host>
    </nmaprun>"""
    findings = parse_output(xml, "probe.test")
    assert len(findings) == 1
    assert findings[0].port == 80


def test_failed_scan_preserves_observation_for_explicit_failed_result():
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="1.1.1.1"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
      </host>
      <runstats><finished exit="error" time="100"/></runstats>
    </nmaprun>"""
    findings = parse_output(xml, "probe.test")
    assert len(findings) == 1
    assert findings[0].port == 80


def test_truncated_xml_preserves_only_complete_host_observations():
    xml = """<nmaprun><host><address addr="1.1.1.1"/><ports>
      <port protocol="tcp" portid="443"><state state="open"/></port>
    </ports></host><host><address addr="1.1.1.1"/><ports>
      <port protocol="tcp" portid="8443"><state state="open"/>"""
    findings = parse_output(xml, "probe.test")
    assert len(findings) == 1
    assert findings[0].port == 443
