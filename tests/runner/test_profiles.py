# SPDX-License-Identifier: Apache-2.0
"""Operation profile unit tests (M6-P0-A)."""
from __future__ import annotations

import pytest

from sentinel.runner import builtin_profiles as _bp  # noqa: F401
from sentinel.runner.profiles import (
    build_argv_for_profile, get_profile, all_profiles, ProfileError,
)


def test_builtin_profiles_registered():
    names = all_profiles()
    assert "nmap/tcp_connect_scan" in names
    assert "httpx/inventory" in names
    assert "subfinder/passive_crtsh" in names


def test_unknown_profile_rejected():
    with pytest.raises(ProfileError, match="unknown operation profile"):
        build_argv_for_profile(
            profile_name="does/not/exist",
            executable_path="/bin/true",
            params={},
        )


def test_missing_params_rejected():
    with pytest.raises(ProfileError, match="missing required params"):
        build_argv_for_profile(
            profile_name="nmap/tcp_connect_scan",
            executable_path="/usr/bin/nmap",
            params={"target": "x.test"},
        )


def test_nmap_produces_expected_argv():
    argv = build_argv_for_profile(
        profile_name="nmap/tcp_connect_scan",
        executable_path="/usr/bin/nmap",
        params={"target": "x.test", "ports": [80, 443], "max_rate": 20},
    )
    assert argv[0] == "/usr/bin/nmap"
    assert "-sT" in argv
    assert "-Pn" in argv
    assert "-n" in argv
    assert "--max-rate" in argv
    assert "20" in argv
    i = argv.index("-p")
    assert argv[i + 1] == "80,443"
    assert argv[-1] == "x.test"


@pytest.mark.parametrize("forbidden", [
    "--script", "-sC", "-sV", "-A", "-O", "-sU", "-sS",
])
def test_nmap_prohibited_flags_listed(forbidden):
    profile = get_profile("nmap/tcp_connect_scan")
    for p in profile.prohibited_flags:
        if forbidden == p or forbidden.startswith(p + "="):
            return
    pytest.fail(f"{forbidden!r} not in prohibited list")


def test_nmap_ports_must_be_list():
    with pytest.raises(ProfileError, match="ports must be a non-empty list"):
        build_argv_for_profile(
            profile_name="nmap/tcp_connect_scan",
            executable_path="/usr/bin/nmap",
            params={"target": "x.test", "ports": "80,443", "max_rate": 20},
        )


def test_nmap_rate_out_of_range():
    with pytest.raises(ProfileError, match="max_rate out of range"):
        build_argv_for_profile(
            profile_name="nmap/tcp_connect_scan",
            executable_path="/usr/bin/nmap",
            params={"target": "x.test", "ports": [80], "max_rate": 0},
        )


def test_httpx_only_get_head():
    for method in ("GET", "HEAD"):
        argv = build_argv_for_profile(
            profile_name="httpx/inventory",
            executable_path="/usr/bin/httpx",
            params={
                "hostname": "x.test", "port": 443,
                "scheme": "https", "method": method,
            },
        )
        assert "-u" in argv
    with pytest.raises(ProfileError, match="method"):
        build_argv_for_profile(
            profile_name="httpx/inventory",
            executable_path="/usr/bin/httpx",
            params={
                "hostname": "x.test", "port": 443,
                "scheme": "https", "method": "POST",
            },
        )


def test_subfinder_only_crtsh_allowed():
    argv = build_argv_for_profile(
        profile_name="subfinder/passive_crtsh",
        executable_path="/usr/bin/subfinder",
        params={"domain": "x.test", "sources": ["crtsh"]},
    )
    assert "crtsh" in argv
    with pytest.raises(ProfileError, match="not authorized"):
        build_argv_for_profile(
            profile_name="subfinder/passive_crtsh",
            executable_path="/usr/bin/subfinder",
            params={"domain": "x.test", "sources": ["censys"]},
        )


def test_subfinder_prohibited_flags_checked():
    profile = get_profile("subfinder/passive_crtsh")
    assert "-all" in profile.prohibited_flags


# --- M7-P0-E: httpx method reaches binary ---

def test_m7p0e_httpx_get_and_head_produce_different_argv():
    """M7-P0-E: -x METHOD must be in argv; GET != HEAD."""
    get_argv = build_argv_for_profile(
        profile_name="httpx/inventory",
        executable_path="/usr/bin/httpx",
        params={"hostname": "x.test", "port": 443,
                "scheme": "https", "method": "GET"},
    )
    head_argv = build_argv_for_profile(
        profile_name="httpx/inventory",
        executable_path="/usr/bin/httpx",
        params={"hostname": "x.test", "port": 443,
                "scheme": "https", "method": "HEAD"},
    )
    assert get_argv != head_argv
    assert "-x" in get_argv
    i = get_argv.index("-x")
    assert get_argv[i + 1] == "GET"
    j = head_argv.index("-x")
    assert head_argv[j + 1] == "HEAD"
