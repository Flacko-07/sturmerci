# SPDX-License-Identifier: Apache-2.0
"""Regression: every registered profile must build a valid argv.

Catches the class of bug where an adapter's prohibited_flags tuple
consumes the builder's own output (e.g. ffuf's bare "-X").
"""

import sentinel.runner.builtin_profiles  # noqa: F401  registers all
from sentinel.runner.profiles import build_argv_for_profile


def test_ffuf_profile_builds_valid_argv():
    argv = build_argv_for_profile(
        profile_name="ffuf/dir_discovery",
        executable_path="/usr/bin/ffuf",
        params={
            "hostname": "127.0.0.1",
            "port": 18080,
            "scheme": "http",
            "wordlist_path": "/x/common.txt",
            "rate": 10,
        },
    )
    assert "-X" in argv and argv[argv.index("-X") + 1] == "GET"


def test_whois_profile_builds_valid_argv():
    argv = build_argv_for_profile(
        profile_name="whois/target_lookup",
        executable_path="/usr/bin/whois",
        params={"target_domain": "example.com", "server": "whois.iana.org"},
    )
    assert "example.com" in argv and "whois.iana.org" in argv


def test_semgrep_trivy_have_no_network_profile():
    """Class 0 adapters have no operation_profile; verified by absence."""
    from sentinel.runner.profiles import all_profiles

    names = all_profiles()
    assert not any("semgrep" in n for n in names), names
    assert not any("trivy" in n for n in names), names
