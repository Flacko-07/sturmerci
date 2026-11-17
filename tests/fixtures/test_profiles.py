# SPDX-License-Identifier: Apache-2.0
"""Test-only operation profiles — registered from pytest only.

Production code imports `sentinel.runner.builtin_profiles`, which no
longer registers any test/* profile. Only tests/conftest.py imports this
module, and this module calls _enable_test_profiles() before registering.
"""

from sentinel.runner.profiles import (
    OperationProfile,
    _enable_test_profiles,
    register_profile,
)

_enable_test_profiles()

register_profile(
    OperationProfile(
        name="test/echo",
        builder=lambda exe, p: [exe, p.get("msg", "hello")],
        required_params=frozenset(),
        prohibited_flags=(),
        execution_class=2,
    )
)

register_profile(
    OperationProfile(
        name="test/exploit",
        builder=lambda exe, p: [exe, "exploit"],
        required_params=frozenset(),
        prohibited_flags=(),
        execution_class=3,
        requires_param_binding=True,
    )
)

register_profile(
    OperationProfile(
        name="test/raw",
        builder=lambda exe, p: [exe, *p.get("args", [])],
        required_params=frozenset({"args"}),
        prohibited_flags=(),
        execution_class=2,
    )
)

register_profile(
    OperationProfile(
        name="test/passthrough",
        builder=lambda exe, p: list(p["argv"]),
        required_params=frozenset({"argv"}),
        prohibited_flags=(),
        execution_class=2,
        allow_argv0_override=True,
    )
)

register_profile(
    OperationProfile(
        name="test/exploit_passthrough",
        builder=lambda exe, p: list(p["argv"]),
        required_params=frozenset({"argv"}),
        prohibited_flags=(),
        execution_class=3,
        requires_param_binding=True,
        allow_argv0_override=True,
    )
)
