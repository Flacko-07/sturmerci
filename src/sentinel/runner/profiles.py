# SPDX-License-Identifier: Apache-2.0
"""Operation profiles — the runner-side argv authority.

An adapter declares intent via `SandboxRequest.operation_profile` +
`SandboxRequest.profile_params`. It does NOT send raw argv. The runner
looks up the profile by name, calls the builder, and verifies the
produced argv. A caller that tries to launch the same binary with
different flags is refused -- the runner no longer trusts the adapter
to enforce flag policy.

See docs/runner-profiles-design.md for the full rationale.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable


class ProfileError(ValueError):
    """Unknown profile, bad params, or argv construction failure."""


@dataclass(frozen=True, slots=True)
class OperationProfile:
    """A named, parameterized operation the runner will execute.

    name:                e.g. "nmap/tcp_connect_scan"
    builder:             fn(executable_path, params) -> list[str]
    required_params:     frozenset of keys params MUST contain
    prohibited_flags:    token substrings that must not appear in argv
                         (runner-enforced, independent of adapter)
    """

    name: str
    builder: Callable[[str, dict[str, Any]], list[str]]
    required_params: frozenset[str]
    prohibited_flags: tuple[str, ...] = field(default_factory=tuple)
    # Class of the specific operation this profile performs. 2 = active
    # low-impact, 3 = intrusive. When a request carries an operation_profile,
    # SandboxRunner gates on max(manifest.execution_class, profile.execution_class)
    # of the profile — so one binary (e.g. metasploit) can host both a
    # Class 2 detection profile and a Class 3 exploit profile.
    execution_class: int = 2
    # Class 3 operations require an approval bound to the profile params,
    # including an explicit hash of the empty parameter set when applicable.
    requires_param_binding: bool = False
    # Exact canonical parameter keys committed by approval. Runtime-only
    # file paths (e.g. report output and generated RC files) are excluded.
    param_binding_keys: frozenset[str] = field(default_factory=frozenset)
    # (batch-1, test-only) When True, the runner permits request.argv[0]
    # to differ from manifest.executable_path. This exists solely so
    # egress tests can drive arbitrary binaries through the sandbox
    # (e.g. /bin/sleep for revocation tests) without a manifest per
    # binary. It is REFUSED by register_profile unless the profile
    # name starts with "test/". No production adapter may set it.
    allow_argv0_override: bool = False


# (batch A) Test-only profiles (test/echo, test/passthrough, ...) are
# registered exclusively from tests/fixtures/test_profiles.py.
# register_profile() refuses the 'test/' prefix unless
# _enable_test_profiles() was called first.
_ALLOW_TEST_PROFILES = False


def _enable_test_profiles() -> None:
    """Test fixtures call this before registering test/* profiles."""
    global _ALLOW_TEST_PROFILES
    _ALLOW_TEST_PROFILES = True


_REGISTRY: dict[str, OperationProfile] = {}


def register_profile(profile: OperationProfile) -> None:
    if profile.name in _REGISTRY:
        raise ProfileError(f"profile {profile.name!r} already registered")
    # (batch A) Production code cannot register test/* profiles. Only
    # tests/fixtures/test_profiles.py calls _enable_test_profiles() before
    # registering. This prevents a production manifest from getting the
    # arbitrary-argv passthrough semantics of test/passthrough.
    if profile.name.startswith("test/") and not _ALLOW_TEST_PROFILES:
        raise ProfileError(
            f"profile {profile.name!r} has a reserved 'test/' prefix. "
            f"Only tests/fixtures/test_profiles.py may register test/* "
            f"profiles (it calls _enable_test_profiles() first)."
        )
    if profile.allow_argv0_override and not profile.name.startswith("test/"):
        raise ProfileError(
            f"allow_argv0_override=True is only permitted on test/* "
            f"profiles (got {profile.name!r})"
        )
    if profile.execution_class >= 3 and not profile.requires_param_binding:
        raise ProfileError(
            f"Class 3 profile {profile.name!r} must require parameter binding"
        )
    if profile.requires_param_binding:
        if not profile.param_binding_keys:
            object.__setattr__(profile, "param_binding_keys", profile.required_params)
        unknown_binding_keys = profile.param_binding_keys - profile.required_params
        if unknown_binding_keys:
            raise ProfileError(
                f"profile {profile.name!r} binding keys must be required params: "
                f"{sorted(unknown_binding_keys)}"
            )
    _REGISTRY[profile.name] = profile


def get_profile(name: str) -> OperationProfile:
    profile = _REGISTRY.get(name)
    if profile is None:
        raise ProfileError(
            f"unknown operation profile {name!r}. Registered: {sorted(_REGISTRY)}"
        )
    return profile


def all_profiles() -> list[str]:
    return sorted(_REGISTRY)


def _reset_for_tests() -> None:
    """Test-only. Not part of the public API."""
    _REGISTRY.clear()


def build_argv_for_profile(
    *,
    profile_name: str,
    executable_path: str,
    params: dict[str, Any],
) -> list[str]:
    """Construct argv via the registered builder. Validate against policy."""
    profile = get_profile(profile_name)

    missing = profile.required_params - set(params)
    if missing:
        raise ProfileError(
            f"profile {profile_name!r} missing required params: {sorted(missing)}"
        )

    try:
        argv = profile.builder(executable_path, params)
    except Exception as e:
        raise ProfileError(f"profile {profile_name!r} builder raised: {e}") from e

    if not argv:
        raise ProfileError(f"profile {profile_name!r} builder returned empty argv")
    if argv[0] != executable_path and not profile.allow_argv0_override:
        raise ProfileError(
            f"profile {profile_name!r} builder did not return "
            f"argv[0]=={executable_path!r}"
        )

    for token in argv:
        for forbidden in profile.prohibited_flags:
            if token == forbidden or token.startswith(forbidden + "="):
                raise ProfileError(
                    f"profile {profile_name!r} produced prohibited flag "
                    f"{token!r} (prohibited: {forbidden!r})"
                )

    return argv


def argv_hash(argv: list[str]) -> str:
    """Normalized hash of argv for audit + approval binding."""
    return hashlib.sha256(
        json.dumps(argv, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def params_hash(params: dict[str, str]) -> str:
    """Deterministic hash over a param dict.

    Used for approval.normalized_arguments_hash: the operator declares
    profile params at issue time, they're hashed, and any run whose
    declared param subset differs is refused at step 3d.
    """
    return hashlib.sha256(
        json.dumps(
            {k: str(v) for k, v in params.items()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
