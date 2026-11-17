# Runner Operation Profiles — Design

**Status:** Implemented
**Date:** 2026-11-14
**Milestone:** M6-P0-A
**Scope:** Named, parameterized operations the runner will execute.
Replaces "adapter constructs argv directly."

## 1. Why a profile layer

Before M6-P0-A, each adapter built its own argv list and passed it to
SandboxRunner. The runner's only argv check was "argv[0] resolves to the
manifest executable." Everything after argv[0] was trusted to the adapter.

The profile layer inverts this. The adapter declares:

    operation_profile: "nmap/tcp_connect_scan"
    profile_params:    {"target": "...", "ports": [...], "max_rate": 100}

and the runner:

1. Looks up the profile in builtin_profiles.py.
2. Calls the builder to produce a canonical argv.
3. Refuses if request.argv != canonical_argv.

## 2. OperationProfile

    @dataclass(frozen=True)
    class OperationProfile:
        name: str
        builder: Callable[[str, dict], list[str]]
        required_params: frozenset[str]
        prohibited_flags: tuple[str, ...] = ()
        execution_class: int = 2   # added 2026-11-14

- `name` — namespaced `<tool>/<operation>`.
- `builder` — pure function. Takes executable path and params dict,
  returns canonical argv.
- `required_params` — pre-checked before calling the builder.
- `prohibited_flags` — secondary check. Token match by exact equality
  or `token.startswith(forbidden + "=")`. The builder is authoritative.
- `execution_class` — defaults to 2. Set to 3 only for genuinely
  intrusive profiles. SandboxRunner gates on this in addition to
  manifest.execution_class, so one binary (metasploit) can host both a
  Class 2 detection profile and a Class 3 exploit profile.

## 3. build_argv_for_profile

    def build_argv_for_profile(*, profile_name, executable_path, params) -> list[str]:
        profile = get_profile(profile_name)
        missing = profile.required_params - set(params)
        if missing:
            raise ProfileError(...)
        argv = profile.builder(executable_path, params)
        if not argv or argv[0] != executable_path:
            raise ProfileError(...)
        for token in argv:
            for forbidden in profile.prohibited_flags:
                if token == forbidden or token.startswith(forbidden + "="):
                    raise ProfileError(...)
        return argv

## 4. Double-check

Both the adapter and the runner call build_argv_for_profile()
independently. The adapter uses it to construct request.argv; the runner
re-invokes it to produce a canonical version and refuses if they differ.
This catches adapter edits that changed argv construction without
updating the profile.

## 5. The prohibited_flags bug class

nuclei: builder produced `-headless=false` and `-code=false`, but
NUCLEI_PROHIBITED_FLAGS contained `-headless` and `-code`. The
runner's `startswith(forbidden + "=")` matched, so the builder refused
its own output. Fix: removed `=false` from builder, since nuclei's
defaults are already false.

The rule: never put a flag in prohibited_flags that the builder
legitimately emits, in any form. If a value must be pinned (e.g. `-X GET`),
the builder pins it and the prohibition catches the wrong values (POST,
PUT), not the flag name.

## 6. Out of scope

- Not user-extensible. Only builtin_profiles.py registers profiles.
- Profiles do not enforce rate limits or scope — that is SandboxRunner.
- Profiles do not control env_overrides or cwd — those are SandboxRequest
  fields, not profile fields.

## 7. Test coverage

`tests/adapters/test_profile_builders.py` asserts that every registered
profile builds valid argv for representative input. Per-adapter
`test_profile_builds_valid_argv` pins the exact argv. ~15 profile-build
tests across the 16 adapters.
