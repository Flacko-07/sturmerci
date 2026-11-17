# SPDX-License-Identifier: Apache-2.0
from importlib import resources


def test_runtime_resources_are_inside_sentinel_package():
    package = resources.files("sentinel")
    migration_files = list(
        package.joinpath("storage", "migrations").glob("*.sql")
    )
    assert migration_files
