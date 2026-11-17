# SPDX-License-Identifier: Apache-2.0
# FIXTURE ONLY — synthetic values, no working credentials.
# Assembled at import time so no credential-shaped literal appears in source.
# The runtime equivalent used by integration tests lives in
# test_gitleaks_adapter.py::_write_synthetic_gitleaks_fixture.

AWS_ACCESS_KEY_ID     = "AKIA" + "Q3EGVZ7J4M2KPL5N"
AWS_SECRET_ACCESS_KEY = "7pK9mN2v" + "Q8xR4tY6wB3cF1hJ5sL0dG8eA2uZ7nP4"
GITHUB_TOKEN          = "ghp_" + "9fK2mN8pQ4vX7yB3cL6hJ1sD5gA0eR2uWtY8kP4"

FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwfQ"
    ".fake-signature-not-a-real-key-AAAAAAA"
)

_begin = "-----BEGIN " + "RSA " + "PRIVATE KEY-----"
_end   = "-----END " + "RSA " + "PRIVATE KEY-----"
_body  = (
    "MIIEowIBAAKCAQEAzXbV9pNqM4kF1aG7dY2vL3hB8tR5mS6cW0jY4xE2kQ9wN8c\n"
    "B1hV7fD3aT6pZ0yW9sL4gQ1hN8bR2mK5cX7vF4tY0dG9jA6eP3wS8uM1nQ5bC2\n"
    "xT4hY9kR7vL0fD3mN6aP8sW1gJ5cZ2tB7qE4nK9dM0uX6yH3vL8aF5hR1cV3\n"
    "bN2mP7sK4tY9dF1hR5cV8wL0aB3gN6mQ2uX9yE4tZ7fD1hS5kW8vC2nM4aP0"
)
FAKE_PRIVATE_KEY = _begin + "\n" + _body + "\n" + _end
