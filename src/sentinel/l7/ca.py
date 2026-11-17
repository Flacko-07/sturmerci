# SPDX-License-Identifier: Apache-2.0
"""Per-run certificate authority for TLS termination.

M7.2 uses this to MITM HTTPS traffic inside the sandbox so method/path
can be inspected. The CA is ephemeral: generated at run start, trusted
only by the sandbox's tool process via SSL_CERT_FILE, destroyed at run end.

Threat model:
- Anyone with the CA private key can sign arbitrary certs trusted by
  the sandbox. Therefore the CA key lives in a per-run directory with
  mode 0700, and the tool only reads the CA *cert* (public), never the key.
- The CA is valid for 24 hours. A stolen CA cert is useless after the
  run because the tool that would trust it no longer exists.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# Hostname pattern matching the L7 adapter's rules.
_VALID_HOSTNAME = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)


class CAError(ValueError):
    """CA generation or signing refused."""


@dataclass(frozen=True, slots=True)
class LeafCert:
    cert_path: Path
    key_path: Path
    common_name: str


class L7CA:
    """Per-run CA. Generate once, sign leaves as needed."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.base_dir.chmod(0o700)
        except OSError:
            pass
        self._ca_cert_path = base_dir / "ca.crt"
        self._ca_key_path = base_dir / "ca.key"
        self._ca_cert: x509.Certificate | None = None
        self._ca_key: rsa.RSAPrivateKey | None = None

    @property
    def ca_cert_path(self) -> Path:
        return self._ca_cert_path

    def generate(self) -> None:
        """Generate the CA. Idempotent (raises if called twice)."""
        if self._ca_key is not None:
            raise CAError("CA already generated")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sentinel Run"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Sentinel Ephemeral CA"),
            ]
        )
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(hours=24))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            # SKID required for chain building; leaves reference this.
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        self._ca_key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self._ca_key_path.chmod(0o600)
        self._ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self._ca_cert_path.chmod(0o644)
        self._ca_key = key
        self._ca_cert = cert

    def sign_leaf(self, hostname: str) -> LeafCert:
        """Sign a leaf cert valid for exactly `hostname`.

        Refuses anything outside `_VALID_HOSTNAME` (no wildcards, no
        trailing dots, no uppercase). Refuses IPs unless they're a
        valid literal (which become SAN IPAddress entries).
        """
        if self._ca_key is None or self._ca_cert is None:
            raise CAError("CA not generated; call generate() first")
        if not hostname:
            raise CAError("empty hostname")
        hostname = hostname.rstrip(".").lower()

        # Determine SAN entries
        is_ip = False
        try:
            ip_obj = ipaddress.ip_address(hostname)
            san_entries: list[x509.GeneralName] = [x509.IPAddress(ip_obj)]
        except ValueError:
            # Wildcard check first: "*.example.com" fails _VALID_HOSTNAME
            # because '*' is not in the character class. Catch it here so
            # the error message names the actual refusal reason, not the
            # generic "invalid hostname".
            if "*" in hostname:
                raise CAError(f"wildcard hostnames refused: {hostname!r}")
            if not _VALID_HOSTNAME.match(hostname):
                raise CAError(f"invalid hostname for leaf cert: {hostname!r}")
            san_entries = [x509.DNSName(hostname)]

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ]
        )
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))  # clock skew
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
            # AKID required by OpenSSL chain verification: must reference
            # the CA's SubjectKeyIdentifier.
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self._ca_key.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", hostname)
        cert_path = self.base_dir / f"leaf_{safe}.crt"
        key_path = self.base_dir / f"leaf_{safe}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        return LeafCert(cert_path=cert_path, key_path=key_path, common_name=hostname)

    def ca_cert_pem(self) -> bytes:
        """Return the CA certificate in PEM form (for SSL_CERT_FILE)."""
        if self._ca_cert is None:
            raise CAError("CA not generated")
        return self._ca_cert.public_bytes(serialization.Encoding.PEM)
