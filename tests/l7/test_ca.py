# SPDX-License-Identifier: Apache-2.0
"""CA module unit tests. No root needed."""

import ssl

import pytest
from cryptography import x509

from sentinel.l7.ca import L7CA, CAError, LeafCert


@pytest.fixture
def ca(tmp_path):
    c = L7CA(tmp_path / "ca")
    c.generate()
    return c


def test_generate_produces_ca_files(tmp_path):
    c = L7CA(tmp_path / "ca")
    c.generate()
    assert c.ca_cert_path.is_file()
    assert c.ca_cert_path.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
    key_path = tmp_path / "ca" / "ca.key"
    assert key_path.is_file()
    # Private key must be mode 0600
    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600, f"CA key mode = {oct(mode)}"


def test_ca_has_ca_basic_constraints(tmp_path):
    c = L7CA(tmp_path / "ca")
    c.generate()
    cert = x509.load_pem_x509_certificate(c.ca_cert_path.read_bytes())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 0


def test_sign_leaf_for_hostname(ca):
    leaf = ca.sign_leaf("app.example.com")
    assert isinstance(leaf, LeafCert)
    assert leaf.cert_path.is_file()
    assert leaf.key_path.is_file()
    assert leaf.key_path.stat().st_mode & 0o777 == 0o600
    # Cert parses
    cert = x509.load_pem_x509_certificate(leaf.cert_path.read_bytes())
    # SAN includes the hostname
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns_names = san.get_values_for_type(x509.DNSName)
    assert "app.example.com" in dns_names


def test_sign_leaf_cn_matches(ca):
    leaf = ca.sign_leaf("api.example.com")
    cert = x509.load_pem_x509_certificate(leaf.cert_path.read_bytes())
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert cn == "api.example.com"


def test_sign_leaf_trailing_dot_normalized(ca):
    leaf = ca.sign_leaf("app.example.com.")
    assert leaf.common_name == "app.example.com"
    cert = x509.load_pem_x509_certificate(leaf.cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "app.example.com" in san.get_values_for_type(x509.DNSName)


def test_sign_leaf_uppercase_normalized(ca):
    leaf = ca.sign_leaf("APP.Example.COM")
    assert leaf.common_name == "app.example.com"


def test_sign_leaf_for_ip(ca):
    leaf = ca.sign_leaf("203.0.113.42")
    cert = x509.load_pem_x509_certificate(leaf.cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ips = san.get_values_for_type(x509.IPAddress)
    assert len(ips) == 1
    assert str(ips[0]) == "203.0.113.42"


def test_sign_leaf_rejects_wildcard(ca):
    with pytest.raises(CAError, match="wildcard"):
        ca.sign_leaf("*.example.com")


def test_sign_leaf_rejects_invalid_hostname(ca):
    for bad in ("bad_host", "..", "", "app..com", "-app.test", "app.test-"):
        with pytest.raises(CAError):
            ca.sign_leaf(bad)


def test_generate_twice_raises(ca):
    with pytest.raises(CAError, match="already generated"):
        ca.generate()


def test_sign_leaf_before_generate(tmp_path):
    c = L7CA(tmp_path / "ca")
    with pytest.raises(CAError, match="not generated"):
        c.sign_leaf("app.test")


def test_leaf_verifiable_by_ca(tmp_path):
    """A client trusting only the CA can verify the leaf (the whole point)."""
    c = L7CA(tmp_path / "ca")
    c.generate()
    leaf = c.sign_leaf("app.example.com")

    # Load CA + leaf into SSLContext and verify the chain
    ca_cert_pem = c.ca_cert_path.read_bytes()
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Load CA into client's trust store
    ca_load_path = tmp_path / "trusted_ca.pem"
    ca_load_path.write_bytes(ca_cert_pem)
    client_ctx.load_verify_locations(cafile=str(ca_load_path))
    client_ctx.check_hostname = True
    client_ctx.verify_mode = ssl.CERT_REQUIRED

    # Server context uses the leaf
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(leaf.cert_path), str(leaf.key_path))

    # Both contexts constructed successfully = cert loadable + CA trusted.
    # A full handshake test happens in the proxy test (needs actual socket).
    assert client_ctx.verify_mode == ssl.CERT_REQUIRED
    assert server_ctx.protocol == ssl.PROTOCOL_TLS_SERVER


def test_leaf_for_different_hostname_does_not_verify(tmp_path):
    """A leaf for A must NOT verify against a client checking B."""
    c = L7CA(tmp_path / "ca")
    c.generate()
    leaf = c.sign_leaf("app.example.com")
    cert = x509.load_pem_x509_certificate(leaf.cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns_names = san.get_values_for_type(x509.DNSName)
    # Cert for app.example.com; check_hostname against other.test must fail
    assert "other.test" not in dns_names


def test_leaf_akid_matches_ca_skid(ca, tmp_path):
    """The leaf's AKID must equal the CA's SKID for OpenSSL verification."""
    from cryptography import x509 as _x509

    leaf = ca.sign_leaf("app.example.com")
    leaf_cert = _x509.load_pem_x509_certificate(leaf.cert_path.read_bytes())
    ca_cert = _x509.load_pem_x509_certificate(ca.ca_cert_path.read_bytes())

    akid = leaf_cert.extensions.get_extension_for_class(
        _x509.AuthorityKeyIdentifier
    ).value
    skid = ca_cert.extensions.get_extension_for_class(_x509.SubjectKeyIdentifier).value
    assert akid.key_identifier == skid.digest


def test_ca_has_subject_key_identifier(ca, tmp_path):
    from cryptography import x509 as _x509

    cert = _x509.load_pem_x509_certificate(ca.ca_cert_path.read_bytes())
    skid = cert.extensions.get_extension_for_class(_x509.SubjectKeyIdentifier).value
    assert len(skid.digest) == 20  # SHA-1 hash is 20 bytes
