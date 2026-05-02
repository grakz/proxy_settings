"""Tests for the local CertAuthority and trust-status diagnostic in
mitm_handler. These do real RSA keygen against tmp_path — slow-ish but
genuine end-to-end coverage of the cert-signing path."""

import os
from pathlib import Path

import pytest

# cryptography is required for these tests; the module imports it lazily so
# we can detect availability without crashing the whole test session.
try:
    import cryptography  # noqa: F401
except ImportError:
    pytest.skip("cryptography not installed", allow_module_level=True)

import mitm_handler
from mitm_handler import (
    CertAuthority,
    check_ca_trust_status,
    compute_ca_fingerprint,
)


class TestCertAuthority:
    def test_creates_ca_on_first_run(self, tmp_path):
        ca_cert = tmp_path / "ca.pem"
        ca_key = tmp_path / "ca.key"
        ca = CertAuthority(ca_cert_path=ca_cert, ca_key_path=ca_key)
        assert ca_cert.exists()
        assert ca_key.exists()
        assert ca_cert.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
        # Key file should also be PEM-encoded
        key_pem = ca_key.read_bytes()
        assert b"PRIVATE KEY" in key_pem

    def test_loads_existing_ca_on_second_run(self, tmp_path):
        ca_cert = tmp_path / "ca.pem"
        ca_key = tmp_path / "ca.key"
        CertAuthority(ca_cert_path=ca_cert, ca_key_path=ca_key)
        cert_bytes_first = ca_cert.read_bytes()
        key_bytes_first = ca_key.read_bytes()

        # A second instance with the same paths must not regenerate
        CertAuthority(ca_cert_path=ca_cert, ca_key_path=ca_key)
        assert ca_cert.read_bytes() == cert_bytes_first
        assert ca_key.read_bytes() == key_bytes_first

    def test_signs_leaf_for_hostname(self, tmp_path, monkeypatch):
        # Direct the leaves cache into tmp_path so we don't pollute ~/.config
        monkeypatch.setattr(mitm_handler, "CA_DIR", tmp_path)

        ca_cert = tmp_path / "ca.pem"
        ca_key = tmp_path / "ca.key"
        ca = CertAuthority(ca_cert_path=ca_cert, ca_key_path=ca_key)

        cert_path, key_path = ca.get_leaf_files("registry.npmjs.org")
        assert os.path.exists(cert_path)
        assert os.path.exists(key_path)

        from cryptography import x509
        leaf = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())

        # SAN should include the hostname (and the wildcard form)
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [n.value for n in san]
        assert "registry.npmjs.org" in names

    def test_leaf_cache_returns_same_files(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mitm_handler, "CA_DIR", tmp_path)
        ca = CertAuthority(
            ca_cert_path=tmp_path / "ca.pem",
            ca_key_path=tmp_path / "ca.key",
        )
        first = ca.get_leaf_files("example.com")
        second = ca.get_leaf_files("example.com")
        assert first == second


class TestComputeCAFingerprint:
    def test_returns_colon_separated_hex(self, tmp_path):
        ca_cert = tmp_path / "ca.pem"
        ca_key = tmp_path / "ca.key"
        CertAuthority(ca_cert_path=ca_cert, ca_key_path=ca_key)

        fp = compute_ca_fingerprint(ca_cert)
        # SHA256 = 32 bytes = 64 hex chars = 32 colon-separated pairs
        parts = fp.split(":")
        assert len(parts) == 32
        for p in parts:
            assert len(p) == 2
            int(p, 16)  # raises if not hex

    def test_fingerprint_is_deterministic(self, tmp_path):
        ca_cert = tmp_path / "ca.pem"
        ca_key = tmp_path / "ca.key"
        CertAuthority(ca_cert_path=ca_cert, ca_key_path=ca_key)
        assert compute_ca_fingerprint(ca_cert) == compute_ca_fingerprint(ca_cert)


class TestCheckCATrustStatus:
    def test_warns_when_node_extra_ca_certs_unset(self, tmp_path, monkeypatch):
        ca_cert = tmp_path / "ca.pem"
        ca_key = tmp_path / "ca.key"
        CertAuthority(ca_cert_path=ca_cert, ca_key_path=ca_key)

        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        warnings = check_ca_trust_status(ca_cert)
        assert warnings  # non-empty list
        joined = " ".join(warnings).lower()
        assert "node_extra_ca_certs" in joined

    def test_warns_when_bundle_path_does_not_exist(self, tmp_path, monkeypatch):
        ca_cert = tmp_path / "ca.pem"
        ca_key = tmp_path / "ca.key"
        CertAuthority(ca_cert_path=ca_cert, ca_key_path=ca_key)

        monkeypatch.setenv("NODE_EXTRA_CA_CERTS", str(tmp_path / "nope.pem"))
        warnings = check_ca_trust_status(ca_cert)
        joined = " ".join(warnings).lower()
        assert "does not exist" in joined

    def test_warns_when_ca_not_in_bundle(self, tmp_path, monkeypatch):
        ca_cert = tmp_path / "ca.pem"
        ca_key = tmp_path / "ca.key"
        CertAuthority(ca_cert_path=ca_cert, ca_key_path=ca_key)

        empty_bundle = tmp_path / "bundle.pem"
        empty_bundle.write_bytes(b"# empty bundle\n")
        monkeypatch.setenv("NODE_EXTRA_CA_CERTS", str(empty_bundle))

        warnings = check_ca_trust_status(ca_cert)
        joined = " ".join(warnings).lower()
        assert "not present" in joined

    def test_no_warnings_when_ca_in_bundle(self, tmp_path, monkeypatch):
        ca_cert = tmp_path / "ca.pem"
        ca_key = tmp_path / "ca.key"
        CertAuthority(ca_cert_path=ca_cert, ca_key_path=ca_key)

        bundle = tmp_path / "bundle.pem"
        # Concatenate the CA into the bundle
        bundle.write_bytes(ca_cert.read_bytes())
        monkeypatch.setenv("NODE_EXTRA_CA_CERTS", str(bundle))

        assert check_ca_trust_status(ca_cert) == []
