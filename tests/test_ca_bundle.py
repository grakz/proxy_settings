"""Tests for write_ca_bundle and ensure_mitm_ca_in_bundle. Operate on real
files in a tmp_path; no mocking."""

import os
from pathlib import Path

import pytest

from configure_proxy import (
    _der_to_pem,
    ensure_mitm_ca_in_bundle,
    write_ca_bundle,
)

# Same minimal fake DER as test_ca_utils — valid SEQUENCE prefix, padding bytes.
_FAKE_DER = bytes.fromhex("30820100" + "00" * 252)
_FAKE_DER_2 = bytes.fromhex("30820100" + "11" * 252)


class TestWriteCABundle:
    def test_writes_to_explicit_path(self, tmp_path):
        out = tmp_path / "bundle.pem"
        result = write_ca_bundle(
            [("Test Cert", "Test Cert", _FAKE_DER, True)],
            str(out),
        )
        assert result == str(out)
        assert out.exists()
        assert out.stat().st_size > 0

    def test_includes_corp_cert_pem(self, tmp_path):
        out = tmp_path / "bundle.pem"
        write_ca_bundle(
            [("ACME Corp Root", "ACME Corp Root", _FAKE_DER, True)],
            str(out),
        )
        text = out.read_text(encoding="ascii")
        assert "ACME Corp Root" in text
        assert "BEGIN CERTIFICATE" in text

    def test_includes_corporate_marker_section(self, tmp_path):
        out = tmp_path / "bundle.pem"
        write_ca_bundle(
            [("Corp Root", "Corp Root", _FAKE_DER, True)],
            str(out),
        )
        text = out.read_text(encoding="ascii")
        assert "Corporate SSL inspection certificates" in text

    def test_multiple_corp_certs_all_included(self, tmp_path):
        out = tmp_path / "bundle.pem"
        write_ca_bundle(
            [
                ("Cert One", "Cert One", _FAKE_DER, True),
                ("Cert Two", "Cert Two", _FAKE_DER_2, True),
            ],
            str(out),
        )
        text = out.read_text(encoding="ascii")
        assert "Cert One" in text
        assert "Cert Two" in text

    def test_uses_lf_line_endings(self, tmp_path):
        out = tmp_path / "bundle.pem"
        write_ca_bundle(
            [("Test Cert", "Test Cert", _FAKE_DER, True)],
            str(out),
        )
        # Bundle is written in binary mode with LF endings explicitly
        raw = out.read_bytes()
        assert b"\r\n" not in raw

    def test_directory_path_appends_default_name(self, tmp_path):
        # Caller passes a directory; function should append ca-bundle.pem
        result = write_ca_bundle(
            [("Test Cert", "Test Cert", _FAKE_DER, True)],
            str(tmp_path),
        )
        assert result.endswith("ca-bundle.pem")
        assert os.path.exists(result)

    def test_creates_parent_directory(self, tmp_path):
        nested = tmp_path / "deep" / "deeper" / "bundle.pem"
        result = write_ca_bundle(
            [("Test", "Test", _FAKE_DER, True)],
            str(nested),
        )
        assert os.path.exists(result)

    def test_empty_corporate_certs_still_writes_baseline_bundle(self, tmp_path):
        # When no corp certs, we still write certifi (or system trust)
        out = tmp_path / "bundle.pem"
        result = write_ca_bundle([], str(out))
        assert os.path.exists(result)
        assert out.stat().st_size > 0  # certifi at minimum


class TestEnsureMitmCAInBundle:
    def _make_bundle(self, path: Path, corp_cert_subject: str) -> None:
        """Helper: create a bundle file with a single fake corp cert."""
        write_ca_bundle(
            [(corp_cert_subject, corp_cert_subject, _FAKE_DER, True)],
            str(path),
        )

    def test_no_mitm_ca_no_op(self, tmp_path, monkeypatch):
        # When ~/.config/configure_proxy/auth_proxy_ca.pem doesn't exist,
        # ensure_mitm_ca_in_bundle is a no-op.
        monkeypatch.setenv("HOME", str(tmp_path))
        if os.name == "nt":
            monkeypatch.setenv("USERPROFILE", str(tmp_path))
        bundle = tmp_path / "bundle.pem"
        self._make_bundle(bundle, "Corp Root")
        before = bundle.read_bytes()
        ensure_mitm_ca_in_bundle(str(bundle))
        assert bundle.read_bytes() == before

    def test_appends_mitm_ca_when_present(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        if os.name == "nt":
            monkeypatch.setenv("USERPROFILE", str(tmp_path))

        # Place a fake MITM CA where ensure_mitm_ca_in_bundle expects it
        ca_dir = tmp_path / ".config" / "configure_proxy"
        ca_dir.mkdir(parents=True)
        mitm_ca = ca_dir / "auth_proxy_ca.pem"
        mitm_pem = _der_to_pem(_FAKE_DER_2)
        mitm_ca.write_text(mitm_pem)

        bundle = tmp_path / "bundle.pem"
        self._make_bundle(bundle, "Corp Root")

        # Before: bundle has corp cert but not MITM CA's bytes
        # (write_ca_bundle does try to append MITM CA if file exists, but
        # the path it checks is the same; so it might already have it).
        # ensure_mitm_ca_in_bundle should at minimum be idempotent.
        ensure_mitm_ca_in_bundle(str(bundle))
        text = bundle.read_text(encoding="ascii")
        # MITM CA's PEM body should be present in the bundle
        assert mitm_pem.strip() in text.replace("\r\n", "\n")

    def test_idempotent_when_already_present(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        if os.name == "nt":
            monkeypatch.setenv("USERPROFILE", str(tmp_path))

        ca_dir = tmp_path / ".config" / "configure_proxy"
        ca_dir.mkdir(parents=True)
        mitm_ca = ca_dir / "auth_proxy_ca.pem"
        mitm_ca.write_text(_der_to_pem(_FAKE_DER_2))

        bundle = tmp_path / "bundle.pem"
        self._make_bundle(bundle, "Corp Root")

        ensure_mitm_ca_in_bundle(str(bundle))
        first = bundle.read_bytes()
        ensure_mitm_ca_in_bundle(str(bundle))
        second = bundle.read_bytes()
        # Second invocation should not have appended a duplicate
        assert first == second

    def test_does_nothing_when_bundle_missing(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("HOME", str(tmp_path))
        if os.name == "nt":
            monkeypatch.setenv("USERPROFILE", str(tmp_path))

        ca_dir = tmp_path / ".config" / "configure_proxy"
        ca_dir.mkdir(parents=True)
        mitm_ca = ca_dir / "auth_proxy_ca.pem"
        mitm_ca.write_text(_der_to_pem(_FAKE_DER_2))

        missing_bundle = tmp_path / "does_not_exist.pem"
        ensure_mitm_ca_in_bundle(str(missing_bundle))
        # Should print a warning, not raise, not create the file
        assert not missing_bundle.exists()
