"""Tests for CA-utility helpers: PEM/DER conversion, microsoft-root heuristic,
inspection-likelihood scoring. Pure-logic, no network or registry."""

import pytest

from configure_proxy import (
    _der_to_pem,
    _is_microsoft_root,
    _score_inspection_likelihood,
    _split_pem_to_der,
)


# A minimal real DER cert (a 2048-bit self-signed test cert); generated once
# and embedded so the tests don't depend on network access. Subject CN: "test-ca".
_FAKE_DER = bytes.fromhex(
    # We don't actually need the bytes to be a real cert for the round-trip
    # test — just for it to be PEM-encoded then parsed back consistently.
    # We use a syntactically-valid DER prefix (SEQUENCE header) for realism.
    "30820100" + "00" * 252
)


class TestDerToPem:
    def test_wraps_in_begin_end_markers(self):
        pem = _der_to_pem(_FAKE_DER)
        assert pem.startswith("-----BEGIN CERTIFICATE-----\n")
        assert pem.rstrip().endswith("-----END CERTIFICATE-----")

    def test_emits_base64(self):
        pem = _der_to_pem(_FAKE_DER)
        # Body between markers should be ASCII base64
        body = pem.split("-----BEGIN CERTIFICATE-----\n")[1]
        body = body.split("-----END CERTIFICATE-----")[0].strip()
        import base64
        decoded = base64.b64decode(body)
        assert decoded == _FAKE_DER


class TestSplitPemToDer:
    def test_round_trip(self):
        pem = _der_to_pem(_FAKE_DER)
        recovered = _split_pem_to_der(pem.encode("ascii"))
        assert len(recovered) == 1
        assert recovered[0] == _FAKE_DER

    def test_multiple_certs(self):
        pem = _der_to_pem(_FAKE_DER) + _der_to_pem(_FAKE_DER)
        recovered = _split_pem_to_der(pem.encode("ascii"))
        assert len(recovered) == 2
        assert recovered[0] == _FAKE_DER
        assert recovered[1] == _FAKE_DER

    def test_handles_extra_text_outside_markers(self):
        pem = "# leading comment\n" + _der_to_pem(_FAKE_DER) + "trailing junk\n"
        recovered = _split_pem_to_der(pem.encode("ascii"))
        assert len(recovered) == 1

    def test_no_certs_returns_empty(self):
        recovered = _split_pem_to_der(b"# nothing here\n")
        assert recovered == []


class TestIsMicrosoftRoot:
    @pytest.mark.parametrize("subject", [
        "Microsoft Root Certificate Authority",
        "Microsoft Root Authority",
        "microsoft authenticode (R) Root",
        "Microsoft Code Verification Root",
        "Microsoft ECC TS Root Certificate Authority 2018",
        "Microsoft RSA Root Certificate Authority 2017",
        "Microsoft Time-Stamp PCA",
        "Microsoft Identity Verification Root",
    ])
    def test_recognises_microsoft_roots(self, subject):
        assert _is_microsoft_root(subject, subject) is True

    @pytest.mark.parametrize("subject", [
        "Zscaler Root CA",
        "Netskope Certification Authority",
        "BlueCoat SG Issuing CA",
        "DigiCert Global Root CA",
        "ACME Internal Root CA",
    ])
    def test_rejects_non_microsoft(self, subject):
        assert _is_microsoft_root(subject, subject) is False

    def test_handles_none(self):
        assert _is_microsoft_root(None, None) is False

    def test_handles_empty(self):
        assert _is_microsoft_root("", "") is False


class TestScoreInspectionLikelihood:
    def test_zscaler_scores_high(self):
        score = _score_inspection_likelihood(
            "Zscaler Root CA", "Zscaler Root CA", _FAKE_DER,
        )
        assert score >= 50  # vendor-name hit

    def test_bluecoat_scores_high(self):
        score = _score_inspection_likelihood(
            "BlueCoat SG", "BlueCoat SG", _FAKE_DER,
        )
        assert score >= 50

    def test_generic_proxy_ca_scores_high(self):
        score = _score_inspection_likelihood(
            "Acme Corp Proxy CA", "Acme Corp Proxy CA", _FAKE_DER,
        )
        assert score >= 50  # "proxy ca" hit

    def test_unrelated_name_scores_low(self):
        score = _score_inspection_likelihood(
            "DigiCert Global Root CA", "DigiCert Global Root CA", _FAKE_DER,
        )
        # No vendor hit, no "root ca" or "issuing ca" → low score
        assert score < 50

    def test_root_ca_hint_adds_a_little(self):
        score = _score_inspection_likelihood(
            "Acme Internal Root CA", "Acme Internal Root CA", _FAKE_DER,
        )
        # "root ca" present but no vendor → small positive
        assert 0 < score < 50

    def test_handles_none_inputs(self):
        # Should not raise; returns some integer
        score = _score_inspection_likelihood(None, None, _FAKE_DER)
        assert isinstance(score, int)
