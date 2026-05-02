"""Tests for URL/proxy parsing helpers in configure_proxy."""

import pytest

from configure_proxy import (
    _is_loopback_proxy,
    normalize_proxy_url,
    parse_registry_proxy,
    redact,
)


class TestNormalizeProxyURL:
    def test_adds_http_scheme_when_missing(self):
        assert normalize_proxy_url("proxy.corp:8080") == "http://proxy.corp:8080"

    def test_preserves_existing_http(self):
        assert normalize_proxy_url("http://proxy.corp:8080") == "http://proxy.corp:8080"

    def test_preserves_existing_https(self):
        assert normalize_proxy_url("https://proxy.corp:443") == "https://proxy.corp:443"

    def test_strips_whitespace(self):
        assert normalize_proxy_url("  proxy.corp:8080  ") == "http://proxy.corp:8080"

    def test_empty_returns_none(self):
        assert normalize_proxy_url("") is None

    def test_whitespace_only_returns_none(self):
        assert normalize_proxy_url("   \t\n") is None


class TestParseRegistryProxy:
    def test_simple_form_no_equals(self):
        assert parse_registry_proxy("proxy.corp:8080") == "http://proxy.corp:8080"

    def test_https_preferred_over_http(self):
        result = parse_registry_proxy("http=p1.corp:80;https=p2.corp:443")
        assert result == "http://p2.corp:443"

    def test_http_only(self):
        assert parse_registry_proxy("http=p1.corp:80") == "http://p1.corp:80"

    def test_https_only(self):
        assert parse_registry_proxy("https=p1.corp:443") == "http://p1.corp:443"

    def test_falls_back_to_first_other_scheme(self):
        # No http/https — pick whatever's first
        assert parse_registry_proxy("ftp=ftpproxy.corp:21") == "http://ftpproxy.corp:21"

    def test_handles_extra_whitespace(self):
        assert parse_registry_proxy("http = p.corp:80 ; https = q.corp:443") == "http://q.corp:443"


class TestIsLoopbackProxy:
    @pytest.mark.parametrize("url", [
        "http://localhost:3128",
        "http://LOCALHOST:3128",
        "http://127.0.0.1:3128",
        "http://127.0.0.1",
        "http://127.99.255.1:8080",
        "http://[::1]:3128",
    ])
    def test_loopback_variants(self, url):
        assert _is_loopback_proxy(url)

    @pytest.mark.parametrize("url", [
        "http://proxy.corp:8080",
        "http://10.0.0.1:8080",
        "http://192.168.1.1:8080",
        "http://example.com",
        "",
        None,
    ])
    def test_non_loopback(self, url):
        assert not _is_loopback_proxy(url)

    def test_garbage_is_not_loopback(self):
        # Hostname that starts with "127." but isn't an IP shouldn't false-positive
        assert not _is_loopback_proxy("http://127.example.com:8080")


class TestRedact:
    def test_strips_basic_auth_credentials(self):
        result = redact("http://user:pass@proxy.corp:8080")
        assert "user" not in result
        assert "pass" not in result
        assert "***:***" in result

    def test_passes_through_when_no_auth(self):
        url = "http://proxy.corp:8080"
        assert redact(url) == url

    def test_keeps_host_and_port(self):
        result = redact("http://alice:secret@proxy.corp:8080/path")
        assert "proxy.corp" in result
        assert "8080" in result

    def test_preserves_path(self):
        result = redact("http://u:p@proxy.corp:8080/wpad.dat")
        assert "/wpad.dat" in result

    def test_handles_invalid_url(self):
        # Should not raise on garbage input — just return it
        assert redact("not a url") == "not a url"
