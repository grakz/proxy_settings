"""Tests for the built-in Python PAC evaluator and result parser."""

import pytest

from configure_proxy import (
    _eval_pac_condition,
    _extract_pac_statements,
    _interpret_pac_string,
    _make_pac_helpers,
    _split_top_level,
    evaluate_pac_in_python,
    parse_pac_result,
)


class TestParsePACResult:
    def test_simple_proxy(self):
        kind, url = parse_pac_result("PROXY proxy.corp:8080")
        assert kind == "proxy"
        assert url == "http://proxy.corp:8080"

    def test_direct(self):
        kind, url = parse_pac_result("DIRECT")
        assert kind == "direct"
        assert url is None

    def test_picks_first_proxy_over_direct(self):
        kind, url = parse_pac_result("PROXY p1:80; DIRECT")
        assert kind == "proxy"
        assert url == "http://p1:80"

    def test_picks_first_proxy_when_multiple(self):
        kind, url = parse_pac_result("PROXY p1:80; PROXY p2:80")
        assert kind == "proxy"
        assert url == "http://p1:80"

    def test_https_proxy_kind(self):
        kind, url = parse_pac_result("HTTPS proxy.corp:443")
        assert kind == "proxy"
        assert url == "https://proxy.corp:443"

    def test_http_alias_for_proxy(self):
        kind, url = parse_pac_result("HTTP proxy.corp:80")
        assert kind == "proxy"
        assert url == "http://proxy.corp:80"

    def test_socks5(self):
        kind, url = parse_pac_result("SOCKS5 sox.corp:1080")
        assert kind == "proxy"
        assert url.startswith("socks5://")

    def test_socks4(self):
        kind, url = parse_pac_result("SOCKS4 sox.corp:1080")
        assert kind == "proxy"
        assert url.startswith("socks4://")

    def test_empty(self):
        kind, url = parse_pac_result("")
        assert kind is None and url is None

    def test_none(self):
        kind, url = parse_pac_result(None)
        assert kind is None and url is None

    def test_unknown_directive(self):
        kind, url = parse_pac_result("BANANA something")
        assert kind is None and url is None


class TestPACHelpers:
    def setup_method(self):
        self.helpers = _make_pac_helpers("registry.npmjs.org")

    def test_shexp_match_star(self):
        assert self.helpers["shExpMatch"]("foo.example.com", "*.example.com") is True
        assert self.helpers["shExpMatch"]("example.com", "*.example.com") is False

    def test_shexp_match_question(self):
        assert self.helpers["shExpMatch"]("a.com", "?.com") is True
        assert self.helpers["shExpMatch"]("ab.com", "?.com") is False

    def test_dns_domain_is(self):
        assert self.helpers["dnsDomainIs"]("foo.example.com", ".example.com")
        assert self.helpers["dnsDomainIs"]("example.com", "example.com")
        assert not self.helpers["dnsDomainIs"]("notexample.com", ".example.com")

    def test_is_plain_host_name(self):
        assert self.helpers["isPlainHostName"]("intranet")
        assert not self.helpers["isPlainHostName"]("intranet.corp")

    def test_dns_domain_levels(self):
        assert self.helpers["dnsDomainLevels"]("a.b.c") == 2
        assert self.helpers["dnsDomainLevels"]("plain") == 0

    def test_is_in_net_match(self):
        assert self.helpers["isInNet"]("10.1.2.3", "10.0.0.0", "255.0.0.0")

    def test_is_in_net_no_match(self):
        assert not self.helpers["isInNet"]("11.1.2.3", "10.0.0.0", "255.0.0.0")

    def test_is_in_net_invalid_input(self):
        # Garbage shouldn't raise
        assert not self.helpers["isInNet"]("not.a.host.at.all", "10.0.0.0", "255.0.0.0")


class TestEvaluatePACInPython:
    def test_direct_only(self):
        pac = """
        function FindProxyForURL(url, host) {
            return "DIRECT";
        }
        """
        assert evaluate_pac_in_python(pac, "https://example.com/", "example.com") == "DIRECT"

    def test_simple_if_else(self):
        pac = """
        function FindProxyForURL(url, host) {
            if (isPlainHostName(host)) return "DIRECT";
            return "PROXY proxy.corp:8080";
        }
        """
        # Plain host -> DIRECT
        assert evaluate_pac_in_python(pac, "http://intranet/", "intranet") == "DIRECT"
        # FQDN -> PROXY
        assert evaluate_pac_in_python(pac, "http://github.com/", "github.com") == "PROXY proxy.corp:8080"

    def test_dns_domain_is(self):
        pac = """
        function FindProxyForURL(url, host) {
            if (dnsDomainIs(host, ".internal.corp")) return "DIRECT";
            return "PROXY proxy.corp:8080";
        }
        """
        assert evaluate_pac_in_python(pac, "http://app.internal.corp/", "app.internal.corp") == "DIRECT"
        assert evaluate_pac_in_python(pac, "http://github.com/", "github.com") == "PROXY proxy.corp:8080"

    def test_shexp_match(self):
        pac = """
        function FindProxyForURL(url, host) {
            if (shExpMatch(host, "*.allowed.com")) return "DIRECT";
            return "PROXY p:80";
        }
        """
        assert evaluate_pac_in_python(pac, "http://x.allowed.com/", "x.allowed.com") == "DIRECT"
        assert evaluate_pac_in_python(pac, "http://elsewhere.com/", "elsewhere.com") == "PROXY p:80"

    def test_braced_block(self):
        pac = """
        function FindProxyForURL(url, host) {
            if (isPlainHostName(host)) {
                return "DIRECT";
            }
            return "PROXY p:80";
        }
        """
        assert evaluate_pac_in_python(pac, "http://intranet/", "intranet") == "DIRECT"

    def test_concatenated_string_return(self):
        pac = """
        function FindProxyForURL(url, host) {
            return "PROXY " + "host:port";
        }
        """
        assert evaluate_pac_in_python(pac, "http://x/", "x") == "PROXY host:port"

    def test_or_in_condition(self):
        pac = """
        function FindProxyForURL(url, host) {
            if (dnsDomainIs(host, ".a.com") || dnsDomainIs(host, ".b.com")) return "DIRECT";
            return "PROXY p:80";
        }
        """
        assert evaluate_pac_in_python(pac, "http://x.a.com/", "x.a.com") == "DIRECT"
        assert evaluate_pac_in_python(pac, "http://x.b.com/", "x.b.com") == "DIRECT"
        assert evaluate_pac_in_python(pac, "http://x.c.com/", "x.c.com") == "PROXY p:80"

    def test_negation(self):
        pac = """
        function FindProxyForURL(url, host) {
            if (!isPlainHostName(host)) return "PROXY p:80";
            return "DIRECT";
        }
        """
        assert evaluate_pac_in_python(pac, "http://intranet/", "intranet") == "DIRECT"
        assert evaluate_pac_in_python(pac, "http://example.com/", "example.com") == "PROXY p:80"

    def test_comments_are_skipped(self):
        pac = """
        function FindProxyForURL(url, host) {
            // single-line comment
            /* block
               comment */
            return "DIRECT";
        }
        """
        assert evaluate_pac_in_python(pac, "http://x/", "x") == "DIRECT"

    def test_no_findproxyforurl_returns_none(self):
        assert evaluate_pac_in_python("var x = 1;", "http://x/", "x") is None


class TestEvalPACConditionRefuses:
    def test_refuses_function_keyword(self):
        with pytest.raises(ValueError):
            _eval_pac_condition("function() { return true; }", "u", "h", _make_pac_helpers("h"))

    def test_refuses_arrow_function(self):
        with pytest.raises(ValueError):
            _eval_pac_condition("(()=>true)()", "u", "h", _make_pac_helpers("h"))

    def test_refuses_require(self):
        with pytest.raises(ValueError):
            _eval_pac_condition("require('fs')", "u", "h", _make_pac_helpers("h"))

    def test_refuses_dunder(self):
        with pytest.raises(ValueError):
            _eval_pac_condition("__import__('os')", "u", "h", _make_pac_helpers("h"))


class TestInterpretPACString:
    def test_double_quoted(self):
        assert _interpret_pac_string('"hello"') == "hello"

    def test_single_quoted(self):
        assert _interpret_pac_string("'world'") == "world"

    def test_concat(self):
        assert _interpret_pac_string('"a" + "b"') == "ab"

    def test_concat_with_whitespace(self):
        assert _interpret_pac_string('"PROXY " + "host:port"') == "PROXY host:port"


class TestSplitTopLevel:
    def test_simple(self):
        assert _split_top_level("a+b+c", "+") == ["a", "b", "c"]

    def test_respects_quotes(self):
        # The "+" inside quotes shouldn't split
        assert _split_top_level('"a+b"+"c"', "+") == ['"a+b"', '"c"']

    def test_respects_parens(self):
        # The "+" inside parens shouldn't split at top level
        assert _split_top_level("a+(b+c)+d", "+") == ["a", "(b+c)", "d"]


class TestExtractPACStatements:
    def test_unconditional_return(self):
        stmts = _extract_pac_statements('return "DIRECT";')
        assert stmts == [(None, '"DIRECT"')]

    def test_if_with_inline_return(self):
        stmts = _extract_pac_statements('if (cond) return "X";')
        assert stmts == [("cond", '"X"')]

    def test_if_with_braced_return(self):
        stmts = _extract_pac_statements('if (cond) { return "X"; }')
        assert stmts == [("cond", '"X"')]

    def test_multiple_statements(self):
        body = '''
            if (a) return "A";
            if (b) return "B";
            return "C";
        '''
        stmts = _extract_pac_statements(body)
        # Three statements: two conditional, one unconditional
        assert len(stmts) == 3
        assert stmts[0] == ("a", '"A"')
        assert stmts[1] == ("b", '"B"')
        assert stmts[2] == (None, '"C"')
