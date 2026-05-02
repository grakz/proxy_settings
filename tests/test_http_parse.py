"""Tests for HTTP header / framing helpers in auth_proxy and mitm_handler."""

import pytest

import auth_proxy
import mitm_handler
from auth_proxy import (
    _content_length as auth_content_length,
    _parse_proxy_authenticate,
    _parse_status,
    _select_scheme,
    _strip_header,
)
from mitm_handler import (
    _content_length as mitm_content_length,
    _has_connection_close,
    _rewrite_response_for_buffered_body,
    get_header,
    remove_header,
    replace_header,
)


class TestParseStatus:
    def test_200(self):
        assert _parse_status(b"HTTP/1.1 200 OK\r\nFoo: bar")[0] == 200

    def test_407(self):
        status, reason = _parse_status(b"HTTP/1.1 407 Proxy Authentication Required\r\n")
        assert status == 407
        assert reason == "Proxy Authentication Required"

    def test_malformed_returns_zero(self):
        assert _parse_status(b"garbage")[0] == 0


class TestParseProxyAuthenticate:
    def test_single_scheme(self):
        result = _parse_proxy_authenticate(
            b"HTTP/1.1 407\r\nProxy-Authenticate: Negotiate\r\n"
        )
        assert result == [("Negotiate", None)]

    def test_multiple_schemes(self):
        result = _parse_proxy_authenticate(
            b"HTTP/1.1 407\r\n"
            b"Proxy-Authenticate: Negotiate\r\n"
            b"Proxy-Authenticate: NTLM\r\n"
        )
        assert ("Negotiate", None) in result
        assert ("NTLM", None) in result

    def test_with_challenge(self):
        result = _parse_proxy_authenticate(
            b"HTTP/1.1 407\r\nProxy-Authenticate: NTLM TlRMTVNTUAAB\r\n"
        )
        assert result == [("NTLM", "TlRMTVNTUAAB")]

    def test_case_insensitive_header_name(self):
        # Real proxies use various capitalisations
        result = _parse_proxy_authenticate(
            b"HTTP/1.1 407\r\nproxy-authenticate: NTLM\r\n"
        )
        assert result == [("NTLM", None)]


class TestContentLengthAuthProxy:
    def test_present(self):
        assert auth_content_length(b"HTTP/1.1 200\r\nContent-Length: 42\r\n") == 42

    def test_missing(self):
        assert auth_content_length(b"HTTP/1.1 200\r\nFoo: bar\r\n") == 0

    def test_invalid_returns_zero(self):
        assert auth_content_length(b"HTTP/1.1 200\r\nContent-Length: not-a-number\r\n") == 0

    def test_case_insensitive(self):
        assert auth_content_length(b"HTTP/1.1 200\r\ncontent-length: 7\r\n") == 7


class TestContentLengthMitmHandler:
    def test_present(self):
        assert mitm_content_length(b"HTTP/1.1 200\r\nContent-Length: 100\r\n") == 100

    def test_missing(self):
        assert mitm_content_length(b"HTTP/1.1 200\r\n") == 0


class TestSelectScheme:
    def test_negotiate_preferred(self):
        # Negotiate beats NTLM beats Basic
        assert _select_scheme([("NTLM", None), ("Negotiate", None)]) == "Negotiate"

    def test_ntlm_when_no_negotiate(self):
        assert _select_scheme([("NTLM", None), ("Basic", None)]) == "NTLM"

    def test_basic_as_last_resort(self):
        assert _select_scheme([("Basic", None)]) == "Basic"

    def test_unknown_returns_none(self):
        assert _select_scheme([("DigestStuff", None)]) is None

    def test_empty_returns_none(self):
        assert _select_scheme([]) is None


class TestStripHeader:
    def test_removes_named_header(self):
        head = b"GET /foo HTTP/1.1\r\nHost: x\r\nProxy-Authorization: NTLM blah\r\nContent-Length: 0"
        result = _strip_header(head, b"proxy-authorization")
        assert b"Proxy-Authorization" not in result
        assert b"Host: x" in result
        assert b"Content-Length: 0" in result

    def test_case_insensitive(self):
        head = b"GET / HTTP/1.1\r\nproxy-authorization: NTLM blah"
        result = _strip_header(head, b"PROXY-AUTHORIZATION")
        assert b"proxy-authorization" not in result.lower()

    def test_strips_all_occurrences(self):
        head = b"GET / HTTP/1.1\r\nX-Foo: 1\r\nX-Foo: 2\r\nHost: x"
        result = _strip_header(head, b"x-foo")
        assert b"X-Foo" not in result
        assert b"Host: x" in result

    def test_no_match_unchanged(self):
        head = b"GET / HTTP/1.1\r\nHost: x"
        assert _strip_header(head, b"nonexistent") == head


class TestReplaceHeader:
    def test_replaces_existing(self):
        head = b"HTTP/1.1 200\r\nContent-Length: 100\r\nServer: x"
        result = replace_header(head, "Content-Length", "0")
        assert b"Content-Length: 0" in result
        assert b"Content-Length: 100" not in result

    def test_adds_when_missing(self):
        head = b"HTTP/1.1 200\r\nServer: x"
        result = replace_header(head, "Content-Length", "0")
        assert b"Content-Length: 0" in result

    def test_drops_duplicates(self):
        head = b"HTTP/1.1 200\r\nX-Foo: 1\r\nX-Foo: 2"
        result = replace_header(head, "X-Foo", "3")
        # Should keep exactly one X-Foo
        assert result.count(b"X-Foo:") == 1
        assert b"X-Foo: 3" in result


class TestRemoveHeader:
    def test_removes(self):
        head = b"HTTP/1.1 200\r\nServer: x\r\nContent-Length: 100"
        result = remove_header(head, "Content-Length")
        assert b"Content-Length" not in result
        assert b"Server: x" in result

    def test_case_insensitive(self):
        head = b"HTTP/1.1 200\r\ncontent-length: 100"
        result = remove_header(head, "Content-Length")
        assert b"content-length" not in result.lower()


class TestGetHeader:
    def test_returns_value(self):
        head = b"HTTP/1.1 200\r\nContent-Type: application/json\r\nServer: nginx"
        assert get_header(head, "Content-Type") == "application/json"

    def test_case_insensitive_lookup(self):
        head = b"HTTP/1.1 200\r\nContent-Type: text/html"
        assert get_header(head, "content-type") == "text/html"

    def test_missing_returns_none(self):
        head = b"HTTP/1.1 200\r\nServer: nginx"
        assert get_header(head, "Content-Type") is None

    def test_returns_first_when_duplicates(self):
        head = b"HTTP/1.1 200\r\nX-Foo: a\r\nX-Foo: b"
        assert get_header(head, "X-Foo") == "a"


class TestHasConnectionClose:
    def test_true(self):
        head = b"HTTP/1.1 200\r\nConnection: close\r\nServer: x"
        assert _has_connection_close(head) is True

    def test_false_keep_alive(self):
        head = b"HTTP/1.1 200\r\nConnection: keep-alive"
        assert _has_connection_close(head) is False

    def test_false_no_header(self):
        head = b"HTTP/1.1 200\r\nServer: x"
        assert _has_connection_close(head) is False

    def test_case_insensitive_value(self):
        head = b"HTTP/1.1 200\r\nConnection: Close"
        assert _has_connection_close(head) is True


class TestRewriteResponseForBufferedBody:
    def test_drops_chunked_adds_content_length(self):
        head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream"
        result = _rewrite_response_for_buffered_body(head, 1234)
        assert b"Transfer-Encoding" not in result
        assert b"Content-Length: 1234" in result
        assert b"Content-Type: application/octet-stream" in result

    def test_replaces_existing_content_length(self):
        head = b"HTTP/1.1 200\r\nContent-Length: 999\r\nServer: x"
        result = _rewrite_response_for_buffered_body(head, 42)
        assert b"Content-Length: 42" in result
        assert b"Content-Length: 999" not in result

    def test_preserves_status_line(self):
        head = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 1"
        result = _rewrite_response_for_buffered_body(head, 5)
        assert result.split(b"\r\n", 1)[0] == b"HTTP/1.1 206 Partial Content"
