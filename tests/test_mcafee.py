"""Tests for the McAfee Web Gateway state-machine helpers in mitm_handler."""

import re

import pytest

from mitm_handler import (
    _build_poll_url,
    _build_synthesized_response,
    classify_mcafee_response,
    extract_ready_link,
    parse_poll_response,
)
from mitm_handler import McAfeeState


# Realistic minimal MWG page bodies. These mirror the regexes in the module:
# the WAITING page contains "Please Wait" and a progresspageid hidden meta;
# the READY page contains an `<a href=".../&dl">` link.

_WAITING_BODY = b"""
<html>
<head>
<meta id="progresspageid" content="abc123" />
</head>
<body>
<p>Please Wait - scanning your file for viruses</p>
<script>
function printProgressBar(p) { /* ... */ }
setInterval(function(){ /* poll */ }, 3000);
</script>
</body>
</html>
"""

_READY_BODY = b"""
<html>
<body>
<p>Your download has been scanned and is ready.</p>
<a href="/mwg-internal/de5fs23hu73ds/progress?id=abc123&amp;dl">Click here to get the file</a>
</body>
</html>
"""

_POLL_BODY = b"1234567;7000000;30;0;5"
_POLL_BODY_READY = b"7000000;7000000;100;1;42"


class TestClassifyMcafeeResponse:
    def test_waiting_page(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        # Body must contain the mwg-internal marker
        body = _WAITING_BODY + b"<!-- mwg-internal/foo -->"
        assert classify_mcafee_response(head, body) == McAfeeState.WAITING

    def test_ready_page(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        # _READY_BODY already contains the mwg-internal href
        assert classify_mcafee_response(head, _READY_BODY) == McAfeeState.READY

    def test_poll_response(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        assert classify_mcafee_response(head, _POLL_BODY) == McAfeeState.POLL

    def test_normal_html_is_not_mcafee(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        body = b"<html><body>just a regular site</body></html>"
        assert classify_mcafee_response(head, body) == McAfeeState.NOT_MCAFEE

    def test_empty_body(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        assert classify_mcafee_response(head, b"") == McAfeeState.NOT_MCAFEE

    def test_none_body(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        assert classify_mcafee_response(head, None) == McAfeeState.NOT_MCAFEE

    def test_html_without_mwg_marker_not_mcafee(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        # "Please Wait" alone, but no mwg-internal marker
        body = b"<html>Please Wait</html>"
        assert classify_mcafee_response(head, body) == McAfeeState.NOT_MCAFEE


class TestExtractReadyLink:
    def test_extracts_from_ready_page(self):
        link = extract_ready_link(_READY_BODY, "https://registry.npmjs.org/foo")
        assert link is not None
        assert "/mwg-internal/" in link
        assert "&dl" in link

    def test_decodes_amp_entity(self):
        # Page uses &amp;dl — extract should produce literal &dl
        link = extract_ready_link(_READY_BODY, "https://example.com/")
        assert "&amp;" not in link
        assert "&dl" in link

    def test_relative_link_resolved_against_base(self):
        link = extract_ready_link(_READY_BODY, "https://npm.example.com/path/file.tgz")
        assert link.startswith("https://npm.example.com/")

    def test_returns_none_when_no_link(self):
        assert extract_ready_link(b"<html>no link here</html>", "https://x/") is None


class TestParsePollResponse:
    def test_parses_progress(self):
        info = parse_poll_response(_POLL_BODY)
        assert info is not None
        assert info["downloaded"] == "1234567"
        assert info["total"] == "7000000"
        assert info["percent"] == "30"
        assert info["ready"] is False
        assert info["scan_seconds"] == "5"

    def test_ready_flag_set(self):
        info = parse_poll_response(_POLL_BODY_READY)
        assert info["ready"] is True

    def test_invalid_returns_none(self):
        assert parse_poll_response(b"not a poll response") is None

    def test_too_few_fields_returns_none(self):
        assert parse_poll_response(b"a;b;c") is None


class TestBuildPollURL:
    def test_appends_query_when_none_present(self):
        url = _build_poll_url("/mwg-internal/abc/progress")
        assert "?a=1&" in url
        assert url.startswith("/mwg-internal/abc/progress")

    def test_appends_with_existing_query(self):
        url = _build_poll_url("/mwg-internal/abc/progress?id=xyz")
        assert "&a=1&" in url
        # Don't break the existing param
        assert "id=xyz" in url

    def test_includes_timestamp(self):
        url = _build_poll_url("/p")
        # Timestamp is the millisecond epoch — must be a long integer at the end
        m = re.search(r"a=1&(\d+)$", url)
        assert m is not None
        ts = int(m.group(1))
        assert ts > 1_000_000_000_000  # post-2001 in milliseconds


class TestBuildSynthesizedResponse:
    def test_includes_content_length(self):
        head = _build_synthesized_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream",
            b"hello world",
        )
        assert b"Content-Length: 11" in head

    def test_preserves_content_type(self):
        head = _build_synthesized_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/x-tar",
            b"data",
        )
        assert b"Content-Type: application/x-tar" in head

    def test_default_content_type_when_missing(self):
        head = _build_synthesized_response(b"HTTP/1.1 200 OK", b"x")
        assert b"application/octet-stream" in head

    def test_marks_as_mitm_synthesized(self):
        head = _build_synthesized_response(b"HTTP/1.1 200 OK", b"x")
        assert b"X-MITM-Source" in head

    def test_status_is_200(self):
        head = _build_synthesized_response(b"HTTP/1.1 304 Not Modified", b"x")
        # We always synthesize a 200 — the original status is irrelevant
        assert head.startswith(b"HTTP/1.1 200")
