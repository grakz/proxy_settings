"""Tests for misc helpers in configure_proxy: NO_PROXY, frozen-mode dispatch,
flag-name parsing, pip config path."""

import os
import sys

import pytest

import configure_proxy
from configure_proxy import (
    _auth_proxy_command_prefix,
    _pip_config_path,
    _user_specified_flags,
    get_no_proxy,
    tool_available,
)


class TestGetNoProxy:
    def test_uppercase_env_var(self, monkeypatch):
        monkeypatch.setenv("NO_PROXY", "localhost,internal.corp")
        monkeypatch.delenv("no_proxy", raising=False)
        assert get_no_proxy() == "localhost,internal.corp"

    def test_lowercase_env_var(self, monkeypatch):
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.setenv("no_proxy", "localhost,internal.corp")
        assert get_no_proxy() == "localhost,internal.corp"

    def test_uppercase_wins_over_lowercase(self, monkeypatch):
        monkeypatch.setenv("NO_PROXY", "win.corp")
        monkeypatch.setenv("no_proxy", "lose.corp")
        assert get_no_proxy() == "win.corp"

    def test_returns_none_when_unset_on_non_windows(self, monkeypatch):
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        if sys.platform != "win32":
            assert get_no_proxy() is None


class TestUserSpecifiedFlags:
    def test_empty(self):
        assert _user_specified_flags([]) == set()

    def test_long_flags(self):
        flags = _user_specified_flags(["--proxy", "http://x", "--dry-run"])
        assert "proxy" in flags
        assert "dry_run" in flags

    def test_dashes_to_underscores(self):
        flags = _user_specified_flags(["--auth-proxy", "always"])
        assert "auth_proxy" in flags

    def test_equals_form(self):
        flags = _user_specified_flags(["--proxy=http://x"])
        assert "proxy" in flags

    def test_ignores_positional(self):
        flags = _user_specified_flags(["positional", "--flag"])
        assert flags == {"flag"}


class TestAuthProxyCommandPrefix:
    def test_normal_python_invocation(self, monkeypatch):
        # When not frozen, returns [executable, /path/to/auth_proxy.py] if it exists
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        prefix = _auth_proxy_command_prefix()
        assert prefix is not None
        assert prefix[0] == sys.executable
        assert prefix[1].endswith("auth_proxy.py")
        assert os.path.exists(prefix[1])

    def test_frozen_uses_sentinel(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        try:
            prefix = _auth_proxy_command_prefix()
        finally:
            monkeypatch.delattr(sys, "frozen", raising=False)
        assert prefix == [sys.executable, "__auth_proxy__"]


class TestPipConfigPath:
    def test_returns_string(self):
        path = _pip_config_path()
        assert isinstance(path, str)
        assert path  # non-empty

    def test_platform_correct_basename(self):
        path = _pip_config_path()
        if sys.platform == "win32":
            assert path.endswith("pip.ini")
        else:
            assert path.endswith("pip.conf")


class TestToolAvailable:
    def test_python_is_available(self):
        # The interpreter we're running under must be findable somewhere
        # — we can't trust 'python' to be on PATH on every CI, but 'python3'
        # is conventional on Linux and 'python' on Windows.
        assert tool_available(sys.executable) or tool_available("python3") or tool_available("python")

    def test_nonsense_is_not_available(self):
        assert not tool_available("definitely-not-a-real-binary-x73y")
