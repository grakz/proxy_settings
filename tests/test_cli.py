"""End-to-end CLI smoke tests. Spawn the actual scripts via subprocess to
verify --help, --show-config, --reset-config, dry-run flow, and that the
auth_proxy entry script accepts its expected flags."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CONFIGURE_PROXY = ROOT / "configure_proxy.py"
AUTH_PROXY = ROOT / "auth_proxy.py"


def _run(*argv, env=None, timeout=30):
    """Helper: run a subprocess, capture both streams, never raise on non-zero."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=full_env,
    )


class TestConfigureProxyCLI:
    def test_help_exits_zero(self):
        r = _run(str(CONFIGURE_PROXY), "--help")
        assert r.returncode == 0
        assert "usage" in r.stdout.lower()

    def test_help_lists_flags(self):
        r = _run(str(CONFIGURE_PROXY), "--help")
        # A few specific flags should be advertised
        for flag in ("--proxy", "--pac-url", "--mitm", "--auth-proxy",
                     "--unset", "--dry-run", "--no-ca", "--ca-import"):
            assert flag in r.stdout, f"{flag} not advertised in --help"

    def test_show_config_no_persisted_state(self, tmp_path):
        # Point HOME at a fresh empty dir so there's no persisted config
        env = {"HOME": str(tmp_path)}
        if sys.platform == "win32":
            env["USERPROFILE"] = str(tmp_path)
        r = _run(str(CONFIGURE_PROXY), "--show-config", env=env)
        assert r.returncode == 0
        assert "no persisted config" in r.stdout.lower()

    def test_reset_config_idempotent(self, tmp_path):
        env = {"HOME": str(tmp_path)}
        if sys.platform == "win32":
            env["USERPROFILE"] = str(tmp_path)
        # First call: nothing to remove
        r1 = _run(str(CONFIGURE_PROXY), "--reset-config", env=env)
        assert r1.returncode == 0
        # Second call: still works (nothing to remove again)
        r2 = _run(str(CONFIGURE_PROXY), "--reset-config", env=env)
        assert r2.returncode == 0

    def test_dry_run_with_explicit_proxy(self, tmp_path):
        # Dry-run with --proxy + --no-ca + --auth-proxy never to keep it
        # entirely offline and OS-independent.
        env = {
            "HOME": str(tmp_path),
            # Make sure no real proxy env vars leak in and short-circuit
            "HTTPS_PROXY": "",
            "HTTP_PROXY": "",
            "NO_PROXY": "",
        }
        if sys.platform == "win32":
            env["USERPROFILE"] = str(tmp_path)
        r = _run(
            str(CONFIGURE_PROXY),
            "--dry-run", "--no-save", "--no-ca",
            "--auth-proxy", "never",
            "--proxy", "http://corp.proxy:8080",
            env=env,
        )
        # Dry-run with explicit proxy should always succeed and print what
        # it would do.
        assert r.returncode == 0, f"stderr: {r.stderr}"
        assert "corp.proxy:8080" in r.stdout
        assert "dry-run" in r.stdout.lower()

    def test_unknown_flag_errors(self):
        r = _run(str(CONFIGURE_PROXY), "--this-flag-does-not-exist")
        assert r.returncode != 0


class TestAuthProxyCLI:
    def test_help_exits_zero(self):
        r = _run(str(AUTH_PROXY), "--help")
        assert r.returncode == 0
        assert "usage" in r.stdout.lower()

    def test_help_lists_subcommands(self):
        r = _run(str(AUTH_PROXY), "--help")
        for flag in ("--start", "--stop", "--status", "--mitm", "--upstream"):
            assert flag in r.stdout, f"{flag} not advertised in --help"

    def test_status_when_not_running(self, tmp_path):
        env = {"HOME": str(tmp_path)}
        if sys.platform == "win32":
            env["USERPROFILE"] = str(tmp_path)
        r = _run(str(AUTH_PROXY), "--status", env=env)
        # Exit code 1 is the contract when daemon is not running
        assert r.returncode == 1
        assert "not running" in r.stdout.lower()

    def test_start_without_upstream_errors(self):
        r = _run(str(AUTH_PROXY), "--start")
        assert r.returncode != 0
        assert "upstream" in (r.stdout + r.stderr).lower()
