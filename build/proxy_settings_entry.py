"""
Entry point for the bundled proxy_settings.exe (PyInstaller --onefile).

The single bundled binary doubles as both the main configurator and the auth
proxy daemon. configure_proxy.py spawns the daemon as a subprocess, and when
running frozen it re-invokes the same exe with a sentinel first argument that
this dispatcher routes into auth_proxy.main().

Imports are explicit rather than lazy so PyInstaller's analyzer collects all
three modules — this keeps the bundle self-contained without any --hidden-import
or --add-data wiring in the build script.
"""

import sys

import auth_proxy
import configure_proxy
import mitm_handler  # noqa: F401  (transitive: auth_proxy imports it lazily under --mitm)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "__auth_proxy__":
        # Re-invocation from configure_proxy.start_auth_proxy() under --frozen.
        # Drop the sentinel so auth_proxy.main() sees a normal argv.
        sys.argv.pop(1)
        return auth_proxy.main() or 0
    return configure_proxy.main() or 0


if __name__ == "__main__":
    sys.exit(main())
