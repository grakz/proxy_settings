"""Pytest configuration and shared fixtures.

Makes the project root importable so tests can `import configure_proxy`,
`import auth_proxy`, `import mitm_handler` directly. The three project
modules avoid Windows-only imports at module level (everything Windows-
specific — winreg, sspi, etc. — is deferred into functions), so they
import cleanly on Linux CI.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
