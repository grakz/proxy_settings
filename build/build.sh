#!/usr/bin/env bash
# Build a standalone Windows x64 executable for proxy_settings.
#
# Designed to run in Git Bash on Windows. Produces a single self-contained
# .exe that bundles the Python interpreter, all three project scripts,
# pywin32 (for SSPI auth), cryptography (for the McAfee MITM workaround),
# and certifi.
#
# Requirements on the build host:
#   - Python 3.10+ on PATH (`py -3` or `python` or `python3`).
#   - Internet access on first run, for pip to fetch build dependencies into
#     the local venv. Subsequent runs are offline-friendly.
#
# Optional but recommended:
#   - upx on PATH. Cuts the resulting binary by roughly 30-50%.
#       choco install upx -y       # if you have Chocolatey
#       scoop install upx          # if you have Scoop
#       https://upx.github.io/     # download a release zip and add to PATH
#
# Output:
#   build/dist/proxy_settings.exe
#
# Re-running the script reuses the venv under build/.venv. To rebuild from
# scratch, delete that directory and run again.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
DIST_DIR="$SCRIPT_DIR/dist"
WORK_DIR="$SCRIPT_DIR/work"
ENTRY="$SCRIPT_DIR/proxy_settings_entry.py"

echo "[build] root: $ROOT_DIR"

# Locate a Python 3 interpreter. We prefer the `python` on PATH because:
#   - On a normal Windows install (and inside `actions/setup-python`'s shim),
#     `python` is the requested version.
#   - The `py` launcher always picks the *latest* installed Python on the
#     system, which can land on a version that doesn't yet have wheels for
#     our deps (notably `cryptography` lags new CPython releases on Windows
#     ARM64). Trying `python` first avoids that.
# `py` and `python3` remain as fallbacks for shells where `python` isn't wired
# (rare on Windows, common on bare Linux).
PYTHON_HOST=""
for cmd in python python3 py; do
    if command -v "$cmd" >/dev/null 2>&1; then
        if "$cmd" --version 2>&1 | grep -q "^Python 3\."; then
            PYTHON_HOST="$cmd"
            break
        fi
    fi
done
if [ -z "$PYTHON_HOST" ]; then
    echo "[build] error: Python 3 not found on PATH" >&2
    echo "[build] install from https://python.org or via 'winget install Python.Python.3'" >&2
    exit 1
fi
echo "[build] host python: $PYTHON_HOST ($("$PYTHON_HOST" --version 2>&1))"

# Create the venv if missing
if [ ! -d "$VENV_DIR" ]; then
    echo "[build] creating venv at $VENV_DIR"
    "$PYTHON_HOST" -m venv "$VENV_DIR"
fi

# Activate it. Windows venvs put scripts under Scripts/; POSIX under bin/.
if [ -f "$VENV_DIR/Scripts/activate" ]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/Scripts/activate"
elif [ -f "$VENV_DIR/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
else
    echo "[build] error: could not find venv activate script" >&2
    exit 1
fi

# Install build deps.
#
# By default we use `--only-binary :all:` so pip refuses source builds and
# auto-picks the highest version of each package that has a matching wheel.
# That covers the x64 build cleanly.
#
# On Windows ARM64 the situation is different: pyca/cryptography stopped
# publishing win_arm64 wheels after 46.0.0 and shows no sign of bringing
# them back, so wheel-only mode would freeze us on an aging release. The
# release workflow therefore sets BUILD_CRYPTOGRAPHY_FROM_SOURCE=1 (along
# with OPENSSL_DIR / OPENSSL_LIB_DIR / OPENSSL_STATIC pointing at a
# vcpkg-supplied OpenSSL) for the ARM64 job, which switches us to building
# cryptography from sdist against that OpenSSL. The other deps still come
# from wheels.
#
# All four packages ship Windows wheels (x64 and ARM64) for the non-cryptography
# entries, so wheel-only is safe for them.
#
# --quiet keeps the log readable; if pip ever fails, drop the flag and
# re-run to see the full resolver trace.
echo "[build] installing dependencies into venv"
python -m pip install --upgrade --quiet pip

PIP_BINARY_FLAGS=(--only-binary :all:)
if [ -n "${BUILD_CRYPTOGRAPHY_FROM_SOURCE:-}" ]; then
    echo "[build] BUILD_CRYPTOGRAPHY_FROM_SOURCE set; cryptography will compile from sdist"
    echo "[build]   OPENSSL_DIR=${OPENSSL_DIR:-(unset)}"
    echo "[build]   OPENSSL_LIB_DIR=${OPENSSL_LIB_DIR:-(unset)}"
    echo "[build]   OPENSSL_STATIC=${OPENSSL_STATIC:-(unset)}"
    PIP_BINARY_FLAGS+=(--no-binary cryptography)
fi

python -m pip install --upgrade --quiet "${PIP_BINARY_FLAGS[@]}" \
    pyinstaller \
    pywin32 \
    cryptography \
    certifi

# Stdlib modules we don't import — excluding them shaves a few MB.
EXCLUDES=(
    tkinter
    turtle
    unittest
    pydoc
    pdb
    doctest
    distutils
    lib2to3
    xmlrpc
    test
    asyncio
    multiprocessing
)
EXCLUDE_ARGS=()
for m in "${EXCLUDES[@]}"; do
    EXCLUDE_ARGS+=(--exclude-module "$m")
done

# Hand UPX off to PyInstaller (it knows how to invoke it safely on the
# bootloader). If upx isn't on PATH, fall through with --noupx.
if command -v upx >/dev/null 2>&1; then
    UPX_PATH="$(command -v upx)"
    UPX_DIR="$(dirname "$UPX_PATH")"
    UPX_ARGS=(--upx-dir "$UPX_DIR")
    echo "[build] using upx from $UPX_DIR"
else
    UPX_ARGS=(--noupx)
    echo "[build] upx not on PATH; binary will be larger."
    echo "[build]   install with: choco install upx -y   OR   scoop install upx"
fi

# Wipe stale build artifacts so we always get a clean binary.
rm -rf "$WORK_DIR" "$DIST_DIR" "$SCRIPT_DIR/proxy_settings.spec"

echo "[build] running PyInstaller"
python -m PyInstaller \
    --onefile \
    --console \
    --clean \
    --noconfirm \
    --name proxy_settings \
    --paths "$ROOT_DIR" \
    --distpath "$DIST_DIR" \
    --workpath "$WORK_DIR" \
    --specpath "$SCRIPT_DIR" \
    "${EXCLUDE_ARGS[@]}" \
    "${UPX_ARGS[@]}" \
    "$ENTRY"

# Verify and report
EXE="$DIST_DIR/proxy_settings.exe"
if [ ! -f "$EXE" ]; then
    EXE="$DIST_DIR/proxy_settings"  # POSIX fallback (build host wasn't Windows)
fi
if [ ! -f "$EXE" ]; then
    echo "[build] error: PyInstaller did not produce a binary in $DIST_DIR" >&2
    exit 1
fi

# stat -c is GNU; stat -f is BSD/macOS. Try GNU first.
size_bytes="$(stat -c '%s' "$EXE" 2>/dev/null || stat -f '%z' "$EXE")"
size_mb="$(awk -v b="$size_bytes" 'BEGIN { printf "%.1f", b/1024/1024 }')"

echo
echo "[build] done"
echo "[build]   $EXE"
echo "[build]   size: ${size_mb} MB (${size_bytes} bytes)"
