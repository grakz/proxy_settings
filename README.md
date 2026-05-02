# proxy_settings

A small toolkit that makes command-line developer tools (Git, npm, pip, Node.js, and anything that honors `HTTPS_PROXY`) work on Windows in enterprise environments sitting behind a corporate proxy.

## Quick start

If you just want it to work and don't need details, this is everything you need.

**1. Install dependencies and run once:**

```
pip install pywin32 cryptography certifi
python configure_proxy.py
```

Then **restart your terminal** (so the env vars `configure_proxy.py` set via `setx` are visible to new processes). That's it.

**2. If npm/pnpm/yarn later fail with tarball integrity errors** (or any download arrives as HTML instead of bytes), your corporate proxy is using McAfee Web Gateway "progress pages" to wrap large downloads. Re-run once with `--mitm` for the offending hosts:

```
python configure_proxy.py --mitm "registry.npmjs.org,registry.yarnpkg.com,binaries.prisma.sh"
```

The flag is persisted, so future runs need no arguments. Restart any pnpm/node processes after.

**3. After a reboot**, re-run the same one-liner (no args needed; it picks up your persisted config):

```
python configure_proxy.py
```

**To start it automatically on login** (no admin rights required), drop a shortcut into your per-user Startup folder:

1. Press `Win+R`, type `shell:startup`, press Enter. This opens `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.
2. Create a file there called `proxy_settings.bat` containing:

   ```bat
   @echo off
   start "" pythonw "C:\full\path\to\configure_proxy.py"
   ```

   `pythonw` runs without a console window. The daemon detaches from the parent, so the script exits immediately and the proxy keeps running in the background.

To undo everything: `python configure_proxy.py --unset`.

---

## Contents

- [Why this exists](#why-this-exists)
- [Files](#files)
- [Requirements](#requirements)
- [`configure_proxy.py`](#configure_proxypy)
  - [Options](#options)
  - [Detection chain](#detection-chain-what-runs-in-what-order)
  - [Corporate CA discovery strategy](#corporate-ca-discovery-strategy)
- [`auth_proxy.py`](#auth_proxypy)
  - [Subcommands](#subcommands-mutually-exclusive)
  - [Connection options](#connection-options)
  - [MITM (TLS interception) options](#mitm-tls-interception-options)
  - [Diagnostics options](#diagnostics-options)
  - [How the auth dance works](#how-the-auth-dance-works)
  - [McAfee progress-page state machine](#mcafee-progress-page-state-machine)
- [`mitm_handler.py`](#mitm_handlerpy)
- [Common workflows](#common-workflows)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Why this exists

It handles the four things that typically break CLI tools on a managed corporate machine:

1. **Proxy discovery** — the proxy may be set in env vars, the Windows registry (static or `AutoConfigURL`), or only discoverable via DNS WPAD; the proxy URL itself may come from a JavaScript PAC file.
2. **TLS inspection** — corporate proxies (Zscaler, Netskope, BlueCoat, McAfee, Palo Alto, etc.) re-sign TLS with a private root CA pushed into the Windows trust store. Tools that ship their own CA bundle (Git for Windows, Node.js, pip/certifi) don't trust it and fail with cert errors.
3. **Proxy authentication** — many corporate proxies require NTLM or Kerberos (Negotiate) auth. Most CLI tools either don't support it at all or need careful per-tool configuration.
4. **McAfee Web Gateway "progress pages"** — when downloading large files (npm tarballs, Prisma binaries, etc.) MWG replaces the real bytes with a "Please Wait" HTML page that polls and eventually shows a "Click here to get the file" link. Headless tools see HTML where they expect a tarball and fail with integrity errors.

The toolkit consists of three Python files. **Only two are meant to be invoked directly.**

## Files

| File | Run directly? | Role |
|---|---|---|
| `configure_proxy.py` | **Yes** — main entry point | Detects the proxy + corporate CA, writes settings into Git/npm/pip/Node, optionally starts the local auth daemon. |
| `auth_proxy.py` | **Yes** — usually managed by `configure_proxy.py`, can be run on its own | Local NTLM/Negotiate-handling proxy daemon, optionally with TLS interception for the McAfee workaround. |
| `mitm_handler.py` | **No** — internal module | Local CA, on-the-fly leaf cert signing, McAfee progress-page state machine. Imported by `auth_proxy.py`. |

State and config live under `~/.config/configure_proxy/`:

- `config.json` — persisted CLI flags from the last successful `configure_proxy.py` run
- `state.json` — last-detected proxy state
- `ca-bundle.pem` — combined system + corporate + local-MITM CA bundle pointed at by Git/npm/pip/Node
- `auth_proxy_ca.pem` / `auth_proxy_ca.key` — local CA generated for MITM mode
- `auth_proxy.pid` / `auth_proxy.log` — daemon control files

## Requirements

- Python 3.9+ (Python 3.13+ unlocks the most reliable cert-chain capture path).
- `pywin32` — required by `auth_proxy.py` for SSPI (NTLM/Kerberos via the logged-in Windows credentials, no password storage).
- `cryptography` — required by `mitm_handler.py` (i.e. only needed if you use `--mitm`).
- `certifi` — recommended; gives a stable baseline trust store to diff the corporate CA against.

```
pip install pywin32 cryptography certifi
```

The toolkit is Windows-first (registry detection, SSPI, `setx`). The detection and CA-bundling code on `configure_proxy.py` will run on Linux/macOS, but `auth_proxy.py` daemon mode and SSPI auth are Windows-only.

## `configure_proxy.py`

Top-level orchestrator. Persists arguments across runs, so most users only ever run it with no flags after the first time.

```
python configure_proxy.py [options]
```

When run with no flags, it will:

1. Detect the proxy (env vars → registry static → registry `AutoConfigURL` → DNS WPAD → PAC).
2. Probe whether the proxy demands authentication.
3. If it does, start `auth_proxy.py` as a background daemon on `127.0.0.1:3128` and point Git, npm, pip and the `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` env vars at it.
4. Find the corporate TLS-inspection root CA (preferring the Windows `ROOT` store, falling back to a TLS probe through the proxy), build a combined PEM bundle, and configure Git (`http.sslCAInfo`), npm (`cafile`), pip (`[global] cert`) and Node (`NODE_EXTRA_CA_CERTS`) to use it.
5. Persist the flags you used to `~/.config/configure_proxy/config.json` so the next run is a no-arg `python configure_proxy.py`.

### Options

#### Proxy detection / override

- `--proxy URL` — Skip detection and use this proxy URL.
- `--pac-url URL` — Skip PAC discovery and fetch from this URL instead.
- `--probe-url URL` — URL used both as the input to PAC evaluation and as the destination of the TLS probe used to capture the corporate cert chain. Default: `https://github.com`.

#### Corporate CA discovery

- `--no-ca` — Skip CA discovery entirely. Use this if SSL inspection is not happening on your network.
- `--ca-bundle-path PATH` — Where to write the combined PEM bundle. Default: `~/.config/configure_proxy/ca-bundle.pem`.
- `--ca-import PATH` — Path to a manually-exported corporate cert (`.cer`/`.pem`/`.crt`). May be passed multiple times. Use this when auto-detection fails; export the cert from *Internet Options → Content → Certificates → Trusted Root* as Base-64 `.cer`.
- `--ca-pick SUBSTRING` — When the Windows `ROOT` store contains multiple plausible candidates, auto-select the one whose subject contains this substring (case-insensitive). Useful for non-interactive or scripted runs.

#### Local auth proxy

- `--auth-proxy {auto,always,never}` — Whether to run `auth_proxy.py` as a local daemon in front of the corporate proxy.
  - `auto` (default): probe the upstream and start the daemon only if it returns 407.
  - `always`: start unconditionally.
  - `never`: skip the daemon and configure tools to talk to the corporate proxy directly. Pick this only if the proxy doesn't require auth or if you have another mechanism (e.g. `cntlm`).
- `--auth-proxy-port N` — Port for the local daemon. Default: `3128`.
- `--mitm HOSTS` — Comma-separated list of hosts (or `*`) for which the local daemon should terminate TLS to handle McAfee progress pages. Common targets: `registry.npmjs.org,registry.yarnpkg.com,binaries.prisma.sh`. Suffix matching applies, so `npmjs.org` covers `registry.npmjs.org`. Pass `--mitm ""` to clear a previously-saved value.
- `--auth-proxy-debug` — Run the daemon with verbose per-request logging.

#### Environment variables

- `--no-env-proxy` — Skip `setx`-ing `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`. By default these *are* set so that anything reading them (curl, wget, requests, Prisma, many CLIs) uses the proxy automatically.

#### Run mode

- `--dry-run` — Show what would be done without touching anything.
- `--unset` — Reverse everything: remove Git/npm/pip CA + proxy settings, delete env vars (Windows: via `reg delete`), stop the daemon, delete the persisted config.
- `--show-config` / `--reset-config` — Inspect or wipe the persisted config and exit.
- `--no-save` — Don't persist this run's flags.
- `-v` / `--verbose` — Show DNS lookups, TLS probe details, certificate diffs.

### Detection chain (what runs in what order)

```
HTTPS_PROXY / HTTP_PROXY env vars (loopback addresses ignored — those are us from a previous run)
    ↓ none
Windows registry: ProxyEnable + ProxyServer
    ↓ none
Windows registry: AutoConfigURL (PAC URL set by GPO)
    ↓ none
DNS WPAD: walk DNS-suffix list, look up wpad.<domain>, fetch wpad.dat
    ↓ none
give up
```

PAC files (JavaScript) are evaluated with Node.js if present on `PATH`; otherwise a small built-in Python evaluator handles the common subset (`shExpMatch`, `dnsDomainIs`, `isInNet`, `isPlainHostName`, `dnsResolve`, `myIpAddress`, `isResolvable`, `dnsDomainLevels`, plus `||` / `&&` / `!`).

### Corporate CA discovery strategy

In order:

1. **`--ca-import`** — anything passed explicitly wins.
2. **Windows `ROOT` store diff** — list certs in the Windows `ROOT` store that aren't in `certifi`, filter out Microsoft OS roots and non-self-signed entries, score the rest by name (Zscaler/BlueCoat/Netskope/etc. → high score) and recency. If multiple candidates remain, do a TLS probe through the proxy and pick the one whose Subject Key Identifier matches the leaf's Authority Key Identifier. Falls back to interactive prompt if the probe is inconclusive.
3. **TLS probe** — connect through the proxy to `--probe-url` (default `https://github.com`) with verification disabled, capture the chain (Python ≥ 3.13's `get_unverified_chain` → `openssl s_client -proxy …` → leaf-only fallback), keep certs not in `certifi`. This path can fail on NTLM proxies if `auth_proxy.py` isn't already in front.

The combined bundle = `certifi` baseline + corporate CA(s) + the local `auth_proxy` MITM CA (if it exists). The MITM CA is also re-appended idempotently on subsequent runs, so creating it after the first run doesn't require rebuilding everything.

## `auth_proxy.py`

A local HTTP/HTTPS proxy that listens on `127.0.0.1` (default port `3128`), accepts plain unauthenticated requests from local tools, and forwards them upstream to the corporate proxy — performing NTLM or Negotiate (Kerberos with NTLM fallback) authentication on the way using Windows SSPI. This means tools never see the auth dance and your password is never stored anywhere; SSPI uses the credentials of the logged-in Windows user.

Usually managed by `configure_proxy.py`, but you can drive it directly:

```
python auth_proxy.py --start --upstream http://corp.proxy:8080 [options]
python auth_proxy.py --status
python auth_proxy.py --stop
```

### Subcommands (mutually exclusive)

- `--start` — Detached background daemon. Writes the PID to `~/.config/configure_proxy/auth_proxy.pid` and logs to `auth_proxy.log` next to it. On Windows uses `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`; on POSIX uses `fork()` + `setsid()`. Verifies the daemon is accepting connections before returning.
- `--stop` — Kill the running daemon (TerminateProcess on Windows, SIGTERM on POSIX) and remove the PID file.
- `--status` — Exit 0 if the daemon is running, 1 otherwise.
- `--serve` — Run in the foreground (used internally by `--start`; useful for debugging).
- `--diagnose URL` — Fetch `URL` through the running daemon and report bytes received, sha512, and any truncation. Pair with `--expect-sha512 HASH` (raw hex or `sha512-…` base64) to verify against an expected hash. Use this when chasing pnpm tarball-integrity errors.

If no subcommand is given, the script runs in the foreground (same as `--serve`).

### Connection options

- `--upstream URL` — Corporate proxy URL. Required for `--start`, `--serve`, and the default foreground mode.
- `--port N` — Listening port. Default: `3128`.
- `--bind ADDR` — Bind address. Default: `127.0.0.1`.

### MITM (TLS interception) options

- `--mitm HOSTS` — Comma-separated list of hosts (suffix-matched) or `*` for all. The daemon terminates TLS for these hosts using a leaf cert signed by its local CA, inspects responses, and follows McAfee Web Gateway progress-page redirects/links so the client receives real file bytes. Requires `cryptography`.
- `--mitm-print-ca` — Print the path to `auth_proxy_ca.pem` and exit. The cert at that path must be in the CA bundle clients use (`configure_proxy.py` does this automatically; otherwise import it manually).
- `--mitm-check` — Diagnostic: confirm the MITM CA exists, that `NODE_EXTRA_CA_CERTS` is set in the current process, and that the bundle file actually contains the CA. Run this when MITM-enabled requests hang during the client TLS handshake or when pnpm/npm doesn't send a request after CONNECT (almost always: client doesn't trust the local CA, often because the shell was started before `setx` updated `NODE_EXTRA_CA_CERTS`).

### Diagnostics options

- `--debug` — Verbose per-request logging: every request line, headers in both directions, every TLS milestone, every MWG poll. Off by default.
- `--expect-sha512 HASH` — Used with `--diagnose`.

### How the auth dance works

For HTTPS (CONNECT):

```
client → auth_proxy:    CONNECT host:443
auth_proxy → corp:      CONNECT host:443                          (round 1)
corp → auth_proxy:      407 Proxy-Authenticate: Negotiate, NTLM
auth_proxy → corp:      CONNECT host:443 + SSPI Type1 token       (round 2)
corp → auth_proxy:      407 Proxy-Authenticate: Negotiate <Type2>
auth_proxy → corp:      CONNECT host:443 + SSPI Type3 response    (round 3)
corp → auth_proxy:      200 Connection established
auth_proxy → client:    200 Connection established
        ↕ raw byte splicing in both directions for the TLS stream ↕
```

The full handshake stays on a single TCP connection (NTLM is connection-bound). For plain HTTP, the same dance happens on the request itself with `Proxy-Authorization` headers.

For MITM hosts, instead of splicing raw bytes, `auth_proxy` terminates TLS with a per-host leaf cert (signed by its local CA, generated and cached lazily), opens a separate TLS connection upstream verified against the system trust store, and proxies HTTP requests one at a time — intervening when responses look like McAfee progress pages.

### McAfee progress-page state machine

Implemented in `mitm_handler.py`. When MWG intercepts a download it replaces the response with one of:

- **WAITING page** — HTML with a JS progress meter; the JS polls `?a=1&<ts>` every 3s.
- **POLL response** — small `text/plain` body like `1234567;7000000;30;0;0` (`downloaded;total;percent;ready;scan_seconds`).
- **READY page** — HTML with `<a href="…&dl">Click here to get the file</a>`.

The handler detects which state the upstream is in (either via a 307 to `/mwg-internal/…/progress` or by classifying the body), polls for ready (up to 10 minutes), follows the `&dl` link, and returns the real bytes to the client with synthesized headers (correct `Content-Length`, `Content-Type` preserved). It also rewrites chunked responses to use `Content-Length` framing because the body has already been buffered, which prevents pnpm/undici from RST-ing on a "chunked" stream that doesn't actually have chunk markers.

## `mitm_handler.py`

Internal module. Not meant to be invoked directly. Imported by `auth_proxy.py` when `--mitm` is in use. Provides:

- `CertAuthority` — loads or creates the local CA at `~/.config/configure_proxy/auth_proxy_ca.pem`, signs per-host leaf certs on the fly with both `host` and `*.host` SANs, caches them in memory and on disk under `~/.config/configure_proxy/leaves/`.
- `mitm_handle_connect()` — TLS-terminates the client side, opens an upstream TLS connection (verified against the system trust store), and proxies HTTP one request at a time.
- `classify_mcafee_response()` / `_handle_mcafee_progress()` — the McAfee state machine described above.
- `compute_ca_fingerprint()` / `check_ca_trust_status()` — diagnostics used by `auth_proxy.py --mitm-check`.

## Common workflows

**First-time setup on a managed machine**

```
pip install pywin32 cryptography certifi
python configure_proxy.py
# restart terminal so setx-ed env vars are visible
```

**npm/pnpm fails with tarball integrity errors**

The corporate proxy is replacing tarballs with McAfee progress pages. Re-run with MITM enabled for the affected hosts:

```
python configure_proxy.py --mitm "registry.npmjs.org,registry.yarnpkg.com,binaries.prisma.sh"
# restart any pnpm/node processes
```

To verify in isolation:

```
python auth_proxy.py --diagnose https://registry.npmjs.org/some/pkg/-/pkg-1.2.3.tgz \
                    --expect-sha512 sha512-AbCdEf...
```

**Auto-detection picked the wrong corporate CA**

```
# list candidates and pick by substring
python configure_proxy.py --ca-pick "Zscaler"
# or import an exported .cer manually
python configure_proxy.py --ca-import C:\Users\me\corp-root.cer
```

**Tear everything down**

```
python configure_proxy.py --unset
```

Removes Git/npm/pip CA + proxy settings, removes the env vars, stops the daemon, deletes the persisted config. The CA bundle file and the local CA on disk are left in place.

**Inspect what's persisted**

```
python configure_proxy.py --show-config
```

## Troubleshooting

- **`auth_proxy listening … forwarding to …` but tools still get 407** — `HTTPS_PROXY` is probably still pointing at the corporate proxy, not at `127.0.0.1:3128`. `setx` only affects new processes; restart the shell.
- **MITM enabled, client hangs after TLS handshake** — client doesn't trust the local CA. Run `python auth_proxy.py --mitm-check`. Common cause: the shell was started before `NODE_EXTRA_CA_CERTS` was set; restart it.
- **`upstream wants Basic auth`** — `auth_proxy.py` deliberately refuses to handle Basic. Embed credentials in the upstream URL (`http://user:pass@proxy:8080`) if you really need this — but normally Basic on a corporate proxy is a misconfiguration, not the intended path.
- **`could not capture cert chain: proxy CONNECT failed`** during CA discovery — the proxy is rejecting the unauthenticated probe. Either pass `--auth-proxy always` so the probe goes through the local daemon, or use `--ca-import` to supply the cert manually.
- **PAC evaluation fails** — install Node.js (`node` on `PATH`) so PAC files can be evaluated by a real JS engine instead of the built-in Python subset.
- **Daemon log** — `~/.config/configure_proxy/auth_proxy.log`. Re-run with `--auth-proxy-debug` (or restart the daemon directly with `--debug`) for per-request detail.

## License

MIT — see [LICENSE](LICENSE). Copyright © 2026 Grakz.
