"""
Local authenticating proxy for corporate NTLM/Negotiate proxies.

Listens on 127.0.0.1:<port>, accepts plain (no-auth) requests from local
tools (Git, npm, pip, etc.), and forwards them to the upstream corporate
proxy, performing NTLM or Negotiate authentication on their behalf using
Windows SSPI (so it uses your logged-in credentials — no password storage).

Usage:
    python auth_proxy.py --upstream http://corp.proxy:8080 [--port 3128]
    python auth_proxy.py --start    # daemonize (Windows: detached process)
    python auth_proxy.py --stop     # kill the running daemon
    python auth_proxy.py --status   # is it running?

Design notes:
  - For HTTPS the protocol is HTTP CONNECT. We do the auth handshake on
    the CONNECT, then splice raw bytes both directions for the TLS stream.
  - For plain HTTP we proxy the request itself, injecting Proxy-Authorization.
  - SSPI requires the same TCP connection to be reused across the auth
    challenge/response messages (the handshake is connection-bound), so we
    keep the upstream socket open across the 407 -> Type1 -> 401-Type2
    -> Type3 -> 200 sequence.
  - Only handles one authentication round-trip per upstream connection;
    after that, we either splice (CONNECT) or close (HTTP) so we don't
    have to deal with keep-alive auth state across requests.
"""

import argparse
import base64
import os
import re
import select
import socket
import socketserver
import sys
import threading
import time
from urllib.parse import urlparse


DEFAULT_PORT = 3128
PID_FILE = os.path.join(os.path.expanduser("~"), ".config", "configure_proxy", "auth_proxy.pid")
LOG_FILE = os.path.join(os.path.expanduser("~"), ".config", "configure_proxy", "auth_proxy.log")
BUFFER_SIZE = 65536


# ---------------------------------------------------------------------------
# SSPI wrapper
# ---------------------------------------------------------------------------

class SspiAuthenticator:
    """
    Thin wrapper around pywin32's sspi module. Produces the Type1 token,
    consumes the Type2 challenge, produces the Type3 response. Each instance
    is single-use (one upstream connection / one auth handshake).
    """

    def __init__(self, scheme, target_spn=None):
        try:
            import sspi  # from pywin32
            import sspicon
        except ImportError as e:
            raise RuntimeError(
                "pywin32 is required for SSPI auth. Install with: pip install pywin32"
            ) from e
        self._sspi = sspi
        self._sspicon = sspicon

        # Map our scheme name to SSPI package name
        scheme_lower = scheme.lower()
        if scheme_lower == "negotiate":
            self.package = "Negotiate"
        elif scheme_lower == "ntlm":
            self.package = "NTLM"
        else:
            raise ValueError(f"unsupported auth scheme: {scheme}")

        self.scheme_header = scheme  # what we send in the Authorization header
        self.target_spn = target_spn  # e.g. "HTTP/proxy.corp" for Kerberos
        self._client_auth = None

    def first_token(self):
        """Generate the Type1 / initial SPNEGO token to send to the proxy."""
        flags = (
            self._sspicon.ISC_REQ_INTEGRITY
            | self._sspicon.ISC_REQ_CONFIDENTIALITY
        )
        self._client_auth = self._sspi.ClientAuth(
            self.package,
            targetspn=self.target_spn,
            scflags=flags,
        )
        err, out_buf = self._client_auth.authorize(None)
        return bytes(out_buf[0].Buffer)

    def next_token(self, server_token):
        """Consume the server's Type2 token and produce the Type3 response."""
        if self._client_auth is None:
            raise RuntimeError("first_token() must be called first")
        err, out_buf = self._client_auth.authorize(server_token)
        return bytes(out_buf[0].Buffer)


# ---------------------------------------------------------------------------
# HTTP parsing helpers
# ---------------------------------------------------------------------------

def _read_http_headers(sock, max_size=65536):
    """Read until \\r\\n\\r\\n from sock. Returns (header_bytes, body_remainder)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_size:
            raise OSError("HTTP headers exceeded max size")
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def _parse_status(headers):
    line = headers.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    parts = line.split(None, 2)
    if len(parts) < 2:
        return 0, ""
    try:
        return int(parts[1]), parts[2] if len(parts) > 2 else ""
    except ValueError:
        return 0, ""


def _parse_proxy_authenticate(headers):
    """Return list of (scheme, b64_challenge_or_None) tuples from Proxy-Authenticate headers."""
    schemes = []
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"proxy-authenticate:"):
            val = line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            parts = val.split(None, 1)
            scheme = parts[0]
            challenge = parts[1].strip() if len(parts) == 2 else None
            schemes.append((scheme, challenge))
    return schemes


def _content_length(headers):
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                return 0
    return 0


# ---------------------------------------------------------------------------
# Upstream connection with NTLM/Negotiate auth
# ---------------------------------------------------------------------------

def _connect_upstream(upstream_url, timeout=15):
    parsed = urlparse(upstream_url)
    host = parsed.hostname
    port = parsed.port or 8080
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(None)
    return sock, host, port


def _drain_response_body(sock, headers, body_remainder):
    """Drain Content-Length bytes from sock so the connection is reusable."""
    n = _content_length(headers)
    drained = len(body_remainder)
    while drained < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - drained))
        if not chunk:
            break
        drained += len(chunk)


def _select_scheme(offered):
    """
    Pick the best scheme the upstream offered. Prefer Negotiate (Kerberos +
    NTLM fallback) over straight NTLM.
    """
    names = [s.lower() for s, _ in offered]
    if "negotiate" in names:
        return "Negotiate"
    if "ntlm" in names:
        return "NTLM"
    if "basic" in names:
        return "Basic"
    return None


def authenticated_connect(upstream_url, target_host, target_port, log=None):
    """
    Open a CONNECT tunnel through `upstream_url` to target_host:target_port,
    performing NTLM/Negotiate auth if challenged. Returns a connected socket
    ready for raw splicing (TLS will run end-to-end through it).
    """
    log = log or (lambda *a, **k: None)
    import time as _t
    t_start = _t.time()
    sock, proxy_host, proxy_port = _connect_upstream(upstream_url)
    sock.settimeout(30)  # don't hang forever on a misbehaving proxy

    def send_connect(extra_headers=b""):
        req = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"Proxy-Connection: Keep-Alive\r\n"
        ).encode("ascii") + extra_headers + b"\r\n"
        sock.sendall(req)

    # Round 1: bare CONNECT
    send_connect()
    headers, rest = _read_http_headers(sock)
    status, _ = _parse_status(headers)
    log.debug(f"upstream CONNECT round 1 -> {status}")
    if status == 200:
        sock.settimeout(None)
        return sock  # no auth needed
    if status != 407:
        sock.close()
        raise OSError(f"upstream CONNECT returned {status}; headers={headers[:200]!r}")

    offered = _parse_proxy_authenticate(headers)
    scheme = _select_scheme(offered)
    if not scheme:
        sock.close()
        raise OSError(f"upstream offers no usable auth scheme: {[s for s,_ in offered]}")

    log.debug(f"upstream challenged with: {[s for s,_ in offered]}; using {scheme}")

    if scheme == "Basic":
        sock.close()
        raise OSError("upstream wants Basic auth; embed credentials in the upstream URL instead")

    # Make sure round-1 body is drained (407 usually has a small HTML body)
    _drain_response_body(sock, headers, rest)

    # SSPI handshake
    spn = f"HTTP/{proxy_host}"
    auth = SspiAuthenticator(scheme, target_spn=spn)

    type1 = auth.first_token()
    type1_b64 = base64.b64encode(type1).decode("ascii")
    send_connect(f"Proxy-Authorization: {scheme} {type1_b64}\r\n".encode("ascii"))

    headers, rest = _read_http_headers(sock)
    status, _ = _parse_status(headers)
    log.debug(f"upstream CONNECT round 2 (Type1) -> {status}")
    if status == 200:
        # Some Kerberos setups complete in one round
        sock.settimeout(None)
        return sock
    if status != 407:
        sock.close()
        raise OSError(f"upstream after Type1 returned {status}")

    # Extract the Type2 challenge for our scheme
    offered = _parse_proxy_authenticate(headers)
    type2_b64 = None
    for s, challenge in offered:
        if s.lower() == scheme.lower() and challenge:
            type2_b64 = challenge
            break
    if not type2_b64:
        sock.close()
        raise OSError(f"upstream did not provide a {scheme} challenge")

    _drain_response_body(sock, headers, rest)

    type2 = base64.b64decode(type2_b64)
    type3 = auth.next_token(type2)
    type3_b64 = base64.b64encode(type3).decode("ascii")
    send_connect(f"Proxy-Authorization: {scheme} {type3_b64}\r\n".encode("ascii"))

    headers, rest = _read_http_headers(sock)
    status, _ = _parse_status(headers)
    log.debug(f"upstream CONNECT round 3 (Type3) -> {status} (auth took {_t.time()-t_start:.1f}s)")
    if status == 200:
        # The body remainder (rest) should be empty for CONNECT; if not, we
        # have to forward it to the client as part of the splice.
        if rest:
            log.debug(f"warning: {len(rest)} bytes of body after CONNECT 200; will forward")
            sock._connect_residual = rest  # type: ignore[attr-defined]
        sock.settimeout(None)
        return sock
    sock.close()
    raise OSError(f"upstream CONNECT failed after auth: {status}")


# ---------------------------------------------------------------------------
# Local proxy server
# ---------------------------------------------------------------------------

class AuthProxyHandler(socketserver.BaseRequestHandler):
    upstream_url = None  # set by the server
    log = None
    mitm_hosts = None    # None = MITM disabled; set() = MITM all; set of names = filter

    def handle(self):
        try:
            self._handle()
        except Exception as e:
            import traceback
            self.log(f"[{self.client_address[0]}] handler error: {type(e).__name__}: {e}")
            self.log(traceback.format_exc())
            try:
                self.request.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass

    def _handle(self):
        # Read the client's request line + headers
        head, rest = _read_http_headers(self.request)
        first_line = head.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        parts = first_line.split()
        if len(parts) < 3:
            return
        method, target = parts[0].upper(), parts[1]

        if method == "CONNECT":
            self._handle_connect(target, head)
        else:
            self._handle_http(method, target, head, rest)

    def _should_mitm(self, host):
        """Decide whether to MITM TLS for this host."""
        if self.mitm_hosts is None:
            return False
        if not self.mitm_hosts:  # empty set = MITM everything
            return True
        # Match either exact host or any suffix (e.g. "npmjs.org" matches "registry.npmjs.org")
        host_lower = host.lower()
        for pattern in self.mitm_hosts:
            p = pattern.lower()
            if host_lower == p or host_lower.endswith("." + p):
                return True
        return False

    def _handle_connect(self, target, client_headers):
        if ":" in target:
            host, port_s = target.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                port = 443
        else:
            host, port = target, 443

        self.log.debug(f"[{self.client_address[0]}] CONNECT {host}:{port}")

        if self._should_mitm(host):
            self._handle_connect_mitm(host, port)
            return

        try:
            upstream = authenticated_connect(self.upstream_url, host, port, log=self.log)
        except Exception as e:
            self.log(f"  upstream CONNECT failed: {e}")
            self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return

        # Tell the local client the tunnel is open
        self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        # Forward any residual bytes from the upstream CONNECT response
        residual = getattr(upstream, "_connect_residual", b"")
        if residual:
            self.request.sendall(residual)

        # Splice both directions
        _splice(self.request, upstream, log=self.log, label=f"{host}:{port}")

    def _handle_connect_mitm(self, host, port):
        """MITM path: terminate TLS, inspect responses, handle McAfee progress pages."""
        try:
            import mitm_handler
        except ImportError as e:
            self.log(f"  MITM requested but mitm_handler unavailable: {e}")
            self.log(f"  install with: pip install cryptography")
            self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return

        ca = mitm_handler.get_ca()

        def upstream_factory(target_host, target_port):
            """Open a fresh authenticated CONNECT through the upstream proxy."""
            return authenticated_connect(self.upstream_url, target_host, target_port,
                                         log=self.log)

        mitm_handler.mitm_handle_connect(
            self.request, host, port, upstream_factory, ca, self.log,
        )

    def _handle_http(self, method, target, head, body_remainder):
        """Plain HTTP through the proxy. Open a fresh upstream connection,
        do the auth handshake on a HEAD/OPTIONS-equivalent if needed, then
        forward the actual request."""
        # Many corporate proxies allow proxying plain HTTP only with auth too,
        # so we follow the same dance: send the request, get 407, redo with
        # Proxy-Authorization. Connection is keep-alive across rounds.
        self.log.debug(f"[{self.client_address[0]}] {method} {target}")

        try:
            sock, proxy_host, _ = _connect_upstream(self.upstream_url)
        except OSError as e:
            self.log(f"  upstream connect failed: {e}")
            self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return

        # Strip any client-supplied Proxy-Authorization (we'll add our own)
        cleaned = _strip_header(head, b"proxy-authorization")
        # Keep Connection: close so we don't have to track keep-alive state
        cleaned = _strip_header(cleaned, b"proxy-connection")
        cleaned = _strip_header(cleaned, b"connection")
        cleaned += b"\r\nProxy-Connection: close"

        # Buffer the client request body so we can replay it after auth
        body = body_remainder + _read_request_body(self.request, head)

        try:
            self._http_with_auth(sock, cleaned, body, proxy_host)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _http_with_auth(self, sock, head, body, proxy_host):
        """Send `head\\r\\n\\r\\n + body` through the proxy with auth retry."""
        def send(extra_auth=b""):
            req = head
            if extra_auth:
                req = req + b"\r\n" + extra_auth
            sock.sendall(req + b"\r\n\r\n" + body)

        send()
        resp_head, resp_rest = _read_http_headers(sock)
        status, _ = _parse_status(resp_head)

        if status == 407:
            offered = _parse_proxy_authenticate(resp_head)
            scheme = _select_scheme(offered)
            if scheme and scheme != "Basic":
                _drain_response_body(sock, resp_head, resp_rest)
                auth = SspiAuthenticator(scheme, target_spn=f"HTTP/{proxy_host}")
                t1 = base64.b64encode(auth.first_token()).decode("ascii")
                send(f"Proxy-Authorization: {scheme} {t1}".encode("ascii"))
                resp_head, resp_rest = _read_http_headers(sock)
                status, _ = _parse_status(resp_head)
                if status == 407:
                    offered = _parse_proxy_authenticate(resp_head)
                    t2_b64 = next(
                        (c for s, c in offered if s.lower() == scheme.lower() and c), None
                    )
                    if t2_b64:
                        _drain_response_body(sock, resp_head, resp_rest)
                        t2 = base64.b64decode(t2_b64)
                        t3 = base64.b64encode(auth.next_token(t2)).decode("ascii")
                        send(f"Proxy-Authorization: {scheme} {t3}".encode("ascii"))
                        resp_head, resp_rest = _read_http_headers(sock)

        # Forward whatever we got to the client
        self.request.sendall(resp_head + b"\r\n\r\n" + resp_rest)
        # And drain the rest of the body
        while True:
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk:
                break
            self.request.sendall(chunk)


def _read_request_body(sock, head):
    """Read Content-Length bytes from the client (after the headers)."""
    n = _content_length(head)
    if n <= 0:
        return b""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - len(buf)))
        if not chunk:
            break
        buf += chunk
    return buf


def _strip_header(head, name):
    """Remove all occurrences of a header (case-insensitive) from a header block."""
    name_lower = name.lower()
    out_lines = []
    for line in head.split(b"\r\n"):
        if not line.lower().startswith(name_lower + b":"):
            out_lines.append(line)
    return b"\r\n".join(out_lines)


def _splice(a, b, log=None, label=""):
    """
    Bidirectionally pipe bytes between sockets a and b. Handle each direction
    independently — when one side sends EOF (recv returns 0), forward a FIN
    to the other side via shutdown(SHUT_WR) but keep reading the reverse
    direction until it also EOFs. This is the correct half-close behavior
    for proxying TLS-over-CONNECT, and prevents truncating data that's
    still in OS send buffers (which manifests as ERR_PNPM_TARBALL_INTEGRITY
    on the client side because pnpm hashes a truncated file).

    Logs byte counts and termination cause when `log` is provided so that
    truncation issues become visible.
    """
    log = log or (lambda *a, **k: None)
    active = {a: True, b: True}
    bytes_a_to_b = 0
    bytes_b_to_a = 0
    end_reason = "unknown"

    try:
        while any(active.values()):
            readable = [s for s, alive in active.items() if alive]
            if not readable:
                break
            try:
                # Note: do NOT pass `xlist` (third arg) on Windows. On Linux
                # an "exceptional condition" usually means OOB/urgent data,
                # which we don't care about. On Windows, the semantics are
                # weirder and select can report exceptional condition for
                # connections that are perfectly fine — bailing on it
                # truncates downloads. Just watch readable.
                r, _, _ = select.select(readable, [], [], 120)
            except (OSError, ValueError) as e:
                end_reason = f"select error: {e}"
                break
            if not r:
                # Idle for 120s. Don't kill the connection — long downloads
                # can have brief lulls. Just loop and re-select.
                continue
            for s in r:
                try:
                    data = s.recv(BUFFER_SIZE)
                except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                    side = "client" if s is a else "upstream"
                    end_reason = f"{side} recv error: {e}"
                    active[s] = False
                    other = b if s is a else a
                    try:
                        other.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                if not data:
                    side = "client" if s is a else "upstream"
                    if end_reason == "unknown":
                        end_reason = f"{side} EOF"
                    active[s] = False
                    other = b if s is a else a
                    try:
                        other.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue

                # Forward
                if s is a:
                    bytes_a_to_b += len(data)
                else:
                    bytes_b_to_a += len(data)
                other = b if s is a else a
                try:
                    other.sendall(data)
                except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                    side = "upstream" if s is a else "client"
                    end_reason = f"send to {side} failed: {e}"
                    active[other] = False
    except Exception as e:
        end_reason = f"unhandled splice exception: {type(e).__name__}: {e}"
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass
        if label:
            log.debug(f"  splice done [{label}]: client->up={bytes_a_to_b}B, "
                f"up->client={bytes_b_to_a}B, end={end_reason}")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(upstream_url, port=DEFAULT_PORT, bind="127.0.0.1", log=None, mitm_hosts=None):
    log = log or print

    # Make sure log has a .debug attribute. If we got a bare callable from a
    # caller that doesn't know about the debug protocol, we attach a no-op
    # .debug so call sites in this module and in mitm_handler can safely use
    # `log.debug(...)`. This matches the protocol _make_safe_log() produces.
    if not (hasattr(log, "debug") and callable(getattr(log, "debug", None))):
        _orig_log = log
        class _LogWithNoopDebug:
            def __call__(self, msg): _orig_log(msg)
            def debug(self, _msg): pass
        log = _LogWithNoopDebug()

    class Handler(AuthProxyHandler):
        pass
    Handler.upstream_url = upstream_url
    Handler.log = staticmethod(log)
    Handler.mitm_hosts = mitm_hosts

    server = ThreadedTCPServer((bind, port), Handler)
    mitm_msg = ""
    if mitm_hosts is not None:
        if not mitm_hosts:
            mitm_msg = " (MITM: ALL hosts)"
        else:
            mitm_msg = f" (MITM: {', '.join(sorted(mitm_hosts))})"

        # Eagerly load (or, in the rare case it isn't already there, generate)
        # the MITM CA so the file is on disk before any TLS interception runs.
        # configure_proxy.py pre-generates this before spawning us, so this is
        # normally a cheap load.
        #
        # We don't run check_ca_trust_status here: this serve() function runs
        # in a freshly-spawned daemon process whose environment was inherited
        # from the parent BEFORE the parent's `setx` updated NODE_EXTRA_CA_CERTS,
        # so the check would always report "MITM CA not in Node bundle" on
        # first run — even though the parent is in the middle of fixing
        # exactly that. The check is still available via
        # `auth_proxy.py --mitm-check`, where the surrounding env is the
        # user's current shell and the result is meaningful.
        try:
            import mitm_handler
            ca = mitm_handler.get_ca()
            log(f"MITM CA: {ca.ca_cert_path}")
            fp = mitm_handler.compute_ca_fingerprint(ca.ca_cert_path)
            log(f"MITM CA SHA256 fingerprint: {fp}")
        except ImportError as e:
            log(f"MITM requested but mitm_handler unavailable: {e}")
            log("install with: pip install cryptography")
            return

    log(f"auth_proxy listening on {bind}:{port}, forwarding to {upstream_url}{mitm_msg}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("shutting down (keyboard interrupt)")
    except Exception as e:
        import traceback
        log(f"FATAL: serve_forever died: {type(e).__name__}: {e}")
        log(traceback.format_exc())
        raise
    finally:
        try:
            server.shutdown()
            server.server_close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Daemon control (Windows-friendly)
# ---------------------------------------------------------------------------

def _ensure_dir(path):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def _read_pid():
    if not os.path.exists(PID_FILE):
        return None
    try:
        with open(PID_FILE) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _is_alive(pid):
    if pid is None:
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            h = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h:
                return False
            ctypes.windll.kernel32.CloseHandle(h)
            return True
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def start_daemon(upstream_url, port=DEFAULT_PORT, mitm_hosts=None, debug=False):
    """Spawn a detached background process running `serve()`."""
    existing = _read_pid()
    if _is_alive(existing):
        print(f"auth_proxy already running (pid {existing})")
        return existing

    _ensure_dir(PID_FILE)
    _ensure_dir(LOG_FILE)

    # Build the --serve command-line, including --mitm if requested
    serve_cmd = [sys.executable, os.path.abspath(__file__),
                 "--serve", "--upstream", upstream_url, "--port", str(port)]
    if mitm_hosts is not None:
        mitm_arg = "*" if not mitm_hosts else ",".join(sorted(mitm_hosts))
        serve_cmd += ["--mitm", mitm_arg]
    if debug:
        serve_cmd += ["--debug"]

    # Force the child's stdout/stderr text encoding to UTF-8 so log lines with
    # any non-ASCII content (URLs, unicode chars, etc) don't crash the handler
    # with charmap UnicodeEncodeError. Without this, Windows defaults to
    # cp1252 for redirected stdout and breaks on chars like en-dashes or
    # arrows that might appear in URLs or future log strings.
    child_env = {**os.environ, "PYTHONIOENCODING": "utf-8"}

    if sys.platform == "win32":
        import subprocess
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        log_f = open(LOG_FILE, "ab", buffering=0)
        proc = subprocess.Popen(
            serve_cmd,
            stdin=subprocess.DEVNULL,
            stdout=log_f,
            stderr=log_f,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
            env=child_env,
        )
    else:
        pid = os.fork()
        if pid > 0:
            proc_pid = pid
            class P: pass
            proc = P(); proc.pid = proc_pid
        else:
            os.setsid()
            with open(LOG_FILE, "ab", buffering=0) as log_f:
                os.dup2(log_f.fileno(), 1)
                os.dup2(log_f.fileno(), 2)
            serve(upstream_url, port=port, log=_make_safe_log(debug=debug),
                  mitm_hosts=mitm_hosts)
            os._exit(0)

    with open(PID_FILE, "w") as f:
        f.write(str(proc.pid))

    # Give it a moment to bind, then verify
    time.sleep(0.5)
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.close()
        print(f"auth_proxy started (pid {proc.pid}), listening on 127.0.0.1:{port}")
        print(f"  upstream: {upstream_url}")
        print(f"  log: {LOG_FILE}")
        return proc.pid
    except OSError:
        print(f"auth_proxy started but isn't accepting connections on port {port}")
        print(f"  check the log: {LOG_FILE}")
        return proc.pid


def diagnose_url(url, port=DEFAULT_PORT, expected_sha512=None):
    """
    Fetch a URL through the local auth_proxy and report what happens.
    Useful for diagnosing tarball integrity failures.

    If `expected_sha512` is provided, compare against the actual hash.
    """
    import hashlib
    import urllib.request
    import urllib.error

    print(f"Diagnosing: {url}")
    print(f"Through:    http://127.0.0.1:{port}")
    if expected_sha512:
        print(f"Expecting:  sha512 = {expected_sha512[:32]}...")

    proxy_handler = urllib.request.ProxyHandler({
        "https": f"http://127.0.0.1:{port}",
        "http": f"http://127.0.0.1:{port}",
    })
    opener = urllib.request.build_opener(proxy_handler)

    start = time.time()
    try:
        resp = opener.open(url, timeout=120)
    except urllib.error.URLError as e:
        print(f"\n✗ FAILED to open: {e}")
        if "Connection refused" in str(e):
            print("  the auth_proxy daemon is not running or is on a different port")
            print("  run: python auth_proxy.py --status")
        return 1

    declared_size = int(resp.headers.get("Content-Length", 0))
    print(f"\nServer:       {resp.headers.get('Server', '?')}")
    print(f"Content-Type: {resp.headers.get('Content-Type', '?')}")
    print(f"Content-Length: {declared_size or '(none)'}")
    print(f"Content-Encoding: {resp.headers.get('Content-Encoding', '(none)')}")

    h = hashlib.sha512()
    received = 0
    chunks = 0
    last_print = time.time()
    try:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            received += len(chunk)
            chunks += 1
            h.update(chunk)
            if time.time() - last_print > 0.5:
                if declared_size:
                    pct = received * 100 / declared_size
                    print(f"  {received:>10}B / {declared_size}B ({pct:5.1f}%) in {chunks} chunks")
                else:
                    print(f"  {received:>10}B in {chunks} chunks")
                last_print = time.time()
    except Exception as e:
        elapsed = time.time() - start
        print(f"\n✗ READ FAILED after {received}B in {elapsed:.1f}s: {type(e).__name__}: {e}")
        if declared_size:
            print(f"  expected {declared_size}B, got {received}B "
                  f"({received*100/declared_size:.1f}%)")
        return 1

    elapsed = time.time() - start
    actual = h.hexdigest()
    print(f"\n✓ Read {received}B in {chunks} chunks in {elapsed:.1f}s")
    print(f"  sha512: {actual[:64]}...")

    if declared_size and received != declared_size:
        print(f"\n✗ TRUNCATED: expected {declared_size}B, got {received}B "
              f"(missing {declared_size - received}B)")
        return 1

    if expected_sha512:
        # Handle both raw hex and base64 (npm uses base64)
        try:
            import base64
            if expected_sha512.startswith("sha512-"):
                expected_sha512 = expected_sha512[len("sha512-"):]
            try:
                expected_bytes = base64.b64decode(expected_sha512)
                actual_bytes = bytes.fromhex(actual)
                if expected_bytes == actual_bytes:
                    print(f"\n✓ HASH MATCHES expected")
                    return 0
                print(f"\n✗ HASH MISMATCH")
                return 1
            except (ValueError, Exception):
                if actual.lower() == expected_sha512.lower():
                    print(f"\n✓ HASH MATCHES expected")
                    return 0
                print(f"\n✗ HASH MISMATCH (raw hex compare)")
                return 1
        except Exception as e:
            print(f"  could not compare hashes: {e}")
    return 0


def stop_daemon():
    pid = _read_pid()
    if not _is_alive(pid):
        print("auth_proxy not running")
        if os.path.exists(PID_FILE):
            os.unlink(PID_FILE)
        return
    if sys.platform == "win32":
        import ctypes
        PROCESS_TERMINATE = 0x0001
        h = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if h:
            ctypes.windll.kernel32.TerminateProcess(h, 0)
            ctypes.windll.kernel32.CloseHandle(h)
    else:
        import signal as _signal
        os.kill(pid, _signal.SIGTERM)
    if os.path.exists(PID_FILE):
        os.unlink(PID_FILE)
    print(f"auth_proxy stopped (pid {pid})")


def status():
    pid = _read_pid()
    if _is_alive(pid):
        print(f"auth_proxy running (pid {pid})")
        return 0
    print("auth_proxy not running")
    return 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--upstream", help="Upstream proxy URL, e.g. http://corp.proxy:8080")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--mitm", metavar="HOSTS", default=None,
                   help="Enable TLS interception for these hosts (comma-separated, "
                        "or '*' for all). Required to handle McAfee/proxy progress "
                        "pages that replace large files with HTML. Hosts match "
                        "exactly or as suffix (e.g. 'npmjs.org' covers "
                        "'registry.npmjs.org'). Requires `cryptography` and the "
                        "auth_proxy CA in your trust bundle.")
    p.add_argument("--mitm-print-ca", action="store_true",
                   help="Print the path to the auth_proxy CA cert and exit. "
                        "Add this cert to your CA bundle so clients trust the "
                        "intercepted TLS connections.")
    p.add_argument("--mitm-check", action="store_true",
                   help="Run trust-store diagnostics: verify the MITM CA exists, "
                        "is registered with Node via NODE_EXTRA_CA_CERTS, and is "
                        "actually present in the bundle file. Use this when MITM "
                        "appears to hang during the client TLS handshake or when "
                        "pnpm/npm doesn't send a request after CONNECT.")
    p.add_argument("--debug", action="store_true",
                   help="Verbose per-request logging: every request line, every "
                        "request and response header, every TLS milestone, every "
                        "MWG poll. Off by default; the normal log shows only "
                        "lifecycle events, errors, and one summary line per "
                        "completed request.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--start", action="store_true", help="Start as a background daemon")
    g.add_argument("--stop", action="store_true", help="Stop the running daemon")
    g.add_argument("--status", action="store_true", help="Check daemon status")
    g.add_argument("--serve", action="store_true",
                   help="Run in foreground (used internally by --start)")
    g.add_argument("--diagnose", metavar="URL",
                   help="Fetch URL through the running daemon and report. "
                        "Use to debug ERR_PNPM_TARBALL_INTEGRITY etc. "
                        "Optionally pair with --expect-sha512 SHA")
    p.add_argument("--expect-sha512", metavar="HASH",
                   help="(with --diagnose) expected sha512 hash, raw hex or "
                        "base64-encoded npm-style 'sha512-...'")
    args = p.parse_args()

    if args.mitm_print_ca:
        try:
            import mitm_handler
            ca = mitm_handler.get_ca()
            print(ca.ca_cert_path)
            return 0
        except ImportError as e:
            print(f"mitm_handler unavailable: {e}", file=sys.stderr)
            print("install with: pip install cryptography", file=sys.stderr)
            return 1

    if args.mitm_check:
        try:
            import mitm_handler
        except ImportError as e:
            print(f"mitm_handler unavailable: {e}", file=sys.stderr)
            return 1
        ca = mitm_handler.get_ca()
        print(f"MITM CA path:        {ca.ca_cert_path}")
        print(f"MITM CA fingerprint: {mitm_handler.compute_ca_fingerprint(ca.ca_cert_path)}")
        print()
        node_extra = os.environ.get("NODE_EXTRA_CA_CERTS")
        if node_extra:
            print(f"NODE_EXTRA_CA_CERTS = {node_extra}")
        else:
            print("NODE_EXTRA_CA_CERTS = (not set)")
        warnings = mitm_handler.check_ca_trust_status(ca.ca_cert_path)
        if not warnings:
            print()
            print("All checks passed. The MITM CA is in the Node CA bundle.")
            print("If pnpm/npm still doesn't trust it, restart the shell that")
            print("launches them so the latest NODE_EXTRA_CA_CERTS env var is")
            print("inherited (setx only affects new processes).")
            return 0
        print()
        print("Issues found:")
        for w in warnings:
            print(f"  - {w}")
        return 1

    # Parse mitm host list
    mitm_hosts = None
    if args.mitm is not None:
        if args.mitm.strip() == "*":
            mitm_hosts = set()  # empty = all
        else:
            mitm_hosts = {h.strip() for h in args.mitm.split(",") if h.strip()}

    if args.stop:
        stop_daemon()
        return 0
    if args.status:
        return status()
    if args.diagnose:
        return diagnose_url(args.diagnose, port=args.port, expected_sha512=args.expect_sha512)
    if args.start:
        if not args.upstream:
            p.error("--start requires --upstream")
        start_daemon(args.upstream, port=args.port, mitm_hosts=mitm_hosts,
                     debug=args.debug)
        return 0
    if args.serve:
        if not args.upstream:
            p.error("--serve requires --upstream")
        serve(args.upstream, port=args.port, bind=args.bind,
              log=_make_safe_log(debug=args.debug),
              mitm_hosts=mitm_hosts)
        return 0

    # Default: foreground serve
    if not args.upstream:
        p.error("--upstream is required (or pass --stop / --status)")
    serve(args.upstream, port=args.port, bind=args.bind,
          log=_make_safe_log(debug=args.debug),
          mitm_hosts=mitm_hosts)
    return 0


def _make_safe_log(debug=False):
    """
    Return a log function that timestamps each line and never raises on
    encoding errors. The returned callable has an extra `.debug` attribute,
    also callable. By default `.debug` is a no-op; pass `debug=True` to make
    it equivalent to the main log.

    Usage from callers:

        log("auth_proxy listening on ...")     # always shows
        log.debug("req #1 forwarded to upstream")  # only shows with --debug

    The split is at call sites — verbose, per-request, and instrumentation
    output should use `log.debug`; lifecycle and unusual events should use
    plain `log`.
    """
    def _log(msg):
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        try:
            print(line, flush=True)
        except UnicodeEncodeError:
            # Re-encode against the active stdout encoding with replacement.
            enc = getattr(sys.stdout, "encoding", None) or "ascii"
            safe = line.encode(enc, errors="replace").decode(enc, errors="replace")
            try:
                print(safe, flush=True)
            except Exception:
                # Absolute last resort — write raw bytes to stdout's buffer.
                try:
                    sys.stdout.buffer.write(
                        line.encode("utf-8", errors="replace") + b"\n"
                    )
                    sys.stdout.flush()
                except Exception:
                    pass

    if debug:
        _log.debug = _log
    else:
        _log.debug = lambda _msg: None
    return _log


if __name__ == "__main__":
    sys.exit(main())