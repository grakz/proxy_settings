"""
MITM (man-in-the-middle) handler for auth_proxy.

When the corporate proxy intercepts large file downloads and replaces the
response with a McAfee Web Gateway "progress page" (HTML with a 'Click here
to get the file' link), the file bytes are not actually delivered — the
client gets HTML instead and rejects it as integrity-corrupt or fails to
parse it as a tarball.

This module solves that by terminating TLS inside auth_proxy, inspecting
the response, and following the progress link on the client's behalf so
the client receives the real bytes.

Architecture:
    [client] <--TLS(our leaf cert)--> [auth_proxy] <--TLS(corp CA leaf)--> [corp proxy] --> [origin]

We generate a local CA on first run; the user adds it to their CA bundle
(via configure_proxy.py or manually). Per-hostname leaf certs are signed
on the fly and cached in memory.

Requires the `cryptography` library.
"""

import datetime
import os
import re
import socket
import ssl
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse, urljoin


# ---------------------------------------------------------------------------
# CA / cert generation
# ---------------------------------------------------------------------------

CA_DIR = Path(os.path.expanduser("~")) / ".config" / "configure_proxy"
CA_CERT_PATH = CA_DIR / "auth_proxy_ca.pem"
CA_KEY_PATH = CA_DIR / "auth_proxy_ca.key"


class CertAuthority:
    """
    Local CA for signing per-host leaf certs. Loads or creates the CA on init.
    Thread-safe leaf cert cache.
    """

    def __init__(self, ca_cert_path=CA_CERT_PATH, ca_key_path=CA_KEY_PATH):
        self.ca_cert_path = Path(ca_cert_path)
        self.ca_key_path = Path(ca_key_path)
        self._leaf_cache = {}  # hostname -> (cert_pem, key_pem) bytes
        self._lock = threading.Lock()
        self._ca_cert = None
        self._ca_key = None
        self._load_or_create_ca()

    def _load_or_create_ca(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            self._ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
            self._ca_key = serialization.load_pem_private_key(
                self.ca_key_path.read_bytes(), password=None
            )
            return

        # Generate a new CA
        self.ca_cert_path.parent.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "auth_proxy local CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "configure_proxy"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ), critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256()))

        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.ca_key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        try:
            os.chmod(self.ca_key_path, 0o600)
        except OSError:
            pass

        self._ca_cert = cert
        self._ca_key = key

    def get_leaf_files(self, hostname):
        """
        Return (cert_path, key_path) for a leaf cert valid for `hostname`.
        Files are written to a temp location and returned by path because
        ssl.SSLContext.load_cert_chain wants paths, not in-memory PEM
        (without using the SSLContext.load_cert_chain in-memory variant
        which is awkward).
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        with self._lock:
            cached = self._leaf_cache.get(hostname)
            if cached:
                return cached

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            now = datetime.datetime.now(datetime.timezone.utc)
            san = [x509.DNSName(hostname)]
            # Also accept *.host for wildcard scenarios
            if not hostname.replace(".", "").isdigit():
                san.append(x509.DNSName(f"*.{hostname}"))
            cert = (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self._ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(hours=1))
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName(san), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")]),
                    critical=False,
                )
                .sign(self._ca_key, hashes.SHA256()))

            cert_dir = CA_DIR / "leaves"
            cert_dir.mkdir(exist_ok=True)
            # Sanitize hostname for filename
            safe = re.sub(r"[^a-zA-Z0-9._-]", "_", hostname)
            cert_path = cert_dir / f"{safe}.pem"
            key_path = cert_dir / f"{safe}.key"
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass

            self._leaf_cache[hostname] = (str(cert_path), str(key_path))
            return self._leaf_cache[hostname]

    def make_server_context(self, hostname):
        """SSLContext with our leaf cert for `hostname`, ready to wrap a client socket."""
        cert_path, key_path = self.get_leaf_files(hostname)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        # We don't need to verify the client (pnpm/git/npm don't present client certs)
        ctx.verify_mode = ssl.CERT_NONE
        # Allow older protocols if needed
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx


def compute_ca_fingerprint(ca_cert_path):
    """Return SHA256 fingerprint of a PEM-encoded cert as colon-separated hex."""
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(open(ca_cert_path, "rb").read())
    der = cert.public_bytes(serialization.Encoding.DER)
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i+2] for i in range(0, len(h), 2))


def check_ca_trust_status(ca_cert_path):
    """
    Return a list of human-readable warnings about whether the MITM CA appears
    to be installed in places that matter. Empty list means "looks OK".
    Specifically checks:
      - NODE_EXTRA_CA_CERTS env var is set in the *current* process
      - The file it points to contains the MITM CA
      - npm cafile is set (best-effort)
    """
    warnings = []

    def _normalize_eol(b):
        # Normalize line endings so a CRLF bundle still matches an LF cert
        # (or vice versa). We compare bytes after this normalization.
        return b.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

    # Read the MITM CA's PEM body so we can string-match it in bundles
    try:
        ca_pem = _normalize_eol(open(ca_cert_path, "rb").read()).strip()
    except OSError as e:
        warnings.append(f"could not read MITM CA file: {e}")
        return warnings

    # Where Node's bundle should be
    node_extra = os.environ.get("NODE_EXTRA_CA_CERTS")
    if not node_extra:
        warnings.append(
            "NODE_EXTRA_CA_CERTS is NOT set in this process. "
            "Node-based clients (pnpm, npm, etc.) won't trust the MITM CA. "
            "Run: python configure_proxy.py  (and restart your shell so the "
            "new env var is picked up)."
        )
        return warnings

    if not os.path.exists(node_extra):
        warnings.append(
            f"NODE_EXTRA_CA_CERTS points to {node_extra} but that file does not exist. "
            "Run: python configure_proxy.py"
        )
        return warnings

    try:
        bundle = _normalize_eol(open(node_extra, "rb").read())
    except OSError as e:
        warnings.append(f"could not read CA bundle at {node_extra}: {e}")
        return warnings

    if ca_pem not in bundle:
        warnings.append(
            f"MITM CA is NOT present in the Node CA bundle ({node_extra}). "
            "Re-run: python configure_proxy.py  "
            "(this auto-appends the MITM CA when it exists). "
            "Then restart any pnpm/node processes — they cache trust on startup."
        )

    return warnings


# ---------------------------------------------------------------------------
# HTTP request/response handling on plaintext sockets
# ---------------------------------------------------------------------------

BUFFER_SIZE = 65536


def read_http_message(sock, max_header_size=131072, is_request=False):
    """
    Read an HTTP message (request or response) from a TLS-unwrapped socket.
    Returns (head_bytes, body_bytes) where body has already been read in
    full according to Content-Length or Transfer-Encoding: chunked.

    Framing rules differ between requests and responses, so the caller MUST
    indicate which it expects:

    - is_request=True: requests without Content-Length and without
      Transfer-Encoding: chunked have NO body (this is required by HTTP/1.1).
      A GET/HEAD/DELETE etc. typically has no body, and the client is then
      waiting for our response. If we tried to read until EOF here, we'd
      block forever because the client is keeping the connection open.

    - is_request=False (response): responses without Content-Length and
      without chunked encoding ARE body-framed by connection close (the
      classic HTTP/1.0 "read until EOF" rule). This is unusual for HTTP/1.1
      but allowed.

    Raises OSError on truncated message or protocol violation.
    """
    head_buf = b""
    while b"\r\n\r\n" not in head_buf:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            if not head_buf:
                return None, None  # connection closed cleanly with no message
            raise OSError(f"connection closed mid-headers ({len(head_buf)} bytes received)")
        head_buf += chunk
        if len(head_buf) > max_header_size:
            raise OSError("HTTP headers exceeded max size")

    head, _, leftover = head_buf.partition(b"\r\n\r\n")

    # Check Transfer-Encoding before Content-Length (per RFC 7230).
    headers_lower = head.lower()
    if b"transfer-encoding: chunked" in headers_lower:
        body = _read_chunked_body(sock, leftover)
    elif b"content-length:" in headers_lower:
        cl = _content_length(head)
        body = _read_fixed_body(sock, leftover, cl)
    else:
        # No length info.
        if is_request:
            # Requests with neither Content-Length nor chunked have no body.
            # Anything still in `leftover` is the next pipelined request,
            # which we don't currently support — but it shouldn't happen for
            # HTTPS-through-CONNECT clients we proxy.
            body = b""
        else:
            # Response with no length info: framed by connection close.
            body = leftover
            while True:
                chunk = sock.recv(BUFFER_SIZE)
                if not chunk:
                    break
                body += chunk

    return head, body


def _content_length(head):
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                return 0
    return 0


def _read_fixed_body(sock, prefix, n):
    body = prefix
    while len(body) < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - len(body)))
        if not chunk:
            raise OSError(f"connection closed mid-body ({len(body)}/{n} bytes)")
        body += chunk
    return body


def _read_chunked_body(sock, prefix):
    """
    Read a Transfer-Encoding: chunked body. Returns the *decoded* bytes
    (chunk markers removed).
    """
    buf = prefix
    decoded = b""
    while True:
        # Read chunk size line
        while b"\r\n" not in buf:
            more = sock.recv(BUFFER_SIZE)
            if not more:
                raise OSError("connection closed mid-chunk-size")
            buf += more
        size_line, _, rest = buf.partition(b"\r\n")
        try:
            chunk_size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            raise OSError(f"bad chunk size line: {size_line!r}")
        if chunk_size == 0:
            # Read trailing headers and final CRLF
            while b"\r\n\r\n" not in (b"\r\n" + rest):
                more = sock.recv(BUFFER_SIZE)
                if not more:
                    break
                rest += more
            return decoded
        # Read chunk_size bytes + trailing \r\n
        needed = chunk_size + 2  # +2 for trailing \r\n
        while len(rest) < needed:
            more = sock.recv(BUFFER_SIZE)
            if not more:
                raise OSError("connection closed mid-chunk")
            rest += more
        decoded += rest[:chunk_size]
        buf = rest[needed:]


def replace_header(head, name, value):
    """Set or replace a header in a header block. Returns new bytes."""
    name_lower = name.lower().encode("ascii") if isinstance(name, str) else name.lower()
    new_line = f"{name}: {value}".encode("ascii") if isinstance(value, str) else (
        name + b": " + value
    )
    out_lines = []
    found = False
    for line in head.split(b"\r\n"):
        if line.lower().startswith(name_lower + b":"):
            if not found:
                out_lines.append(new_line)
                found = True
            # else: drop duplicate
        else:
            out_lines.append(line)
    if not found:
        out_lines.append(new_line)
    return b"\r\n".join(out_lines)


def remove_header(head, name):
    """Remove all occurrences of a header (case-insensitive)."""
    name_lower = name.lower().encode("ascii") if isinstance(name, str) else name.lower()
    out_lines = [
        line for line in head.split(b"\r\n")
        if not line.lower().startswith(name_lower + b":")
    ]
    return b"\r\n".join(out_lines)


def get_header(head, name):
    """Return the first matching header value, or None."""
    name_lower = name.lower().encode("ascii") if isinstance(name, str) else name.lower()
    for line in head.split(b"\r\n"):
        if line.lower().startswith(name_lower + b":"):
            return line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
    return None


# ---------------------------------------------------------------------------
# McAfee Web Gateway progress-page detection
# ---------------------------------------------------------------------------
#
# The McAfee MWG "progress" mechanism for large file downloads has THREE
# distinct page states the proxy serves under /mwg-internal/.../progress?id=...:
#
#   1. WAITING page (HTML, ~10KB): served while MWG is still downloading and
#      scanning the file. Contains "Please Wait", a JS progress meter, and
#      a hidden meta with the progress page id. JS in the page polls the same
#      URL with `&a=1&<timestamp>` appended.
#
#   2. POLL response (text/plain or text/html, very small, <500B): served
#      in response to the `&a=1&...` polls. Body looks like
#         "1234567;7000000;30;0;0"
#      (downloaded;total;percent;ready;scan_seconds). When `ready` is 1, the
#      JS reloads the WAITING URL.
#
#   3. READY page (HTML): served once the file has finished downloading and
#      passed scanning. Contains "Click here to get the file" with a link
#      ending in &dl. Following that link yields the actual file bytes.
#
# The full flow we have to emulate:
#
#   GET <orig URL>                 -> 307 Location: <progress URL>
#   GET <progress URL>             -> 200 WAITING page
#   GET <progress URL>&a=1&<ts>    -> POLL response, ready=0
#     (repeat every ~3s until ready=1)
#   GET <progress URL>             -> 200 READY page
#   GET <progress URL>&dl          -> 200 file bytes

# Common: the response is an MWG page when its body contains the proxy's
# internal path marker. This is the signal "we're still inside the MWG
# state machine, not at the real origin yet".
_MWG_PATH_MARKER = b"mwg-internal"

# Page 3 (READY): contains a link `<a href="/mwg-internal/.../progress?...&dl">`.
# The HTML may use `&amp;dl` (entity-encoded) or `&dl` (literal). We accept
# both, then decode entities before using the URL.
_MCAFEE_READY_LINK_RE = re.compile(
    rb'href="(/mwg-internal/[^"]*progress[^"]*(?:&amp;|&)dl(?:=[^"&]*)?[^"]*)"',
    re.IGNORECASE,
)

# Page 1 (WAITING): contains "Please Wait" and references the progress polling
# JS. We don't need a tight regex — the absence of the READY link plus the
# WAITING signature is enough.
_MCAFEE_WAITING_RE = re.compile(
    rb'Please\s*Wait|printProgressBar\s*\(|id=["\']progresspageid["\']',
    re.IGNORECASE,
)

# Page 2 (POLL): semicolon-delimited 5-field body, no HTML, length < 500.
_MCAFEE_POLL_RE = re.compile(
    rb'^\s*[^;]{0,20};[^;]{0,20};[01]?\d{0,3};[01];[^;]{0,100}\s*$'
)


class McAfeeState:
    """Identified MWG page kind."""
    NOT_MCAFEE = "not_mcafee"
    WAITING = "waiting"      # Please-wait HTML; we need to poll
    READY = "ready"          # Click-here HTML; link is available
    POLL = "poll"            # response to a polling XHR


def classify_mcafee_response(response_head, response_body):
    """Return one of McAfeeState.* describing the response."""
    if response_body is None or not response_body:
        return McAfeeState.NOT_MCAFEE

    ct = (get_header(response_head, "Content-Type") or "").lower()

    # Poll responses are short and not HTML
    if len(response_body) < 500 and "html" not in ct:
        if _MCAFEE_POLL_RE.match(response_body):
            return McAfeeState.POLL

    # Both WAITING and READY are HTML containing "mwg-internal"
    if "html" not in ct:
        return McAfeeState.NOT_MCAFEE
    if _MWG_PATH_MARKER not in response_body:
        return McAfeeState.NOT_MCAFEE

    # READY: has the &dl link
    if _MCAFEE_READY_LINK_RE.search(response_body):
        return McAfeeState.READY

    # WAITING: has the progress-meter signature
    if _MCAFEE_WAITING_RE.search(response_body):
        return McAfeeState.WAITING

    # MWG-looking HTML but neither pattern matched. Could be a new variant —
    # treat as not-McAfee so we pass it through and the user can investigate.
    return McAfeeState.NOT_MCAFEE


def extract_ready_link(response_body, base_url):
    """Find the &dl link in a READY page body. Returns absolute URL or None."""
    m = _MCAFEE_READY_LINK_RE.search(response_body)
    if not m:
        return None
    # The href may contain HTML-entity-encoded ampersands; decode them.
    raw = m.group(1).decode("ascii", errors="replace")
    raw = raw.replace("&amp;", "&")
    return urljoin(base_url, raw)


def parse_poll_response(body):
    """
    Parse a POLL response body (e.g. "1234;5678;22;0;3") into a dict.
    Returns None if the body isn't a valid poll response.
    """
    text = body.strip().decode("ascii", errors="replace")
    parts = text.split(";")
    if len(parts) < 5:
        return None
    try:
        return {
            "downloaded": parts[0],
            "total": parts[1],
            "percent": parts[2],
            "ready": parts[3] == "1",
            "scan_seconds": parts[4],
        }
    except (IndexError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Main MITM handler entry point
# ---------------------------------------------------------------------------

def _ensure_debug_attr(log):
    """
    Ensure the given log callable has a `.debug` attribute that is itself a
    callable. If absent, attach a no-op (so verbose call sites silently skip).

    Callers built via auth_proxy's `_make_safe_log()` always have `.debug`.
    This wrapper exists for ad-hoc callables (test scripts, lambdas) so they
    don't AttributeError when this module uses `log.debug(...)`.

    We don't try to "promote" a bare callable to a debug-printing one — that
    would be surprising behavior. The principle is: if you didn't opt in to
    debug logging by constructing a log function with `.debug`, you don't get
    debug output.
    """
    if hasattr(log, "debug") and callable(log.debug):
        return log
    # Wrap in a tiny shim that satisfies the .debug protocol.
    class _LogWithNoopDebug:
        def __init__(self, fn): self._fn = fn
        def __call__(self, msg): self._fn(msg)
        def debug(self, _msg): pass
    return _LogWithNoopDebug(log)


def mitm_handle_connect(client_sock, host, port, upstream_factory, ca, log):
    """
    Handle a CONNECT in MITM mode: terminate TLS toward the client using a
    leaf cert for `host` signed by our CA, open a TLS connection through
    upstream to the real `host:port`, then proxy HTTP requests/responses
    one at a time. On responses that look like McAfee progress pages,
    follow the link transparently and serve the real bytes to the client.

    `upstream_factory()` should return a fresh upstream socket — either by
    doing the authenticated CONNECT through the corp proxy, or by a direct
    connect when no auth is needed.

    `ca` is a CertAuthority instance.
    """
    import time as _t

    # Make sure log has a .debug attribute. Callers built via auth_proxy's
    # _make_safe_log() always provide one, but if a test script or a custom
    # caller passes a bare callable, we don't want AttributeError.
    log = _ensure_debug_attr(log)

    # 1. Tell the client the tunnel is open
    log.debug(f"  MITM[{host}]: sending 200 to client")
    client_sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

    # 2. TLS-wrap the client socket with our leaf cert for `host`.
    # Set a finite timeout so that if the client never sends ClientHello
    # (e.g. it doesn't trust our cert), we fail fast instead of hanging.
    log.debug(f"  MITM[{host}]: starting client-side TLS handshake")
    server_ctx = ca.make_server_context(host)
    t0 = _t.time()
    try:
        client_sock.settimeout(30)
        client_tls = server_ctx.wrap_socket(client_sock, server_side=True)
        client_tls.settimeout(None)
    except (ssl.SSLError, socket.timeout, OSError) as e:
        log(f"  MITM[{host}]: client TLS handshake FAILED after {_t.time()-t0:.1f}s: "
            f"{type(e).__name__}: {e}")
        log(f"  MITM[{host}]: most common cause = client doesn't trust our CA.")
        log(f"  MITM[{host}]: ensure {ca.ca_cert_path} is in your CA bundle, then re-run configure_proxy.py")
        return
    log.debug(f"  MITM[{host}]: client TLS up ({_t.time()-t0:.1f}s)")

    # 3. Open upstream socket via the upstream_factory (authenticated CONNECT
    # through the corp proxy in production).
    log.debug(f"  MITM[{host}]: opening upstream to corp proxy")
    t1 = _t.time()
    try:
        upstream_raw = upstream_factory(host, port)
    except Exception as e:
        log(f"  MITM[{host}]: upstream connect FAILED after {_t.time()-t1:.1f}s: "
            f"{type(e).__name__}: {e}")
        try: client_tls.shutdown(socket.SHUT_WR); client_tls.close()
        except OSError: pass
        return
    log.debug(f"  MITM[{host}]: upstream socket open ({_t.time()-t1:.1f}s)")

    # 4. TLS-wrap the upstream socket. The cert presented by the corp proxy
    # is signed by the corp CA; we verify against the system trust store
    # (which configure_proxy.py has populated with the corp CA).
    log.debug(f"  MITM[{host}]: starting upstream TLS handshake (verifying corp cert)")
    client_ctx = ssl.create_default_context()
    t2 = _t.time()
    try:
        upstream_raw.settimeout(30)
        upstream_tls = client_ctx.wrap_socket(upstream_raw, server_hostname=host)
        upstream_tls.settimeout(None)
    except (ssl.SSLError, socket.timeout, OSError) as e:
        log(f"  MITM[{host}]: upstream TLS handshake FAILED after {_t.time()-t2:.1f}s: "
            f"{type(e).__name__}: {e}")
        log(f"  MITM[{host}]: this means the corp proxy's cert is not trusted by Python.")
        log(f"  MITM[{host}]: check that the corp CA is installed in the system root store.")
        try: upstream_raw.close()
        except OSError: pass
        try: client_tls.shutdown(socket.SHUT_WR); client_tls.close()
        except OSError: pass
        return
    log.debug(f"  MITM[{host}]: upstream TLS up ({_t.time()-t2:.1f}s); entering proxy loop")

    # 5. Proxy HTTP requests on this TLS connection until it closes.
    try:
        _proxy_http_requests(client_tls, upstream_tls, host, port, upstream_factory, ca, log)
    finally:
        for s in (client_tls, upstream_tls):
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def _proxy_http_requests(client, upstream, host, port, upstream_factory, ca, log):
    """One TLS connection from the client; loop forwarding HTTP requests."""
    import time as _t
    request_count = 0
    while True:
        request_count += 1
        log.debug(f"  MITM[{host}]: waiting for client request #{request_count}")
        t_wait_req = _t.time()
        try:
            req_head, req_body = read_http_message(client, is_request=True)
        except OSError as e:
            elapsed = _t.time() - t_wait_req
            # Read failures on req #1 with no data are interesting; on req #2+
            # they're just a normal end-of-keep-alive close from the client.
            if request_count == 1:
                log(f"  MITM[{host}]: client read failed after {elapsed:.1f}s "
                    f"(req #{request_count}): {e}")
                if elapsed > 30:
                    log(f"  MITM[{host}]: HINT: client completed TLS but never sent a request.")
                    log(f"  MITM[{host}]: this almost always means the client doesn't trust our CA.")
                    log(f"  MITM[{host}]: run `python auth_proxy.py --mitm-check` to diagnose.")
            else:
                log.debug(f"  MITM[{host}]: client read failed after {elapsed:.1f}s "
                    f"(req #{request_count}): {e}")
            return
        if req_head is None:
            elapsed = _t.time() - t_wait_req
            if request_count == 1:
                log(f"  MITM[{host}]: client closed cleanly after {elapsed:.1f}s "
                    f"(after req #{request_count-1})")
                if elapsed > 30:
                    log(f"  MITM[{host}]: HINT: client completed TLS but never sent a request.")
                    log(f"  MITM[{host}]: this almost always means the client doesn't trust our CA.")
                    log(f"  MITM[{host}]: run `python auth_proxy.py --mitm-check` to diagnose.")
            else:
                log.debug(f"  MITM[{host}]: client closed cleanly after {elapsed:.1f}s "
                    f"(after req #{request_count-1})")
            return  # clean close

        # Parse the request line for logging
        request_line = req_head.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        method = request_line.split()[0] if request_line.split() else ""
        path = request_line.split()[1] if len(request_line.split()) >= 2 else "/"
        path_short = path if len(path) <= 80 else path[:77] + "..."
        log.debug(f"  MITM[{host}]: req #{request_count} received: {method} {path_short} "
            f"({len(req_body or b'')}B body, waited {_t.time()-t_wait_req:.1f}s)")
        # Dump request headers for debugging — helps spot oddities like the
        # client sending Connection: close, unusual Accept-Encoding, etc.
        for h_line in req_head.split(b"\r\n")[1:]:
            if h_line:
                log.debug(f"  MITM[{host}]: req #{request_count} header: {h_line.decode('ascii', errors='replace')}")

        # Forward the request as-is to upstream
        try:
            upstream.sendall(req_head + b"\r\n\r\n" + (req_body or b""))
        except OSError as e:
            log(f"  MITM[{host}]: upstream send failed: {e}")
            return
        log.debug(f"  MITM[{host}]: req #{request_count} forwarded to upstream; waiting for response")

        t_wait_resp = _t.time()
        try:
            resp_head, resp_body = read_http_message(upstream)
        except OSError as e:
            log(f"  MITM[{host}]: upstream read failed after {_t.time()-t_wait_resp:.1f}s "
                f"(req #{request_count}): {e}")
            return
        if resp_head is None:
            log(f"  MITM[{host}]: upstream closed without response (req #{request_count})")
            return

        # Now that we have the response from upstream, do a quick liveness
        # check on the client BEFORE attempting to send. If select says the
        # client socket is readable, that means either:
        #   - data arrived from the client (unusual mid-response — possibly a
        #     pipelined request, but more likely a TLS close_notify alert)
        #   - the underlying TCP got FIN/RST
        # We use select on the SSL socket's underlying fd; SSLSocket inherits
        # fileno() correctly. If pending() shows decrypted data already
        # buffered, that's also a sign the client did something weird.
        try:
            import select as _select
            r, _, _ = _select.select([client], [], [], 0)
            if r:
                pending = client.pending() if hasattr(client, "pending") else 0
                log.debug(f"  MITM[{host}]: client socket is readable BEFORE we send response "
                    f"(req #{request_count}); ssl pending()={pending}; "
                    f"this usually means pnpm closed the connection")
        except Exception as e:
            log.debug(f"  MITM[{host}]: liveness check raised {type(e).__name__}: {e}")

        base_url = f"https://{host}:{port}{path}"

        # Parse status to detect 307 redirects to MWG, which is the most common
        # entry point for the McAfee progress flow.
        status_line = resp_head.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        sl_parts = status_line.split(None, 2)
        try:
            resp_status = int(sl_parts[1]) if len(sl_parts) >= 2 else 0
        except ValueError:
            resp_status = 0

        # Visibility: log every response with status, size, content-type, and
        # any McAfee classification. Truncate long paths.
        ct = (get_header(resp_head, "Content-Type") or "?").split(";", 1)[0].strip()
        body_len = len(resp_body or b"")
        mcafee_state_dbg = classify_mcafee_response(resp_head, resp_body)
        location_dbg = get_header(resp_head, "Location")
        extra = ""
        if mcafee_state_dbg != McAfeeState.NOT_MCAFEE:
            extra += f" mwg={mcafee_state_dbg}"
        if location_dbg:
            extra += f" Location={location_dbg[:80]}"
        log.debug(f"  MITM[{host}]: req #{request_count} response: {resp_status} {ct} "
            f"{body_len}B (upstream took {_t.time()-t_wait_resp:.1f}s){extra}")
        # Dump response headers so we can see Content-Encoding, Content-Length,
        # Transfer-Encoding, Connection, etc. This helps diagnose cases where
        # the client closes mid-response — e.g. if Content-Length doesn't match
        # the body we read, or if both Content-Length and chunked are present.
        for h_line in resp_head.split(b"\r\n")[1:]:
            if h_line:
                log.debug(f"  MITM[{host}]: req #{request_count} resp header: {h_line.decode('ascii', errors='replace')}")

        # --- McAfee detection: ---
        # Path A: 307 redirect to /mwg-internal/.../progress?id=...
        # Path B: response is itself an MWG WAITING or READY page (no redirect)
        is_mwg_redirect = (
            resp_status in (301, 302, 303, 307, 308)
            and method == "GET"
            and (get_header(resp_head, "Location") or "").find("/mwg-internal/") >= 0
        )
        mcafee_state = classify_mcafee_response(resp_head, resp_body)
        is_mwg_page = (
            method == "GET" and mcafee_state in (McAfeeState.WAITING, McAfeeState.READY)
        )

        if is_mwg_redirect or is_mwg_page:
            if is_mwg_redirect:
                progress_url = urljoin(base_url, get_header(resp_head, "Location"))
                log.debug(f"  MITM[{host}]: MWG 307 redirect for {path} -> {progress_url}")
                # Original upstream is done — close it and re-fetch via state machine
                try: upstream.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                try: upstream.close()
                except OSError: pass
                # Follow the 307 ourselves to pick up the WAITING (or READY) page
                final_url, status, mwg_head, mwg_body = _follow_redirects(
                    progress_url, upstream_factory, log,
                )
                if status != 200:
                    log(f"  MITM[{host}]: MWG progress URL returned {status}; aborting")
                    return
                progress_url = final_url
            else:
                log.debug(f"  MITM[{host}]: MWG {mcafee_state} page directly for {path}")
                progress_url = base_url
                mwg_head, mwg_body = resp_head, resp_body
                # Close the original upstream — Connection: close is typical
                try: upstream.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                try: upstream.close()
                except OSError: pass

            # Drive the state machine
            try:
                file_body, file_head = _handle_mcafee_progress(
                    progress_url, mwg_head, mwg_body, upstream_factory, log,
                )
            except Exception as e:
                log(f"  MITM[{host}]: MWG handler raised: {type(e).__name__}: {e}")
                file_body = file_head = None

            if file_body is not None:
                new_head = _build_synthesized_response(file_head, file_body)
                try:
                    client.sendall(new_head + b"\r\n\r\n" + file_body)
                except OSError as e:
                    log(f"  MITM[{host}]: client send failed (after MWG fetch): {e}")
                    return
            else:
                log(f"  MITM[{host}]: MWG handling failed; sending 502 to client")
                err = (b"HTTP/1.1 502 Bad Gateway\r\n"
                       b"Content-Type: text/plain\r\n"
                       b"Content-Length: 0\r\n"
                       b"Connection: close\r\n"
                       b"X-MITM-Source: auth_proxy-mcafee-progress\r\n\r\n")
                try: client.sendall(err)
                except OSError: pass
            # Original upstream is gone — end this client connection
            return

        # Normal response: forward to client.
        # CRITICAL: read_http_message has already dechunked the body. The
        # `resp_body` we have is plain bytes, but `resp_head` may still say
        # `Transfer-Encoding: chunked`. Forwarding both as-is gives the client
        # a body that doesn't match the headers — pnpm/undici sees what looks
        # like garbage at the start of the "chunked" stream, decides the
        # response is corrupt, and sends RST. That manifests on our side as
        # ECONNRESET when sendall tries to write the rest of the body.
        # Fix: rewrite the headers to use plain Content-Length framing, since
        # we've already buffered the whole body and know its size.
        out_head = _rewrite_response_for_buffered_body(resp_head, len(resp_body))

        try:
            client.sendall(out_head + b"\r\n\r\n" + resp_body)
        except OSError as e:
            # By the time we get here on a clean response, the most common
            # cause of a 10054/EPIPE is that we sent something the client
            # rejected (e.g. mismatched framing, malformed headers) and the
            # client RST'd partway through our sendall.
            log(f"  MITM[{host}]: client gone before response delivered "
                f"(req #{request_count}, {body_len}B): {e}")
            return

        # Honor Connection: close on either side
        if _has_connection_close(req_head) or _has_connection_close(resp_head):
            return


def _rewrite_response_for_buffered_body(head, body_len):
    """
    Rewrite response headers so they correctly describe a plain-bytes body
    of `body_len` bytes. We do this because:

      - read_http_message dechunks any Transfer-Encoding: chunked response
        into a flat byte string. If we then forward that byte string with
        the original headers (which still say "chunked"), the client tries
        to parse our flat body as chunk-framed and fails, often with RST.

      - We may also need to strip "Transfer-Encoding: gzip" or other
        transforms that we did not in fact apply. (We DO leave
        Content-Encoding alone — that's end-to-end and we never touch the
        compressed payload.)

    We replace any existing Transfer-Encoding and Content-Length with a
    single, accurate Content-Length header. Other headers are preserved.
    """
    lines = head.split(b"\r\n")
    if not lines:
        return head
    status_line = lines[0]
    out_lines = [status_line]
    for line in lines[1:]:
        if not line:
            continue
        # Case-insensitive prefix match on the header name
        lower = line.lower()
        if lower.startswith(b"transfer-encoding:") or lower.startswith(b"content-length:"):
            continue  # drop; we'll add our own Content-Length below
        out_lines.append(line)
    out_lines.append(b"Content-Length: " + str(body_len).encode("ascii"))
    return b"\r\n".join(out_lines)


def _has_connection_close(head):
    val = (get_header(head, "Connection") or "").lower()
    return "close" in val


# ---------------------------------------------------------------------------
# Upstream GET helper + McAfee state-machine driver
# ---------------------------------------------------------------------------

# How long to keep polling an MWG WAITING page before giving up. MWG can scan
# large files for several minutes; we want a generous ceiling but not infinite.
MCAFEE_POLL_TIMEOUT_SECONDS = 600   # 10 minutes
MCAFEE_POLL_INTERVAL_SECONDS = 3    # matches the JS setInterval(3000)
MCAFEE_MAX_REDIRECTS = 5


def _do_get(abs_url, upstream_factory, log, accept="*/*"):
    """
    Issue a single GET to abs_url through a fresh authenticated upstream.
    Returns (status, head_bytes, body_bytes), or (None, None, None) on failure.

    Always opens a new upstream socket — McAfee progress responses come with
    Connection: close so the previous one isn't reusable anyway.
    """
    parsed = urlparse(abs_url)
    target_host = parsed.hostname
    target_port = parsed.port or 443
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    if not path:
        path = "/"

    upstream = None
    try:
        try:
            fresh_raw = upstream_factory(target_host, target_port)
        except Exception as e:
            log(f"  MITM: upstream open for {target_host}:{target_port} failed: {e}")
            return None, None, None

        try:
            ctx = ssl.create_default_context()
            upstream = ctx.wrap_socket(fresh_raw, server_hostname=target_host)
        except Exception as e:
            log(f"  MITM: TLS handshake to {target_host} failed: {e}")
            try: fresh_raw.close()
            except OSError: pass
            return None, None, None

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"User-Agent: auth_proxy-mitm/1.0\r\n"
            f"Accept: {accept}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii")
        try:
            upstream.sendall(req)
        except OSError as e:
            log(f"  MITM: send to {target_host} failed: {e}")
            return None, None, None

        try:
            head, body = read_http_message(upstream)
        except OSError as e:
            log(f"  MITM: read from {target_host} failed: {e}")
            return None, None, None

        if head is None:
            return None, None, None

        status_line = head.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        parts = status_line.split(None, 2)
        try:
            status = int(parts[1]) if len(parts) >= 2 else 0
        except ValueError:
            status = 0

        return status, head, body
    finally:
        if upstream is not None:
            try: upstream.close()
            except OSError: pass


def _follow_redirects(start_url, upstream_factory, log, max_redirects=MCAFEE_MAX_REDIRECTS):
    """
    GET start_url, following 30x redirects up to max_redirects.
    Returns (final_url, status, head, body), or (final_url, None, None, None)
    if the chain failed.
    """
    current = start_url
    for hop in range(max_redirects + 1):
        status, head, body = _do_get(current, upstream_factory, log)
        if status is None:
            return current, None, None, None
        if status in (301, 302, 303, 307, 308):
            location = get_header(head, "Location")
            if not location:
                log(f"  MITM: redirect {status} with no Location header; giving up")
                return current, status, head, body
            new_url = urljoin(current, location)
            log.debug(f"  MITM: {status} -> {new_url}")
            current = new_url
            continue
        return current, status, head, body
    log(f"  MITM: too many redirects (>{max_redirects})")
    return current, None, None, None


def _build_poll_url(progress_url):
    """Append the &a=1&<ms-timestamp> querystring to a progress URL."""
    import time as _time
    ts = int(_time.time() * 1000)
    sep = "&" if "?" in progress_url else "?"
    return f"{progress_url}{sep}a=1&{ts}"


def _wait_for_mcafee_ready(progress_url, upstream_factory, log,
                           timeout=MCAFEE_POLL_TIMEOUT_SECONDS,
                           interval=MCAFEE_POLL_INTERVAL_SECONDS):
    """
    Poll the MWG progress URL until the 4th field of the response is "1"
    (download_ready) or until timeout. Returns True if ready, False otherwise.
    """
    import time as _time
    deadline = _time.time() + timeout
    poll_count = 0
    last_progress = None

    while _time.time() < deadline:
        poll_url = _build_poll_url(progress_url)
        status, head, body = _do_get(poll_url, upstream_factory, log)
        poll_count += 1

        if status is None:
            log(f"  MITM: poll #{poll_count} failed (network)")
            _time.sleep(interval)
            continue
        if status != 200:
            log(f"  MITM: poll #{poll_count} returned status {status}; aborting wait")
            return False

        info = parse_poll_response(body or b"")
        if info is None:
            # Either MWG short-circuited and returned the READY page directly
            # (some versions do that on poll if the file became ready), or the
            # body is unexpected. Check if it's now a READY page.
            state = classify_mcafee_response(head, body)
            if state == McAfeeState.READY:
                log.debug(f"  MITM: poll returned READY page directly after {poll_count} polls")
                return True
            log(f"  MITM: poll #{poll_count} response not parseable "
                f"(state={state}, {len(body or b'')}B); aborting wait")
            if body:
                log(f"  MITM: first 200B: {body[:200]!r}")
            return False

        # Log progress occasionally so the operator knows we're alive
        progress_str = (f"{info['downloaded']}/{info['total']} ({info['percent']}%) "
                        f"scan={info['scan_seconds']}s ready={info['ready']}")
        if progress_str != last_progress:
            log.debug(f"  MITM: poll #{poll_count}: {progress_str}")
            last_progress = progress_str

        if info["ready"]:
            log(f"  MITM: download ready after {poll_count} polls")
            return True

        _time.sleep(interval)

    log(f"  MITM: timed out waiting for MWG download "
        f"({timeout}s, {poll_count} polls, last={last_progress})")
    return False


def _handle_mcafee_progress(initial_url, initial_head, initial_body,
                            upstream_factory, log):
    """
    Drive the full MWG state machine starting from the initial response we
    just got (which is at least a WAITING page or a READY page or a 307).

    Returns (file_body_bytes, file_head_bytes) or (None, None).
    """
    state = classify_mcafee_response(initial_head, initial_body)
    progress_url = initial_url
    head = initial_head
    body = initial_body

    if state == McAfeeState.WAITING:
        log.debug(f"  MITM: WAITING page at {progress_url}")
        log.debug(f"  MITM: polling for ready signal (timeout={MCAFEE_POLL_TIMEOUT_SECONDS}s)")
        if not _wait_for_mcafee_ready(progress_url, upstream_factory, log):
            return None, None

        # Refetch the progress URL — should now be the READY page
        log.debug(f"  MITM: refetching progress URL after ready signal")
        final_url, status, head, body = _follow_redirects(
            progress_url, upstream_factory, log,
        )
        if status != 200:
            log(f"  MITM: post-ready refetch returned {status}")
            return None, None
        state = classify_mcafee_response(head, body)
        if state != McAfeeState.READY:
            log(f"  MITM: post-ready refetch is in state {state}, not READY; "
                f"first 200B: {(body or b'')[:200]!r}")
            return None, None
        progress_url = final_url

    if state != McAfeeState.READY:
        log(f"  MITM: expected READY state, got {state}")
        return None, None

    # Extract &dl link and fetch
    dl_url = extract_ready_link(body, progress_url)
    if not dl_url:
        log(f"  MITM: READY page has no &dl link; first 200B: {(body or b'')[:200]!r}")
        return None, None
    log.debug(f"  MITM: following download link {dl_url}")

    final_url, status, head, body = _follow_redirects(
        dl_url, upstream_factory, log,
    )
    if status != 200:
        log(f"  MITM: download fetch returned {status}")
        return None, None

    # Sanity: the result should NOT be another MWG page
    final_state = classify_mcafee_response(head, body)
    if final_state != McAfeeState.NOT_MCAFEE:
        log(f"  MITM: download fetch yielded another MWG page (state={final_state})")
        return None, None

    log(f"  MITM: served {len(body or b'')} bytes from MWG download")
    return body, head


def _build_synthesized_response(orig_head, body):
    """
    Build response headers for the body we fetched. Preserve Content-Type
    if upstream gave us one; replace Content-Length to match `body`; remove
    Transfer-Encoding (we have the full body in memory now, no chunking).
    """
    content_type = get_header(orig_head, "Content-Type") or "application/octet-stream"
    head = (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Type: {content_type}\r\n".encode("ascii")
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n"
        + b"X-MITM-Source: auth_proxy-mcafee-progress"
    )
    return head


# ---------------------------------------------------------------------------
# Module-level CA singleton (initialized lazily)
# ---------------------------------------------------------------------------

_ca_singleton = None
_ca_singleton_lock = threading.Lock()


def get_ca():
    global _ca_singleton
    if _ca_singleton is None:
        with _ca_singleton_lock:
            if _ca_singleton is None:
                _ca_singleton = CertAuthority()
    return _ca_singleton