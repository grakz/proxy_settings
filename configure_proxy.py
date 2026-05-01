"""
Detect Windows proxy settings (including WPAD/PAC) and configure Git, npm,
Node.js and pip to use them — including auto-discovery of the corporate
SSL-inspection root CA.

Proxy detection order:
    1. HTTPS_PROXY / HTTP_PROXY environment variables
    2. Windows registry static proxy (ProxyEnable + ProxyServer)
    3. Windows registry AutoConfigURL (PAC file URL set by GPO)
    4. DNS-based WPAD discovery (http://wpad.<domain>/wpad.dat)

PAC files are JavaScript. We evaluate them with Node.js if available; otherwise
we use a small built-in Python evaluator that supports the common PAC helpers.

SSL CA discovery (when the proxy does TLS inspection):
    - Connects to a public HTTPS site through the detected proxy
    - Extracts the certificate chain the proxy presents
    - Identifies the root CA that doesn't match the system trust store
    - Writes a combined PEM bundle (system roots + corporate root)
    - Points Git, npm, Node.js, and pip at it

Usage:
    python configure_proxy.py            # Detect proxy + CA, apply everything
    python configure_proxy.py --dry-run  # Show what would be applied
    python configure_proxy.py --unset    # Remove all settings
    python configure_proxy.py --no-ca    # Skip the CA discovery step
    python configure_proxy.py --pac-url URL  # Force a specific PAC URL
    python configure_proxy.py --probe-url URL  # URL used to query the PAC and probe TLS
"""

import argparse
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlparse, urlunparse


DEFAULT_PROBE_URL = "https://github.com"


# ---------------------------------------------------------------------------
# Static proxy detection (env + registry)
# ---------------------------------------------------------------------------

def detect_from_env():
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        value = os.environ.get(var)
        if value:
            return normalize_proxy_url(value), f"environment variable {var}"
    return None, None


def detect_from_registry_static():
    if sys.platform != "win32":
        return None, None
    try:
        import winreg
    except ImportError:
        return None, None
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            try:
                proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            except FileNotFoundError:
                proxy_enable = 0
            if not proxy_enable:
                return None, None
            try:
                proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except FileNotFoundError:
                return None, None
            if not proxy_server:
                return None, None
            return parse_registry_proxy(proxy_server), "Windows registry (static proxy)"
    except OSError:
        return None, None


def parse_registry_proxy(proxy_server):
    if "=" not in proxy_server:
        return normalize_proxy_url(proxy_server)
    parts = {}
    for chunk in proxy_server.split(";"):
        if "=" in chunk:
            scheme, addr = chunk.split("=", 1)
            parts[scheme.strip().lower()] = addr.strip()
    for scheme in ("https", "http"):
        if scheme in parts:
            return normalize_proxy_url(parts[scheme])
    if parts:
        return normalize_proxy_url(next(iter(parts.values())))
    return None


def normalize_proxy_url(value):
    value = value.strip()
    if not value:
        return None
    if "://" not in value:
        value = "http://" + value
    return value


# ---------------------------------------------------------------------------
# PAC URL discovery
# ---------------------------------------------------------------------------

def get_autoconfig_url_from_registry():
    """Read AutoConfigURL from the registry (set by Internet Options or GPO)."""
    if sys.platform != "win32":
        return None
    try:
        import winreg
    except ImportError:
        return None
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            try:
                value, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                if value:
                    return value.strip()
            except FileNotFoundError:
                return None
    except OSError:
        return None
    return None


def get_dns_search_domains():
    """
    DNS suffixes to try for WPAD discovery, walked from most specific to parent
    (e.g. eu.corp.example.com -> corp.example.com -> example.com).
    """
    domains = []

    try:
        fqdn = socket.getfqdn()
        host = socket.gethostname()
        if fqdn and fqdn != host and "." in fqdn:
            suffix = fqdn.split(".", 1)[1]
            if suffix:
                domains.append(suffix)
    except OSError:
        pass

    if sys.platform == "win32":
        try:
            out = subprocess.run(
                ["ipconfig", "/all"], capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines():
                m = re.search(r"(?:DNS Suffix[^:]*|Connection-specific DNS Suffix)[^:]*:\s*(\S+)", line)
                if m:
                    suffix = m.group(1).strip()
                    if suffix and suffix not in domains:
                        domains.append(suffix)
        except (OSError, subprocess.SubprocessError):
            pass

    expanded = []
    for d in domains:
        parts = d.split(".")
        for i in range(len(parts) - 1):  # stop before TLD
            sub = ".".join(parts[i:])
            if sub and sub not in expanded:
                expanded.append(sub)
    return expanded


def discover_wpad_url(verbose=False):
    """Try DNS-based WPAD: http://wpad.<domain>/wpad.dat for each search domain."""
    for domain in get_dns_search_domains():
        host = f"wpad.{domain}"
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            if verbose:
                print(f"  wpad lookup: {host} not found")
            continue
        url = f"http://{host}/wpad.dat"
        if verbose:
            print(f"  wpad lookup: {host} resolves, trying {url}")
        return url
    return None


def find_pac_url(verbose=False):
    url = get_autoconfig_url_from_registry()
    if url:
        return url, "registry AutoConfigURL"
    url = discover_wpad_url(verbose=verbose)
    if url:
        return url, "DNS WPAD"
    return None, None


# ---------------------------------------------------------------------------
# PAC fetching and evaluation
# ---------------------------------------------------------------------------

def fetch_pac(url, timeout=10):
    """Fetch the PAC file. Bypass any ambient proxy."""
    req = urllib.request.Request(url, headers={"User-Agent": "configure_proxy/1.0"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        data = resp.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


NODE_PAC_HELPERS = r"""
const dns = require('dns');
const net = require('net');
const { execSync } = require('child_process');

function dnsResolveSync(host) {
  try {
    if (net.isIP(host)) return host;
    const safe = String(host).replace(/[^a-zA-Z0-9.\-]/g, '');
    const out = execSync(
      `node -e "require('dns').lookup('${safe}', (e,a)=>{if(!e)process.stdout.write(a)})"`,
      { timeout: 3000 }
    ).toString().trim();
    return out || null;
  } catch (e) { return null; }
}

function isPlainHostName(host) { return host.indexOf('.') < 0; }
function dnsDomainIs(host, domain) {
  return host.length >= domain.length &&
         host.substring(host.length - domain.length).toLowerCase() === domain.toLowerCase();
}
function localHostOrDomainIs(host, hostdom) {
  return host === hostdom || hostdom.indexOf(host + '.') === 0;
}
function isResolvable(host) { return !!dnsResolveSync(host); }
function isInNet(host, pattern, mask) {
  const ip = net.isIP(host) ? host : dnsResolveSync(host);
  if (!ip) return false;
  const toLong = (s) => s.split('.').reduce((a, b) => (a << 8) + parseInt(b, 10), 0) >>> 0;
  return (toLong(ip) & toLong(mask)) === (toLong(pattern) & toLong(mask));
}
function dnsResolve(host) { return dnsResolveSync(host); }
function myIpAddress() {
  const ifs = require('os').networkInterfaces();
  for (const name of Object.keys(ifs)) {
    for (const i of ifs[name]) {
      if (i.family === 'IPv4' && !i.internal) return i.address;
    }
  }
  return '127.0.0.1';
}
function dnsDomainLevels(host) { return (host.match(/\./g) || []).length; }
function shExpMatch(str, shexp) {
  const re = '^' + shexp.replace(/[.+^${}()|\[\]\\]/g, '\\$&')
                       .replace(/\*/g, '.*').replace(/\?/g, '.') + '$';
  return new RegExp(re).test(str);
}
function weekdayRange() { return true; }
function dateRange() { return true; }
function timeRange() { return true; }
function alert(msg) { /* no-op */ }
"""


def evaluate_pac_with_node(pac_source, probe_url, probe_host):
    """Run the PAC's FindProxyForURL via Node.js."""
    node = shutil.which("node")
    if not node:
        return None

    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        script_path = f.name
        f.write(NODE_PAC_HELPERS)
        f.write("\n")
        f.write(pac_source)
        f.write("\n")
        f.write(
            "try {\n"
            "  const r = FindProxyForURL(%r, %r);\n"
            "  process.stdout.write(String(r));\n"
            "} catch (e) { process.stderr.write(String(e)); process.exit(2); }\n"
            % (probe_url, probe_host)
        )

    try:
        result = subprocess.run(
            [node, script_path], capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass


def evaluate_pac_in_python(pac_source, probe_url, probe_host):
    """
    Minimal Python PAC evaluator. Extracts FindProxyForURL's body and walks the
    standard `if (cond) return "..."` pattern that nearly all corporate PACs use.
    Supports shExpMatch, dnsDomainIs, isPlainHostName, isInNet, dnsResolve,
    myIpAddress, isResolvable, dnsDomainLevels.
    """
    m = re.search(
        r"function\s+FindProxyForURL\s*\([^)]*\)\s*\{(.*)\}\s*$",
        pac_source, re.DOTALL,
    )
    if not m:
        m = re.search(r"function\s+FindProxyForURL\s*\([^)]*\)\s*\{(.*)\}", pac_source, re.DOTALL)
    if not m:
        return None
    body = m.group(1)

    helpers = _make_pac_helpers(probe_host)
    statements = _extract_pac_statements(body)
    for cond, retval in statements:
        try:
            if cond is None or _eval_pac_condition(cond, probe_url, probe_host, helpers):
                return _interpret_pac_string(retval)
        except Exception:
            continue
    return None


def _make_pac_helpers(host):
    def shExpMatch(s, pattern):
        regex = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
        return re.match(regex, s) is not None

    def dnsDomainIs(h, domain):
        return h.lower().endswith(domain.lower())

    def isPlainHostName(h):
        return "." not in h

    def dnsResolve(h):
        try:
            return socket.gethostbyname(h)
        except socket.gaierror:
            return None

    def isInNet(h, pattern, mask):
        ip = h if _is_ip(h) else dnsResolve(h)
        if not ip:
            return False
        try:
            ip_int = int(ipaddress.IPv4Address(ip))
            pat_int = int(ipaddress.IPv4Address(pattern))
            mask_int = int(ipaddress.IPv4Address(mask))
            return (ip_int & mask_int) == (pat_int & mask_int)
        except (ipaddress.AddressValueError, ValueError):
            return False

    def myIpAddress():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"

    def isResolvable(h):
        return dnsResolve(h) is not None

    def dnsDomainLevels(h):
        return h.count(".")

    return {
        "shExpMatch": shExpMatch,
        "dnsDomainIs": dnsDomainIs,
        "isPlainHostName": isPlainHostName,
        "dnsResolve": dnsResolve,
        "isInNet": isInNet,
        "myIpAddress": myIpAddress,
        "isResolvable": isResolvable,
        "dnsDomainLevels": dnsDomainLevels,
    }


def _is_ip(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def _extract_pac_statements(body):
    """
    Yield (condition_or_None, return_value_string) pairs from a PAC function body.
    Recognizes:
        if (COND) return "X";
        if (COND) { return "X"; }
        return "X";
    """
    statements = []
    i = 0
    n = len(body)
    while i < n:
        while i < n and body[i] in " \t\r\n":
            i += 1
        if i + 1 < n and body[i:i+2] == "//":
            j = body.find("\n", i)
            i = j + 1 if j != -1 else n
            continue
        if i + 1 < n and body[i:i+2] == "/*":
            j = body.find("*/", i + 2)
            i = j + 2 if j != -1 else n
            continue

        if body[i:i+2] == "if" and (i + 2 < n and not body[i+2].isalnum() and body[i+2] != "_"):
            paren_start = body.find("(", i)
            if paren_start == -1:
                break
            paren_end = _match_paren(body, paren_start, "(", ")")
            if paren_end == -1:
                break
            cond = body[paren_start + 1:paren_end].strip()
            k = paren_end + 1
            while k < n and body[k] in " \t\r\n":
                k += 1
            if k < n and body[k] == "{":
                brace_end = _match_paren(body, k, "{", "}")
                if brace_end == -1:
                    break
                inner = body[k + 1:brace_end]
                ret = _find_return(inner)
                if ret is not None:
                    statements.append((cond, ret))
                i = brace_end + 1
                continue
            else:
                ret = _find_return(body[k:])
                if ret is not None:
                    statements.append((cond, ret))
                semi = body.find(";", k)
                i = semi + 1 if semi != -1 else n
                continue

        if body[i:i+6] == "return" and (i + 6 < n and not body[i+6].isalnum()):
            ret = _find_return(body[i:])
            if ret is not None:
                statements.append((None, ret))
            semi = body.find(";", i)
            i = semi + 1 if semi != -1 else n
            continue

        i += 1
    return statements


def _match_paren(s, start, open_ch, close_ch):
    depth = 0
    in_str = None
    i = start
    while i < len(s):
        c = s[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
        else:
            if c in ('"', "'"):
                in_str = c
            elif c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _find_return(s):
    """Find `return <expr>;` and return the raw <expr> string, respecting string literals."""
    m = re.search(r"return\s+", s)
    if not m:
        return None
    i = m.end()
    in_str = None
    while i < len(s):
        c = s[i]
        if in_str:
            if c == "\\" and i + 1 < len(s):
                i += 2
                continue
            if c == in_str:
                in_str = None
        else:
            if c in ('"', "'"):
                in_str = c
            elif c == ";":
                return s[m.end():i].strip()
        i += 1
    return s[m.end():].strip() or None


def _interpret_pac_string(expr):
    """
    Reduce a JS string expression to a Python string. Handles "literal",
    'literal', and concatenations like "PROXY " + "host:port".
    """
    expr = expr.strip()
    m = re.match(r'^"((?:[^"\\]|\\.)*)"$', expr)
    if m:
        return m.group(1)
    m = re.match(r"^'((?:[^'\\]|\\.)*)'$", expr)
    if m:
        return m.group(1)
    if "+" in expr:
        parts = []
        for piece in _split_top_level(expr, "+"):
            sub = _interpret_pac_string(piece.strip())
            if sub is None:
                return expr
            parts.append(sub)
        return "".join(parts)
    return expr


def _split_top_level(s, sep):
    out = []
    depth = 0
    in_str = None
    buf = []
    i = 0
    while i < len(s):
        c = s[i]
        if in_str:
            buf.append(c)
            if c == "\\" and i + 1 < len(s):
                buf.append(s[i+1])
                i += 2
                continue
            if c == in_str:
                in_str = None
        else:
            if c in ('"', "'"):
                in_str = c
                buf.append(c)
            elif c in "([{":
                depth += 1
                buf.append(c)
            elif c in ")]}":
                depth -= 1
                buf.append(c)
            elif c == sep and depth == 0:
                out.append("".join(buf))
                buf = []
            else:
                buf.append(c)
        i += 1
    out.append("".join(buf))
    return out


def _eval_pac_condition(cond, url, host, helpers):
    """
    Evaluate a PAC condition by translating JS-ish syntax to Python and exec'ing
    in a tightly restricted namespace. We refuse anything outside the safe subset.
    """
    if any(tok in cond for tok in ("=>", "function", "process", "require", "import", "while", "for(", "__")):
        raise ValueError("unsupported PAC construct")

    py = cond
    py = re.sub(r"\|\|", " or ", py)
    py = re.sub(r"&&", " and ", py)
    py = re.sub(r"!\s*([a-zA-Z_(])", r"not \1", py)
    py = py.replace("true", "True").replace("false", "False").replace("null", "None")

    safe_globals = {"__builtins__": {}}
    safe_locals = dict(helpers)
    safe_locals["url"] = url
    safe_locals["host"] = host

    return bool(eval(py, safe_globals, safe_locals))  # noqa: S307


# ---------------------------------------------------------------------------
# PAC return-value parsing
# ---------------------------------------------------------------------------

def parse_pac_result(result):
    """
    A PAC result looks like 'PROXY host:port; PROXY host2:port2; DIRECT'.
    Pick the first PROXY entry. If only DIRECT, return ('direct', None).
    """
    if not result:
        return None, None
    entries = [e.strip() for e in result.split(";") if e.strip()]
    for entry in entries:
        parts = entry.split(None, 1)
        if not parts:
            continue
        kind = parts[0].upper()
        if kind in ("PROXY", "HTTP"):
            if len(parts) == 2:
                return "proxy", normalize_proxy_url(parts[1].strip())
        elif kind == "HTTPS":
            if len(parts) == 2:
                return "proxy", normalize_proxy_url("https://" + parts[1].strip())
        elif kind == "DIRECT":
            return "direct", None
        elif kind in ("SOCKS", "SOCKS4", "SOCKS5"):
            if len(parts) == 2:
                scheme = "socks5" if kind == "SOCKS5" else "socks4"
                return "proxy", f"{scheme}://{parts[1].strip()}"
    return None, None


# ---------------------------------------------------------------------------
# SSL inspection / corporate root CA discovery
# ---------------------------------------------------------------------------
#
# When a corporate proxy does TLS inspection ("MITM"), it terminates the TLS
# connection itself and re-encrypts traffic to the client using a certificate
# signed by a corporate root CA that's been pushed to the OS trust store.
#
# Tools that don't read the OS store (Git for Windows ships its own CA bundle,
# Node.js bundles its own, pip uses certifi) will fail with cert errors. Our
# job: connect through the proxy to a public HTTPS site, capture the chain
# the proxy presents, find the root that's NOT in a stock CA bundle, and
# build a combined PEM bundle for those tools.

class ProxyAuthRequiredError(OSError):
    """Raised when the proxy returns 407 (NTLM/Negotiate/Basic auth required)."""
    def __init__(self, schemes):
        self.schemes = schemes
        super().__init__(f"proxy requires authentication ({', '.join(schemes) or 'unknown scheme'})")


def _proxy_tunnel_socket(proxy_url, target_host, target_port, timeout=10):
    """
    Open a raw TCP socket to target_host:target_port through an HTTP proxy
    using the CONNECT method. Returns the connected socket (no TLS yet).
    Raises ProxyAuthRequiredError on 407.
    """
    parsed = urlparse(proxy_url)
    proxy_host = parsed.hostname
    proxy_port = parsed.port or (443 if parsed.scheme == "https" else 8080)

    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        connect_req = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
        )
        if parsed.username and parsed.password:
            import base64
            creds = f"{parsed.username}:{parsed.password}"
            token = base64.b64encode(creds.encode()).decode()
            connect_req += f"Proxy-Authorization: Basic {token}\r\n"
        connect_req += "\r\n"
        sock.sendall(connect_req.encode("ascii"))

        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 16384:
                break

        status_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        if " 407 " in status_line:
            # Parse the offered auth schemes for diagnostics
            schemes = []
            for line in response.split(b"\r\n"):
                if line.lower().startswith(b"proxy-authenticate:"):
                    val = line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
                    schemes.append(val.split()[0] if val else "")
            raise ProxyAuthRequiredError(schemes)
        if " 200 " not in status_line:
            raise OSError(f"proxy CONNECT failed: {status_line}")
        return sock
    except Exception:
        sock.close()
        raise


def fetch_proxy_cert_chain(proxy_url, target_host, target_port=443, timeout=10):
    """
    Connect through `proxy_url` to target_host:target_port using TLS, with
    verification disabled, and return the cert chain the server presents as
    a list of DER-encoded bytes (leaf first).

    Tries three strategies in order:
      1. Python's get_unverified_chain() (3.13+) — full chain
      2. openssl s_client -showcerts through the proxy — full chain
      3. Python getpeercert() — leaf only (last resort)
    """
    import ssl as _ssl

    # Strategy 1: Python's get_unverified_chain (3.13+); also grab the leaf
    # as a fallback for strategy 3.
    leaf_only = []
    sock = _proxy_tunnel_socket(proxy_url, target_host, target_port, timeout=timeout)
    try:
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=target_host) as tls:
            try:
                unverified = tls.get_unverified_chain()
                chain = [c.public_bytes() for c in unverified]
                if chain:
                    return chain
            except AttributeError:
                pass  # Python < 3.13 — fall through
            leaf = tls.getpeercert(binary_form=True)
            if leaf:
                leaf_only = [leaf]
    finally:
        try:
            sock.close()
        except OSError:
            pass

    # Strategy 2: openssl s_client through the proxy — typically gives full chain
    openssl_chain = _fetch_chain_via_openssl(proxy_url, target_host, target_port, timeout)
    if openssl_chain:
        return openssl_chain

    # Strategy 3: leaf-only — better than nothing, but won't include the root
    return leaf_only


def _fetch_chain_via_openssl(proxy_url, target_host, target_port, timeout):
    """Use `openssl s_client -showcerts -proxy host:port` to capture the full chain."""
    openssl = shutil.which("openssl")
    if not openssl:
        return []

    parsed = urlparse(proxy_url)
    proxy_host = parsed.hostname
    proxy_port = parsed.port or 8080
    if not proxy_host:
        return []

    # -proxy was added in OpenSSL 1.1.0 and is widely available
    cmd = [
        openssl, "s_client",
        "-connect", f"{target_host}:{target_port}",
        "-proxy", f"{proxy_host}:{proxy_port}",
        "-servername", target_host,
        "-showcerts",
    ]
    try:
        result = subprocess.run(
            cmd, input=b"Q\n", capture_output=True, timeout=timeout + 5,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    output = result.stdout.decode("utf-8", errors="replace")
    chain_pems = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        output, re.DOTALL,
    )
    chain_der = []
    import base64
    for pem in chain_pems:
        body = re.sub(r"-----(BEGIN|END) CERTIFICATE-----", "", pem).strip()
        try:
            chain_der.append(base64.b64decode("".join(body.split())))
        except (ValueError, Exception):
            continue
    return chain_der


def _der_to_pem(der_bytes):
    import base64
    b64 = base64.encodebytes(der_bytes).decode("ascii").strip()
    return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n"


def _cert_subject_issuer(der_bytes):
    """
    Get (subject_cn, issuer_cn, is_self_signed) from a DER cert without
    pulling in cryptography. We use ssl._ssl or just a minimal parse via
    the stdlib by writing the cert to a temp file and using ssl.PEM_cert_to_DER
    inversely. The cleanest stdlib way: use ssl._ssl.txt2obj? Too internal.
    We use a subprocess to `openssl` if available, else fall back to a crude
    DER walk for just the subject CN.
    """
    # Try cryptography if installed (it usually is on dev machines)
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        def cn(name):
            try:
                return name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            except (IndexError, AttributeError):
                return name.rfc4514_string()
        subject = cn(cert.subject)
        issuer = cn(cert.issuer)
        return subject, issuer, cert.subject == cert.issuer
    except ImportError:
        pass

    # Fall back to openssl CLI
    openssl = shutil.which("openssl")
    if openssl:
        try:
            r = subprocess.run(
                [openssl, "x509", "-inform", "DER", "-noout", "-subject", "-issuer"],
                input=der_bytes, capture_output=True, timeout=5,
            )
            if r.returncode == 0:
                out = r.stdout.decode("utf-8", errors="replace")
                subj = re.search(r"subject=.*?CN\s*=\s*([^\n,/]+)", out)
                iss = re.search(r"issuer=.*?CN\s*=\s*([^\n,/]+)", out)
                # Compare the full subject/issuer DNs to detect self-signed
                subj_full = re.search(r"subject=(.*)", out)
                iss_full = re.search(r"issuer=(.*)", out)
                self_signed = (subj_full and iss_full and
                               subj_full.group(1).strip() == iss_full.group(1).strip())
                return (
                    subj.group(1).strip() if subj else "(unknown)",
                    iss.group(1).strip() if iss else "(unknown)",
                    self_signed,
                )
        except (OSError, subprocess.SubprocessError):
            pass

    return "(unknown)", "(unknown)", False


def _certifi_ca_set():
    """
    Return DER bytes of certs in certifi's bundle. This is the trust store
    that pip uses, that Git for Windows often ships a copy of, and that
    Node.js's bundled trust mirrors closely. A cert from the proxy's chain
    that's NOT in this set is one our tools won't trust by default.
    """
    bundle = set()
    try:
        import certifi
        with open(certifi.where(), "rb") as f:
            bundle.update(_split_pem_to_der(f.read()))
    except (ImportError, OSError):
        # Fall back to OpenSSL's default trust if certifi isn't installed
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        try:
            for cert in ctx.get_ca_certs(binary_form=True):
                bundle.add(cert)
        except (AttributeError, _ssl.SSLError):
            pass
    return bundle


def _system_ca_set():
    """
    Return DER bytes of all CA certs from the OS trust store (Windows ROOT/CA
    stores on Windows). This is broader than certifi and reflects what the OS
    itself trusts — useful for diagnostics but NOT for deciding what to add
    to our bundle (use _certifi_ca_set for that).
    """
    import ssl as _ssl

    bundle = set()
    if sys.platform == "win32":
        try:
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_default_certs(_ssl.Purpose.SERVER_AUTH)
            for cert in ctx.get_ca_certs(binary_form=True):
                bundle.add(cert)
            for store in ("ROOT", "CA"):
                try:
                    for cert_der, encoding, trust in _ssl.enum_certificates(store):
                        if encoding == "x509_asn":
                            bundle.add(cert_der)
                except (OSError, AttributeError):
                    pass
        except (ImportError, OSError):
            pass
    else:
        try:
            ctx = _ssl.create_default_context()
            for cert in ctx.get_ca_certs(binary_form=True):
                bundle.add(cert)
        except (AttributeError, _ssl.SSLError):
            pass
    return bundle


def _split_pem_to_der(pem_bytes):
    """Split a PEM bundle into individual DER blobs."""
    import base64
    out = []
    text = pem_bytes.decode("ascii", errors="replace")
    for m in re.finditer(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        text, re.DOTALL,
    ):
        try:
            out.append(base64.b64decode("".join(m.group(1).split())))
        except (ValueError, Exception):
            continue
    return out


def _load_certs_from_file(path):
    """
    Load certs from a file at `path`. Accepts PEM (one or more certs) or
    a single DER cert. Returns (subject, issuer, der, is_self_signed) tuples.
    """
    with open(path, "rb") as f:
        data = f.read()

    if not data:
        return []

    ders = []
    if b"BEGIN CERTIFICATE" in data:
        ders = _split_pem_to_der(data)
    else:
        # Assume DER. A valid DER cert starts with 0x30 (SEQUENCE).
        if data[:1] == b"\x30":
            ders = [data]
        else:
            raise ValueError("file is neither PEM nor DER")

    out = []
    for der in ders:
        subj, iss, ss = _cert_subject_issuer(der)
        out.append((subj, iss, der, ss))
    return out


def discover_corporate_ca_from_windows_store(verbose=False):
    """
    Find corporate CA candidates by diffing the Windows ROOT trust store
    against certifi's bundle. The corporate root is pushed into the Windows
    store by group policy on managed machines, and is typically NOT in
    certifi (since it's not a public WebPKI root).

    This is the fastest and most reliable detection path — no proxy traffic,
    no auth, no TLS handshake — and works on any locked-down corporate machine.

    Returns the same shape as discover_corporate_ca: list of
    (subject, issuer, der, is_self_signed) tuples.
    """
    if sys.platform != "win32":
        return []

    import ssl as _ssl

    windows_roots = []
    try:
        for store in ("ROOT",):
            try:
                for cert_der, encoding, trust in _ssl.enum_certificates(store):
                    if encoding == "x509_asn":
                        windows_roots.append(cert_der)
            except (OSError, AttributeError):
                continue
    except Exception:
        return []

    certifi_certs = _certifi_ca_set()
    if verbose:
        print(f"  Windows ROOT store: {len(windows_roots)} certs")
        print(f"  certifi bundle: {len(certifi_certs)} certs")

    candidates = []
    for der in windows_roots:
        if der in certifi_certs:
            continue
        subj, iss, self_signed = _cert_subject_issuer(der)
        # Skip entries that are clearly Microsoft / OS roots (these are in the
        # Windows store but legitimately not in certifi — e.g. Microsoft Code
        # Verification Root, Microsoft Authenticode, etc.). We're conservative
        # here to avoid bundling Microsoft-internal roots that pip doesn't need.
        if _is_microsoft_root(subj, iss):
            if verbose:
                print(f"    [skip-ms]  {subj!r}")
            continue
        if not self_signed:
            # Roots should be self-signed; skip anything that isn't (probably
            # an intermediate that ended up in the ROOT store by mistake).
            if verbose:
                print(f"    [skip-int] {subj!r} (not self-signed)")
            continue
        if verbose:
            print(f"    [CANDIDATE] {subj!r}")
        candidates.append((subj, iss, der, True))

    return candidates


def _is_microsoft_root(subject, issuer):
    """Heuristic: identify Microsoft-issued OS roots that we shouldn't bundle."""
    s = (subject or "").lower()
    return any(tag in s for tag in (
        "microsoft root",
        "microsoft authenticode",
        "microsoft code",
        "microsoft ecc",
        "microsoft rsa",
        "microsoft time-stamp",
        "microsoft identity",
    ))


# Names of known SSL-inspection vendors and generic markers that strongly
# suggest a cert is the corporate inspection CA.
_INSPECTION_HINTS = (
    "ssl inspection", "tls inspection", "deep inspection", "deep packet",
    "decrypt", "decryption", "mitm", "intercept", "proxy ca",
    "zscaler", "bluecoat", "blue coat", "netskope", "forcepoint",
    "palo alto", "paloalto", "fortinet", "fortigate", "checkpoint",
    "check point", "websense", "ironport", "mcafee web", "symantec web",
    "trendmicro", "trend micro", "sonicwall", "barracuda",
    "umbrella", "cisco web", "cloud proxy", "secure web gateway",
    "swg", "explicit proxy",
)


def _score_inspection_likelihood(subject, issuer, der):
    """
    Score how likely this cert is to be the SSL-inspection CA.
    Higher = more likely. Used to rank candidates when there are many.
    """
    score = 0
    s = (subject or "").lower()
    i = (issuer or "").lower()
    text = s + " " + i
    for hint in _INSPECTION_HINTS:
        if hint in text:
            score += 50
            break
    # "ca" or "root" in the name is mildly positive (it's a CA cert, but
    # specifically one named so) — most legit roots have it
    if "root ca" in s or "issuing ca" in s:
        score += 2
    # Recent NotBefore (last ~5 years) is a weak signal — corporate roots
    # tend to be regenerated more frequently than public CAs
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(der, default_backend())
        from datetime import datetime, timezone
        try:
            nb = cert.not_valid_before_utc
            now = datetime.now(timezone.utc)
        except AttributeError:
            nb = cert.not_valid_before
            now = datetime.utcnow()
        age_years = (now - nb).days / 365.0
        if age_years < 5:
            score += 5
        elif age_years > 15:
            score -= 5  # ancient public roots are unlikely to be inspection CAs
    except Exception:
        pass
    return score


def _cert_authority_key_id(der):
    """Return the Authority Key Identifier (AKI) bytes, or None."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import ExtensionOID
        cert = x509.load_der_x509_certificate(der, default_backend())
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            return ext.value.key_identifier
        except x509.ExtensionNotFound:
            return None
    except Exception:
        return None


def _cert_subject_key_id(der):
    """Return the Subject Key Identifier (SKI) bytes, or None."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import ExtensionOID
        cert = x509.load_der_x509_certificate(der, default_backend())
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            return ext.value.digest
        except x509.ExtensionNotFound:
            return None
    except Exception:
        return None


def identify_signing_root(candidates, proxy_url, probe_url, verbose=False):
    """
    Try to determine which of `candidates` is the actual TLS-inspection CA
    by probing a public site through the proxy and finding the cert in
    candidates that issued the leaf.

    Strategy:
      1. Capture the leaf cert presented for `probe_url` through `proxy_url`.
         (May fail with auth errors — caller catches.)
      2. Read the leaf's Authority Key Identifier (AKI).
      3. Find the candidate whose Subject Key Identifier (SKI) matches.
      4. If AKI/SKI not available, match by issuer DN to subject DN.

    Returns the matching candidate tuple or None.
    """
    parsed = urlparse(probe_url)
    target_host = parsed.hostname
    target_port = parsed.port or 443
    if not target_host:
        return None

    try:
        chain = fetch_proxy_cert_chain(proxy_url, target_host, target_port)
    except (ProxyAuthRequiredError, OSError) as e:
        if verbose:
            print(f"  TLS probe failed ({e}); cannot definitively identify the inspection CA")
        return None

    if not chain:
        return None

    leaf_der = chain[0]

    # First attempt: AKI/SKI match (most reliable)
    leaf_aki = _cert_authority_key_id(leaf_der)
    if leaf_aki:
        if verbose:
            print(f"  leaf AKI: {leaf_aki.hex()[:32]}...")
        for cand in candidates:
            ski = _cert_subject_key_id(cand[2])
            if ski and ski == leaf_aki:
                if verbose:
                    print(f"  matched by AKI/SKI: {cand[0]!r}")
                return cand

    # Second attempt: any cert in the chain that's also in our candidates
    # (covers the case where the proxy includes the root in the chain)
    chain_set = set(chain)
    for cand in candidates:
        if cand[2] in chain_set:
            if verbose:
                print(f"  matched by chain inclusion: {cand[0]!r}")
            return cand

    # Third attempt: name match between leaf's issuer and candidate's subject
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        leaf = x509.load_der_x509_certificate(leaf_der, default_backend())
        leaf_issuer_dn = leaf.issuer.rfc4514_string()
        for cand in candidates:
            try:
                cand_cert = x509.load_der_x509_certificate(cand[2], default_backend())
                if cand_cert.subject.rfc4514_string() == leaf_issuer_dn:
                    if verbose:
                        print(f"  matched by issuer DN: {cand[0]!r}")
                    return cand
            except Exception:
                continue
    except ImportError:
        pass

    return None


def prompt_for_cert_choice(candidates, recommended=None):
    """
    Show the user a numbered list of candidates and let them pick.
    `recommended` is the auto-detected one (will be marked with a ★).
    Returns the chosen list (one element) or candidates (if user picks 'all'),
    or [] if cancelled.
    """
    if not candidates:
        return []
    if not sys.stdin.isatty():
        # Non-interactive: take the recommended one if known, else the first
        if recommended:
            return [recommended]
        return [candidates[0]]

    print("\nMultiple corporate CA candidates found in the Windows trust store.")
    print("Pick the one to install (or 'a' for all, 'q' to cancel):\n")
    for n, cand in enumerate(candidates, 1):
        subj, iss, der, _ = cand
        marker = " ★" if cand is recommended else "  "
        print(f"  {marker}{n:2d}. {subj}")
        if subj != iss:
            print(f"       issued by: {iss}")

    if recommended:
        rec_idx = candidates.index(recommended) + 1
        prompt = f"\nChoice [1-{len(candidates)}, default {rec_idx}, 'a' for all, 'q' to cancel]: "
    else:
        prompt = f"\nChoice [1-{len(candidates)}, 'a' for all, 'q' to cancel]: "

    while True:
        try:
            answer = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return []
        if not answer and recommended:
            return [recommended]
        if answer in ("q", "quit", "cancel"):
            return []
        if answer in ("a", "all"):
            return list(candidates)
        try:
            idx = int(answer)
            if 1 <= idx <= len(candidates):
                return [candidates[idx - 1]]
        except ValueError:
            pass
        print(f"  please enter 1-{len(candidates)}, 'a', or 'q'")


def select_corporate_ca(candidates, proxy_url, probe_url, verbose=False, interactive=True):
    """
    Reduce a list of candidate CAs to the one (or few) the user actually wants.
    Tries TLS probe identification first, then ranking + interactive prompt.
    """
    if not candidates:
        return []
    if len(candidates) == 1:
        return candidates

    # Try definitive identification via TLS probe
    print(f"\n  multiple candidates ({len(candidates)}); attempting to identify the active inspection CA...")
    matched = identify_signing_root(candidates, proxy_url, probe_url, verbose=verbose)
    if matched:
        print(f"  ✓ confirmed by TLS probe: {matched[0]!r}")
        return [matched]

    # Fall back to scoring + prompting
    scored = sorted(
        candidates,
        key=lambda c: _score_inspection_likelihood(c[0], c[1], c[2]),
        reverse=True,
    )
    top_score = _score_inspection_likelihood(scored[0][0], scored[0][1], scored[0][2])
    runner_up = _score_inspection_likelihood(scored[1][0], scored[1][1], scored[1][2])

    # If the top candidate has a much higher score than the next, take it
    if top_score >= 50 and top_score - runner_up >= 30:
        print(f"  ✓ ranked best by name heuristics: {scored[0][0]!r}")
        return [scored[0]]

    if not interactive:
        print(f"  could not definitively identify; defaulting to top-ranked: {scored[0][0]!r}")
        return [scored[0]]

    chosen = prompt_for_cert_choice(scored, recommended=scored[0])
    return chosen


def discover_corporate_ca(proxy_url, probe_url, verbose=False):
    """
    Connect to probe_url through proxy_url, capture the cert chain, and
    identify certs that aren't in certifi's bundle (the narrowest trust
    store our target tools consult).

    Returns a list of (subject, issuer, der_bytes, is_self_signed) tuples,
    preferring self-signed roots. Empty list means no TLS inspection or
    nothing new to install.
    """
    parsed = urlparse(probe_url)
    target_host = parsed.hostname
    target_port = parsed.port or 443
    if not target_host:
        return []

    if verbose:
        print(f"  probing {target_host}:{target_port} through {redact(proxy_url)} ...")

    try:
        chain = fetch_proxy_cert_chain(proxy_url, target_host, target_port)
    except OSError as e:
        print(f"  could not capture cert chain: {e}")
        return []

    if not chain:
        print("  proxy returned no certs")
        return []

    if verbose:
        print(f"  proxy presented {len(chain)} cert(s) in the chain")

    certifi_certs = _certifi_ca_set()
    windows_certs = _system_ca_set() if sys.platform == "win32" else set()

    if verbose:
        print(f"  certifi trust store: {len(certifi_certs)} certs")
        if windows_certs:
            print(f"  Windows trust store: {len(windows_certs)} certs")

    novel = []
    for der in chain:
        subj, iss, self_signed = _cert_subject_issuer(der)
        in_certifi = der in certifi_certs
        in_windows = der in windows_certs
        if verbose:
            tags = []
            tags.append("certifi" if in_certifi else "NOT-in-certifi")
            if windows_certs:
                tags.append("windows" if in_windows else "NOT-in-windows")
            kind = "self-signed root" if self_signed else "intermediate/leaf"
            print(f"    [{','.join(tags)}] {kind}: subject={subj!r}")
        # We need to add it to our bundle iff certifi doesn't have it AND it's
        # a CA (self-signed or intermediate). Skip leaf certs.
        if not in_certifi and (self_signed or _looks_like_ca(der)):
            novel.append((subj, iss, der, self_signed))

    # Prefer self-signed roots; fall back to whatever's novel
    roots = [n for n in novel if n[3]]
    return roots if roots else novel


def _looks_like_ca(der_bytes):
    """Best-effort detection of CA certs (BasicConstraints CA:TRUE)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import ExtensionOID
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            return bool(ext.value.ca)
        except x509.ExtensionNotFound:
            return False
    except ImportError:
        # Without cryptography, conservatively treat non-self-signed certs as non-CA.
        # This prevents leaf certs from polluting the bundle but means we may miss
        # an intermediate. Since the corporate root is what matters, this is OK.
        return False
    except Exception:
        return False


def write_ca_bundle(corporate_certs, output_path):
    """
    Write a combined PEM bundle: certifi/system roots + corporate certs.
    Returns the actual path written (may differ from output_path if it
    was a directory or had to fall back).
    """
    # Resolve where to actually write. If output_path looks like a directory
    # (exists as one, or has no extension and the parent doesn't exist as a
    # file), append the default filename.
    output_path = os.path.abspath(output_path)
    if os.path.isdir(output_path):
        output_path = os.path.join(output_path, "ca-bundle.pem")
    elif not os.path.splitext(output_path)[1] and not os.path.exists(output_path):
        # No file extension and doesn't exist — treat as a directory the user
        # wants us to create
        output_path = os.path.join(output_path, "ca-bundle.pem")

    pieces = []

    # Start with certifi if available (most portable baseline)
    try:
        import certifi
        with open(certifi.where(), "rb") as f:
            pieces.append(f.read().decode("ascii", errors="replace"))
    except (ImportError, OSError):
        # Fallback: load_default_certs + enum_certificates on Windows
        import ssl as _ssl
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        try:
            ctx.load_default_certs(_ssl.Purpose.SERVER_AUTH)
            for cert in ctx.get_ca_certs(binary_form=True):
                pieces.append(_der_to_pem(cert))
        except (OSError, AttributeError):
            pass

    pieces.append("\n# ---- Corporate SSL inspection certificates ----\n")
    for subj, iss, der, self_signed in corporate_certs:
        pieces.append(f"# Subject: {subj}\n# Issuer: {iss}\n")
        pieces.append(_der_to_pem(der))

    # Append the auth_proxy MITM CA if it exists. This is the CA used by
    # auth_proxy.py when running with --mitm; without it in the bundle,
    # tools won't trust the intercepted TLS connections.
    auth_proxy_ca = os.path.join(
        os.path.expanduser("~"), ".config", "configure_proxy", "auth_proxy_ca.pem"
    )
    if os.path.exists(auth_proxy_ca):
        try:
            with open(auth_proxy_ca, encoding="utf-8") as f:
                pieces.append("\n# ---- auth_proxy MITM CA ----\n")
                pieces.append(f.read())
        except OSError:
            pass

    bundle = "".join(pieces)
    # Encode with explicit LF line endings (binary write below) so the file
    # has consistent endings regardless of platform. This matters because
    # other code may bytes-compare against this file later, and Windows
    # text-mode writes would produce CRLF where the source PEMs have LF.
    bundle_bytes = bundle.replace("\r\n", "\n").encode("ascii")

    # Make sure the parent dir exists; if creation fails (permissions),
    # fall back to a writable user dir.
    target_dir = os.path.dirname(output_path)
    try:
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(bundle_bytes)
        return output_path
    except (OSError, PermissionError) as e:
        fallback = os.path.join(
            os.path.expanduser("~"), ".config", "configure_proxy", "ca-bundle.pem"
        )
        if os.path.abspath(fallback) == os.path.abspath(output_path):
            raise  # already trying the fallback, don't loop
        print(f"  could not write to {output_path}: {e}")
        print(f"  falling back to {fallback}")
        os.makedirs(os.path.dirname(fallback), exist_ok=True)
        with open(fallback, "wb") as f:
            f.write(bundle_bytes)
        return fallback


def ensure_mitm_ca_in_bundle(bundle_path):
    """
    Idempotently append the auth_proxy MITM CA to an existing bundle.
    Does nothing (and logs nothing) if:
      - the MITM CA file does not exist (user isn't using MITM)
      - the bundle file does not exist (configure_ca_for_tools wasn't run yet
        for the corp-cert path, so there's no bundle to amend)
      - the MITM CA's PEM body is already present in the bundle (matched
        modulo line endings — important on Windows where CRLF/LF can differ
        between the bundle and the PEM source)

    Otherwise appends and reports.
    """
    auth_proxy_ca = os.path.join(
        os.path.expanduser("~"), ".config", "configure_proxy", "auth_proxy_ca.pem"
    )
    if not os.path.exists(auth_proxy_ca):
        # Nothing to do — user hasn't generated an MITM CA yet.
        return

    # Resolve bundle_path the same way write_ca_bundle does (it might be a
    # directory the user wanted us to create).
    bundle_path = os.path.abspath(bundle_path)
    if os.path.isdir(bundle_path):
        bundle_path = os.path.join(bundle_path, "ca-bundle.pem")

    if not os.path.exists(bundle_path):
        print(f"\n[MITM CA] bundle {bundle_path} does not exist yet; "
              f"nothing to amend. Detect a corporate CA first or pass "
              f"--ca-import to create the bundle.")
        return

    def _normalize_eol(b):
        return b.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

    # Read both files as bytes and compare with normalized line endings.
    # This matters on Windows where the bundle may have CRLF (text-mode
    # writes) and the PEM source may have LF, so a naive substring search
    # would miss the match.
    try:
        ca_pem_bytes = open(auth_proxy_ca, "rb").read()
    except OSError as e:
        print(f"\n[MITM CA] could not read MITM CA at {auth_proxy_ca}: {e}")
        return
    ca_pem_norm = _normalize_eol(ca_pem_bytes).strip()

    try:
        bundle_bytes = open(bundle_path, "rb").read()
    except OSError as e:
        print(f"\n[MITM CA] could not read bundle at {bundle_path}: {e}")
        return
    bundle_norm = _normalize_eol(bundle_bytes)

    if ca_pem_norm in bundle_norm:
        print(f"\n[MITM CA] already present in {bundle_path}")
        return

    # Build the new content as bytes with LF line endings, then write in
    # binary mode so Windows doesn't translate them. This produces a bundle
    # with consistent LF endings throughout the appended section, which is
    # what every TLS library on every platform handles correctly.
    appended = bundle_norm
    if not appended.endswith(b"\n"):
        appended += b"\n"
    appended += b"\n# ---- auth_proxy MITM CA ----\n"
    appended += ca_pem_norm
    if not appended.endswith(b"\n"):
        appended += b"\n"

    try:
        with open(bundle_path, "wb") as f:
            f.write(appended)
        print(f"\n[MITM CA] appended to {bundle_path}")
        print(f"          restart any pnpm/node/npm processes for the change to take effect")
    except (OSError, PermissionError) as e:
        print(f"\n[MITM CA] could not write {bundle_path}: {e}")


def configure_ca_for_tools(bundle_path, dry_run=False):
    """Point Git, npm, Node, and pip at our combined CA bundle."""
    print(f"\n[CA bundle] {bundle_path}")

    # Git
    if tool_available("git"):
        run(["git", "config", "--global", "http.sslCAInfo", bundle_path], dry_run)
    else:
        print("  git not on PATH; skipping http.sslCAInfo")

    # npm
    if tool_available("npm"):
        npm = shutil.which("npm")
        run([npm, "config", "set", "cafile", bundle_path], dry_run)
    else:
        print("  npm not on PATH; skipping cafile")

    # pip — write to user-level pip.conf / pip.ini
    pip_config_path = _pip_config_path()
    if dry_run:
        print(f"  [dry-run] would set [global] cert = {bundle_path} in {pip_config_path}")
    else:
        _set_pip_cert(pip_config_path, bundle_path)
        print(f"  pip config: {pip_config_path}")

    # Node.js — needs an env var. We can only print instructions for the
    # user shell, since setting it in the current process is useless and
    # setx persistence requires its own opt-in.
    print("  Node.js: set NODE_EXTRA_CA_CERTS for it to take effect")
    if sys.platform == "win32" and not dry_run:
        if shutil.which("setx"):
            run(["setx", "NODE_EXTRA_CA_CERTS", bundle_path], dry_run)
            print("    (setx persists for new shells; restart your terminal)")
    else:
        print(f"    export NODE_EXTRA_CA_CERTS={bundle_path}")


def _pip_config_path():
    """Per-user pip config location."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
        return os.path.join(appdata, "pip", "pip.ini")
    return os.path.join(os.path.expanduser("~"), ".config", "pip", "pip.conf")


def _set_pip_cert(config_path, cert_path):
    import configparser
    cfg = configparser.ConfigParser()
    if os.path.exists(config_path):
        cfg.read(config_path)
    if "global" not in cfg:
        cfg["global"] = {}
    cfg["global"]["cert"] = cert_path
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        cfg.write(f)


def unset_ca_for_tools(dry_run=False):
    print("\n[CA bundle] removing CA settings")
    if tool_available("git"):
        cmd = ["git", "config", "--global", "--unset", "http.sslCAInfo"]
        if dry_run:
            print(f"  [dry-run] {' '.join(cmd)}")
        else:
            print(f"  $ {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True)
    if tool_available("npm"):
        npm = shutil.which("npm")
        cmd = [npm, "config", "delete", "cafile"]
        if dry_run:
            print(f"  [dry-run] {' '.join(cmd)}")
        else:
            print(f"  $ {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True)
    pip_config_path = _pip_config_path()
    if os.path.exists(pip_config_path) and not dry_run:
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(pip_config_path)
        if "global" in cfg and "cert" in cfg["global"]:
            del cfg["global"]["cert"]
            with open(pip_config_path, "w", encoding="utf-8") as f:
                cfg.write(f)
            print(f"  removed cert from {pip_config_path}")




def tool_available(name):
    return shutil.which(name) is not None


def run(cmd, dry_run=False):
    printable = " ".join(cmd)
    if dry_run:
        print(f"  [dry-run] {printable}")
        return True
    print(f"  $ {printable}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, shell=False)
        if result.returncode != 0:
            print(f"    ERROR: {result.stderr.strip()}")
            return False
        if result.stdout.strip():
            print(f"    {result.stdout.strip()}")
        return True
    except FileNotFoundError:
        print(f"    ERROR: command not found: {cmd[0]}")
        return False


def configure_git(proxy_url, no_proxy, dry_run=False):
    print("\n[Git]")
    if not tool_available("git"):
        print("  git not found on PATH; skipping.")
        return
    run(["git", "config", "--global", "http.proxy", proxy_url], dry_run)
    run(["git", "config", "--global", "https.proxy", proxy_url], dry_run)
    if no_proxy:
        print(f"  note: set NO_PROXY={no_proxy} in your environment for bypass hosts")


def configure_npm(proxy_url, no_proxy, dry_run=False):
    print("\n[npm]")
    if not tool_available("npm"):
        print("  npm not found on PATH; skipping.")
        return
    npm = shutil.which("npm")
    run([npm, "config", "set", "proxy", proxy_url], dry_run)
    run([npm, "config", "set", "https-proxy", proxy_url], dry_run)
    if no_proxy:
        run([npm, "config", "set", "noproxy", no_proxy], dry_run)


def configure_environment_proxy(proxy_url, no_proxy, dry_run=False):
    """
    Set the standard HTTP_PROXY / HTTPS_PROXY / NO_PROXY environment variables
    so that tools which only honor these (Prisma, curl, wget, urllib-based
    Python scripts, requests, many CLIs) can find the proxy without per-tool
    config.

    On Windows we use `setx` to persist them across new shells. The current
    process won't see the change — that's a `setx` quirk — so we tell the
    user to restart their shell. On non-Windows we just print the export
    lines for the user to add to their shell profile.

    NO_PROXY is set to include localhost and a couple of common loopback
    representations so that local services (Postgres, dev servers) don't
    accidentally route through the proxy.
    """
    print("\n[Environment proxy variables]")

    # Always include loopback in NO_PROXY so local services aren't proxied.
    no_proxy_with_local = "localhost,127.0.0.1,::1"
    if no_proxy:
        no_proxy_with_local += "," + no_proxy

    if sys.platform == "win32":
        if not shutil.which("setx"):
            print("  setx not on PATH; skipping. Set HTTPS_PROXY / HTTP_PROXY / "
                  "NO_PROXY manually in your shell.")
            return
        for var in ("HTTPS_PROXY", "HTTP_PROXY"):
            run(["setx", var, proxy_url], dry_run)
        run(["setx", "NO_PROXY", no_proxy_with_local], dry_run)
        if not dry_run:
            print("  (setx persists for new shells; restart your terminal)")
            print("  affects: Prisma, curl, wget, requests, and any CLI that "
                  "honors HTTPS_PROXY")
    else:
        print(f"  export HTTPS_PROXY={proxy_url}")
        print(f"  export HTTP_PROXY={proxy_url}")
        print(f"  export NO_PROXY={no_proxy_with_local}")
        print("  (add to ~/.bashrc / ~/.zshrc / shell profile)")


def unset_git(dry_run=False):
    print("\n[Git] removing proxy settings")
    if not tool_available("git"):
        print("  git not found on PATH; skipping.")
        return
    for key in ("http.proxy", "https.proxy"):
        cmd = ["git", "config", "--global", "--unset", key]
        if dry_run:
            print(f"  [dry-run] {' '.join(cmd)}")
        else:
            print(f"  $ {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True)


def unset_npm(dry_run=False):
    print("\n[npm] removing proxy settings")
    if not tool_available("npm"):
        print("  npm not found on PATH; skipping.")
        return
    npm = shutil.which("npm")
    for key in ("proxy", "https-proxy", "noproxy"):
        cmd = [npm, "config", "delete", key]
        if dry_run:
            print(f"  [dry-run] {' '.join(cmd)}")
        else:
            print(f"  $ {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True)


def unset_environment_proxy(dry_run=False):
    """
    Remove HTTPS_PROXY / HTTP_PROXY / NO_PROXY environment variables that
    `configure_environment_proxy` set. On Windows we use `reg delete` (since
    `setx VAR ""` doesn't actually remove the var, just blanks it).
    """
    print("\n[Environment proxy variables] removing")
    if sys.platform == "win32":
        for var in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"):
            cmd = ["reg", "delete", "HKCU\\Environment", "/F", "/V", var]
            if dry_run:
                print(f"  [dry-run] {' '.join(cmd)}")
            else:
                print(f"  $ {' '.join(cmd)}")
                # capture output: reg delete prints to stderr if the var
                # didn't exist, which we don't want to scare the user with
                r = subprocess.run(cmd, capture_output=True, text=True)
                if r.returncode != 0 and "unable to find" not in r.stderr.lower():
                    # unexpected error — show it
                    print(f"    {r.stderr.strip()}")
        print("  (changes affect new shells; restart your terminal)")
    else:
        print("  remove HTTPS_PROXY/HTTP_PROXY/NO_PROXY from your shell profile")


# ---------------------------------------------------------------------------
# no-proxy / bypass list
# ---------------------------------------------------------------------------

def get_no_proxy():
    for var in ("NO_PROXY", "no_proxy"):
        value = os.environ.get(var)
        if value:
            return value
    if sys.platform == "win32":
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                try:
                    override, _ = winreg.QueryValueEx(key, "ProxyOverride")
                    if override:
                        items = [p.strip() for p in override.split(";") if p.strip()]
                        items = [p for p in items if p != "<local>"]
                        if items:
                            return ",".join(items)
                except FileNotFoundError:
                    pass
        except (ImportError, OSError):
            pass
    return None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def detect_proxy(probe_url, pac_url_override=None, verbose=False):
    """Run the full detection chain."""
    proxy, source = detect_from_env()
    if proxy:
        return proxy, source

    proxy, source = detect_from_registry_static()
    if proxy:
        return proxy, source

    if pac_url_override:
        pac_url, pac_source = pac_url_override, "command line"
    else:
        pac_url, pac_source = find_pac_url(verbose=verbose)

    if not pac_url:
        return None, None

    print(f"PAC URL: {pac_url}  (source: {pac_source})")
    try:
        pac_text = fetch_pac(pac_url)
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        print(f"  failed to fetch PAC: {e}")
        return None, None

    probe_host = urlparse(probe_url).hostname or "example.com"

    result = None
    if shutil.which("node"):
        result = evaluate_pac_with_node(pac_text, probe_url, probe_host)
        if result and verbose:
            print(f"  PAC (node) returned: {result}")
    if not result:
        result = evaluate_pac_in_python(pac_text, probe_url, probe_host)
        if result and verbose:
            print(f"  PAC (python) returned: {result}")

    if not result:
        print("  could not evaluate PAC file")
        return None, None

    kind, proxy = parse_pac_result(result)
    if kind == "direct":
        print(f"  PAC says DIRECT for {probe_url}; no proxy needed for that destination")
        return None, None
    if kind == "proxy" and proxy:
        return proxy, f"PAC ({pac_source})"
    return None, None


def redact(url):
    try:
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            netloc = parsed.hostname or ""
            if parsed.port:
                netloc += f":{parsed.port}"
            netloc = f"***:***@{netloc}"
            return urlunparse(parsed._replace(netloc=netloc))
    except ValueError:
        pass
    return url


def probe_proxy_auth(proxy_url, probe_host="github.com", probe_port=443, timeout=8):
    """
    Send a CONNECT to the upstream proxy and observe whether it returns 407.
    Returns ('open', None) if no auth needed, ('auth', schemes) if 407, or
    ('error', reason) on connection failure.
    """
    parsed = urlparse(proxy_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 8080)
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return "error", f"connect to proxy {host}:{port} failed: {e}"
    try:
        req = (
            f"CONNECT {probe_host}:{probe_port} HTTP/1.1\r\n"
            f"Host: {probe_host}:{probe_port}\r\n\r\n"
        ).encode("ascii")
        sock.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 16384:
                break
        status_line = buf.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        if " 200 " in status_line:
            return "open", None
        if " 407 " in status_line:
            schemes = []
            for line in buf.split(b"\r\n"):
                if line.lower().startswith(b"proxy-authenticate:"):
                    val = line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
                    schemes.append(val.split()[0] if val else "")
            return "auth", schemes
        return "error", f"unexpected: {status_line}"
    finally:
        sock.close()


STATE_FILE = os.path.join(
    os.path.expanduser("~"), ".config", "configure_proxy", "state.json"
)


def save_state(state):
    """Persist detected settings so subcommands like `auth-proxy start` can reuse them."""
    import json
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except OSError as e:
        print(f"  warning: could not save state to {STATE_FILE}: {e}")


def load_state():
    """Load the previously-saved state, or {} if none."""
    import json
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def start_auth_proxy(upstream_url, port, mitm=None, debug=False):
    """
    Start auth_proxy.py as a background daemon. Returns the local proxy URL
    if successful, otherwise None.

    `mitm` is an optional comma-separated host list (or '*'). When provided,
    the daemon is started with `--mitm <hosts>` so it intercepts TLS for
    those hosts and handles McAfee progress pages.

    `debug` runs the daemon with verbose per-request logging.

    If a daemon is already running, we stop it first — otherwise the existing
    daemon would keep its old (possibly stale) `--mitm`/`--debug`/`--upstream`
    settings even though the user just gave us new ones.
    """
    auth_proxy_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth_proxy.py")
    if not os.path.exists(auth_proxy_script):
        print(f"  auth_proxy.py not found next to this script ({auth_proxy_script})")
        return None

    # Verify SSPI is available before trying
    if sys.platform != "win32":
        print("  auth_proxy requires Windows (SSPI); skipping.")
        return None
    try:
        import sspi  # noqa: F401
    except ImportError:
        print("  pywin32 not installed; install with: pip install pywin32")
        print("  (or pass --auth-proxy never to skip and configure tools to use the corporate proxy directly)")
        return None

    # Stop any existing daemon so we can start fresh with the current settings.
    # auth_proxy.py --stop is a no-op if nothing is running, so this is safe.
    try:
        subprocess.run([sys.executable, auth_proxy_script, "--stop"],
                       capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass  # best-effort; if --stop fails, --start will still attempt and likely succeed

    cmd = [sys.executable, auth_proxy_script, "--start",
           "--upstream", upstream_url, "--port", str(port)]
    if mitm:
        cmd += ["--mitm", mitm]
    if debug:
        cmd += ["--debug"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"  failed to start auth_proxy: {e}")
        return None

    if result.stdout:
        for line in result.stdout.strip().splitlines():
            print(f"  {line}")
    if result.returncode != 0:
        print(f"  auth_proxy startup failed: {result.stderr.strip()}")
        return None

    return f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# Persisted configuration (so reboots don't need re-typing all the args)
# ---------------------------------------------------------------------------

CONFIG_FILE = os.path.join(
    os.path.expanduser("~"), ".config", "configure_proxy", "config.json"
)

# Args to persist after a successful run. Keys match argparse `dest` names.
# Excludes things that should be re-detected (proxy URL, pac URL) and things
# that don't make sense to persist (dry-run, unset, verbose).
_PERSISTED_ARGS = (
    "probe_url",
    "ca_bundle_path",
    "ca_import",
    "ca_pick",
    "no_ca",
    "auth_proxy",
    "auth_proxy_port",
    "mitm",
    "auth_proxy_debug",
    "no_env_proxy",
)


def load_persisted_config():
    """Return a dict of persisted settings, or empty dict if none/unreadable."""
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        import json
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except (OSError, ValueError):
        return {}


def save_persisted_config(args, hardcoded_defaults):
    """
    Save args that differ from hardcoded_defaults to the config file.
    Skips empty/None values and anything in _PERSISTED_ARGS that matches the
    hardcoded default (keeps the file minimal).
    """
    import json
    to_save = {}
    # When the user explicitly passes --foo "" on the command line, we want to
    # clear any previously-persisted value for that arg, not "skip saving" it
    # (which would leave the old persisted value intact and confusing). To
    # tell "user passed empty" from "user didn't pass at all", we look at argv.
    user_specified = _user_specified_flags(sys.argv[1:])

    for name in _PERSISTED_ARGS:
        if not hasattr(args, name):
            continue
        value = getattr(args, name)
        default = hardcoded_defaults.get(name)

        # Explicit clear: the user passed --foo "" on this invocation.
        # Skip saving so the persisted value goes away on rewrite.
        if name in user_specified and (value == "" or value == [] or value is None):
            continue

        if value is None or value == "" or value == []:
            continue
        if value == default:
            continue
        to_save[name] = value

    if not to_save:
        # Remove the file if there's nothing meaningful to save (clean state)
        if os.path.exists(CONFIG_FILE):
            try:
                os.unlink(CONFIG_FILE)
            except OSError:
                pass
        return

    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        # Write atomically via temp file + rename so a crash mid-write doesn't
        # corrupt the config
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(to_save, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, CONFIG_FILE)
    except OSError as e:
        print(f"  warning: could not save config to {CONFIG_FILE}: {e}")


def _user_specified_flags(argv):
    """
    Return the set of dest-style names of flags the user explicitly passed
    on the command line. Used so saved-config values don't override CLI.
    """
    specified = set()
    for token in argv:
        if not token.startswith("--"):
            continue
        # Strip --no-foo prefix, --foo=value form
        flag = token.split("=", 1)[0].lstrip("-")
        # argparse converts dashes to underscores in dest
        specified.add(flag.replace("-", "_"))
    return specified


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--unset", action="store_true")
    parser.add_argument("--proxy", help="Override detection and use this proxy URL")
    parser.add_argument("--pac-url", help="Use this PAC URL instead of auto-discovering")
    parser.add_argument("--probe-url", default=DEFAULT_PROBE_URL,
                        help=f"URL used for PAC query and TLS probe (default: {DEFAULT_PROBE_URL})")
    parser.add_argument("--no-ca", action="store_true",
                        help="Skip corporate root CA discovery and CA bundle setup")
    parser.add_argument("--ca-bundle-path",
                        help="Where to write the combined CA bundle (default: ~/.config/configure_proxy/ca-bundle.pem)")
    parser.add_argument("--ca-import", action="append", default=[], metavar="PATH",
                        help="Path to a manually-exported corporate cert (.cer/.pem/.crt). "
                             "Can be passed multiple times. Use this when auto-detection fails.")
    parser.add_argument("--ca-pick", metavar="SUBSTRING",
                        help="When multiple CA candidates are found in the Windows store, "
                             "auto-select the one whose subject contains this substring "
                             "(case-insensitive). Useful for non-interactive runs.")
    parser.add_argument("--auth-proxy", choices=["auto", "always", "never"], default="auto",
                        help="Whether to start a local NTLM/Negotiate-handling proxy in front of "
                             "the corporate proxy. 'auto' (default): detect and offer if needed. "
                             "'always': start unconditionally. 'never': skip and configure tools "
                             "to use the corporate proxy directly.")
    parser.add_argument("--auth-proxy-port", type=int, default=3128,
                        help="Port for the local auth-handling proxy (default: 3128)")
    parser.add_argument("--mitm", metavar="HOSTS", default=None,
                        help="Comma-separated list of hosts to MITM through "
                             "the local auth_proxy (or '*' for all). MITM is "
                             "needed for hosts where the corporate proxy "
                             "returns McAfee progress pages instead of file "
                             "bytes — typically anywhere serving large "
                             "binaries. Common offenders: registry.npmjs.org, "
                             "registry.yarnpkg.com, binaries.prisma.sh. "
                             "Persisted across runs once set. Pass an empty "
                             "string ('') to clear a previously-saved value.")
    parser.add_argument("--auth-proxy-debug", action="store_true",
                        help="Run the auth_proxy daemon with --debug (verbose "
                             "per-request logging). Persisted across runs.")
    parser.add_argument("--no-env-proxy", action="store_true",
                        help="Skip setting HTTPS_PROXY/HTTP_PROXY/NO_PROXY env "
                             "vars via setx. By default we set them so that "
                             "tools which only honor env vars (Prisma, curl, "
                             "wget, requests-based scripts, and many other "
                             "CLIs) route through the proxy automatically. "
                             "Disable this if you want to manage these vars "
                             "yourself or only have specific tools use the proxy.")
    parser.add_argument("--show-config", action="store_true",
                        help="Print the persisted config and exit")
    parser.add_argument("--reset-config", action="store_true",
                        help="Delete the persisted config file and exit")
    parser.add_argument("--no-save", action="store_true",
                        help="Don't persist this run's settings to disk")
    parser.add_argument("-v", "--verbose", action="store_true")

    # Capture the hardcoded defaults BEFORE we mutate args, so save logic can
    # diff against them later.
    hardcoded_defaults = {a.dest: a.default for a in parser._actions}

    args = parser.parse_args()

    # --show-config / --reset-config short-circuit before any other work
    if args.show_config:
        cfg = load_persisted_config()
        if not cfg:
            print(f"No persisted config at {CONFIG_FILE}")
        else:
            import json
            print(f"Persisted config ({CONFIG_FILE}):")
            print(json.dumps(cfg, indent=2, sort_keys=True))
        return 0
    if args.reset_config:
        if os.path.exists(CONFIG_FILE):
            os.unlink(CONFIG_FILE)
            print(f"Removed {CONFIG_FILE}")
        else:
            print(f"No persisted config at {CONFIG_FILE}")
        return 0

    # Merge in persisted config: for each persistable field, if the user did
    # NOT pass it on the command line, use the saved value. Saved values
    # never override explicit CLI flags.
    persisted = load_persisted_config()
    if persisted:
        user_flags = _user_specified_flags(sys.argv[1:])
        applied = []
        for name, value in persisted.items():
            if name not in _PERSISTED_ARGS:
                continue  # ignore unknown keys (forward-compat)
            if name in user_flags:
                continue  # user overrode it
            if not hasattr(args, name):
                continue
            setattr(args, name, value)
            applied.append(name)
        if applied:
            print(f"Loaded persisted settings from {CONFIG_FILE}: {', '.join(applied)}")

    if args.unset:
        unset_git(args.dry_run)
        unset_npm(args.dry_run)
        unset_environment_proxy(args.dry_run)
        unset_ca_for_tools(args.dry_run)
        # Best-effort stop the auth proxy daemon
        auth_proxy_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth_proxy.py")
        if os.path.exists(auth_proxy_script):
            print("\n[auth_proxy] stopping daemon if running")
            if not args.dry_run:
                subprocess.run([sys.executable, auth_proxy_script, "--stop"], capture_output=True)
        # Clear persisted config so a future run starts fresh
        if not args.dry_run and os.path.exists(CONFIG_FILE):
            try:
                os.unlink(CONFIG_FILE)
                print(f"\nRemoved persisted config {CONFIG_FILE}")
            except OSError as e:
                print(f"\nwarning: couldn't remove {CONFIG_FILE}: {e}")
        return 0

    if args.proxy:
        proxy_url = normalize_proxy_url(args.proxy)
        source = "command line"
    else:
        proxy_url, source = detect_proxy(args.probe_url, pac_url_override=args.pac_url, verbose=args.verbose)

    if not proxy_url:
        print("\nNo proxy detected.")
        print("  Tried: env vars, registry static proxy, registry AutoConfigURL, DNS WPAD")
        print("  Hints:")
        print("    - Pass --pac-url http://wpad.yourdomain/wpad.dat if you know it")
        print("    - Pass --proxy http://host:port to set one explicitly")
        print("    - Run with -v to see DNS lookups during WPAD discovery")
        return 1

    no_proxy = get_no_proxy()

    print(f"\nDetected proxy: {redact(proxy_url)}")
    print(f"  source: {source}")
    if no_proxy:
        print(f"  no-proxy: {no_proxy}")
    if args.dry_run:
        print("  (dry-run mode — no changes will be made)")

    # Decide whether to put a local auth-handling proxy in front
    upstream_url = proxy_url  # the corporate proxy
    tool_proxy_url = proxy_url  # what we tell git/npm/etc to use

    if args.auth_proxy != "never":
        needs_auth = False
        if args.auth_proxy == "always":
            needs_auth = True
            print("\n[auth_proxy] --auth-proxy always: starting local proxy")
        else:
            probe_host = urlparse(args.probe_url).hostname or "github.com"
            print(f"\n[auth_proxy] probing whether {redact(proxy_url)} requires auth...")
            kind, info = probe_proxy_auth(proxy_url, probe_host=probe_host)
            if kind == "auth":
                print(f"  upstream requires auth (offered: {', '.join(info) or '?'})")
                needs_auth = True
            elif kind == "open":
                print("  upstream does not require auth; using it directly")
            else:
                print(f"  probe inconclusive: {info}")
                print("  proceeding with direct upstream config; pass --auth-proxy always to force the local proxy")

        if needs_auth and not args.dry_run:
            local = start_auth_proxy(upstream_url, args.auth_proxy_port,
                                     mitm=args.mitm,
                                     debug=args.auth_proxy_debug)
            if local:
                tool_proxy_url = local
                print(f"  tools will be pointed at {local} (which forwards to {redact(upstream_url)})")
                if args.mitm:
                    print(f"  auth_proxy is intercepting TLS for: {args.mitm}")
            else:
                print("  auth_proxy unavailable; falling back to direct upstream config")
                print("  (Git on Windows can usually authenticate via SSPI on its own;")
                print("   npm and pip will likely fail until auth_proxy is running)")
        elif needs_auth and args.dry_run:
            print(f"  [dry-run] would start auth_proxy on port {args.auth_proxy_port}")
            if args.mitm:
                print(f"  [dry-run] with --mitm {args.mitm}")
            if args.auth_proxy_debug:
                print(f"  [dry-run] with --debug")
            tool_proxy_url = f"http://127.0.0.1:{args.auth_proxy_port}"

    configure_git(tool_proxy_url, no_proxy, args.dry_run)
    configure_npm(tool_proxy_url, no_proxy, args.dry_run)
    if not args.no_env_proxy:
        configure_environment_proxy(tool_proxy_url, no_proxy, args.dry_run)

    if not args.no_ca:
        corporate_certs = []

        # Strategy 0: explicit --ca-import paths (highest priority)
        for import_path in args.ca_import:
            try:
                certs_from_file = _load_certs_from_file(import_path)
                if not certs_from_file:
                    print(f"\n[SSL CA] no certificates found in {import_path}")
                    continue
                print(f"\n[SSL CA] imported {len(certs_from_file)} cert(s) from {import_path}")
                for subj, iss, der, self_signed in certs_from_file:
                    kind = "root" if self_signed else "intermediate"
                    print(f"    - [{kind}] {subj}")
                corporate_certs.extend(certs_from_file)
            except (OSError, ValueError) as e:
                print(f"\n[SSL CA] failed to import {import_path}: {e}")

        # Strategy 1: Windows ROOT trust store (works without proxy auth).
        # On a managed corporate machine the inspection CA is already here.
        if not corporate_certs and sys.platform == "win32":
            print("\n[SSL CA] checking Windows ROOT trust store for corporate CAs...")
            candidates = discover_corporate_ca_from_windows_store(verbose=args.verbose)
            if candidates:
                # If the user gave a substring match, apply it first
                if args.ca_pick:
                    needle = args.ca_pick.lower()
                    matches = [c for c in candidates if needle in c[0].lower()]
                    if not matches:
                        print(f"  --ca-pick {args.ca_pick!r}: no candidate matched.")
                        print(f"  candidates: {[c[0] for c in candidates]}")
                    elif len(matches) > 1:
                        print(f"  --ca-pick {args.ca_pick!r}: matched {len(matches)} candidates; "
                              "be more specific")
                        for c in matches:
                            print(f"    - {c[0]}")
                    else:
                        print(f"  --ca-pick matched: {matches[0][0]!r}")
                        corporate_certs = matches
                if not corporate_certs:
                    corporate_certs = select_corporate_ca(
                        candidates, tool_proxy_url, args.probe_url,
                        verbose=args.verbose,
                        interactive=sys.stdin.isatty(),
                    )

        # Strategy 2: probe the proxy directly. Only as last resort, since this
        # is the path that fails on NTLM/Negotiate proxies (when not behind
        # the local auth_proxy).
        if not corporate_certs:
            print("\n[SSL CA] discovering corporate root CA via TLS probe...")
            try:
                # Use tool_proxy_url so the probe goes through the local auth
                # proxy if we started one (which handles NTLM transparently)
                corporate_certs = discover_corporate_ca(tool_proxy_url, args.probe_url, verbose=args.verbose)
            except ProxyAuthRequiredError as e:
                print(f"  proxy requires authentication: {e}")
                print(f"  schemes offered: {', '.join(e.schemes) or '(none parsed)'}")
                print("  Pass --auth-proxy always to start the local auth-handling proxy,")
                print("  or use --ca-import to supply the cert manually.")

        if corporate_certs:
            print(f"\n  found {len(corporate_certs)} corporate cert(s):")
            for subj, iss, _, self_signed in corporate_certs:
                kind = "root" if self_signed else "intermediate"
                print(f"    - [{kind}] {subj}  (issued by: {iss})")

            bundle_path = args.ca_bundle_path or os.path.join(
                os.path.expanduser("~"), ".config", "configure_proxy", "ca-bundle.pem"
            )
            if args.dry_run:
                print(f"  [dry-run] would write combined CA bundle to {bundle_path}")
            else:
                bundle_path = write_ca_bundle(corporate_certs, bundle_path)
                print(f"  wrote combined CA bundle to {bundle_path}")
            configure_ca_for_tools(bundle_path, args.dry_run)
        else:
            print("\n  no corporate root CA detected.")
            print("  If you know SSL inspection is happening but detection failed,")
            print("  export the cert manually (Internet Options > Content > Certificates >")
            print("  Trusted Root, find the corporate one, Export as Base-64 .cer) and run:")
            print("    python configure_proxy.py --ca-import <path-to-exported.cer>")

        # Independent of whether we (re)built the bundle just now, make sure
        # the MITM CA is present in it. Without this, users who created the
        # MITM CA *after* their first configure_proxy.py run would have a
        # bundle that doesn't include it (because the corp-cert discovery
        # may not run on every invocation).
        if not args.dry_run:
            bundle_path = args.ca_bundle_path or os.path.join(
                os.path.expanduser("~"), ".config", "configure_proxy", "ca-bundle.pem"
            )
            ensure_mitm_ca_in_bundle(bundle_path)

    # Persist the settings used in this run so the next run (e.g. after a
    # reboot) can pick them up automatically.
    if not args.dry_run and not args.no_save:
        save_persisted_config(args, hardcoded_defaults)

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())