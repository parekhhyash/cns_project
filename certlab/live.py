"""Mode 1: live check of a real server's certificate.

One TLS handshake with verification switched off (only to *read* the chain), then
the chain is judged by our own engine against the operating system's trust store.
No application data is ever sent, and the connection is closed straight away.
"""
from __future__ import annotations

import base64
import functools
import ipaddress
import os
import re
import socket
import ssl
import urllib.request
import warnings
from dataclasses import dataclass
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
HOST_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*\.?$")
CONNECT_TIMEOUT = 6.0


@dataclass
class LiveFetch:
    chain: list[x509.Certificate]
    host: str
    port: int
    ip: str
    tls_version: str
    cipher: str
    proxied: bool


def parse_target(text: str) -> tuple[str, int]:
    """'https://Example.com:8443/path' -> ('example.com', 8443). Default port 443."""
    t = (text or "").strip()
    if not t:
        raise ValueError("Enter a domain, for example example.com.")
    if "://" not in t:
        t = "https://" + t
    u = urlparse(t)
    try:
        port = u.port or 443
    except ValueError:
        raise ValueError("That port number is not valid.") from None
    host = (u.hostname or "").rstrip(".").lower()
    if not host or len(host) > 253:
        raise ValueError("Enter a domain, for example example.com.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.match(host):
            raise ValueError("That does not look like a valid domain name.") from None
    return host, port


@functools.lru_cache(maxsize=1)
def system_trust() -> tuple[x509.Certificate, ...]:
    """Root certificates the operating system (and Python) already trust."""
    warnings.filterwarnings("ignore", category=Warning, module=__name__)   # odd legacy roots
    ders: dict[bytes, None] = {}
    ctx = ssl.create_default_context()
    for d in ctx.get_ca_certs(binary_form=True):
        ders[d] = None
    vp = ssl.get_default_verify_paths()
    files = [os.environ.get("SSL_CERT_FILE"), vp.cafile, vp.openssl_cafile,
             "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"]
    for f in files:
        if f and os.path.isfile(f):
            try:
                with open(f, "rb") as fh:
                    for c in x509.load_pem_x509_certificates(fh.read()):
                        ders[c.public_bytes(Encoding.DER)] = None
            except ValueError:
                continue
    out = []
    for d in ders:
        try:
            out.append(x509.load_der_x509_certificate(d))
        except ValueError:
            continue
    return tuple(out)


def _proxy_for(host: str):
    proxies = urllib.request.getproxies()
    p = proxies.get("https") or proxies.get("http")
    if p and not urllib.request.proxy_bypass(host):
        return urlparse(p)
    return None


def _check_public(host: str, proxied: bool, allow_private: bool) -> str | None:
    """Refuse loopback, private and link-local targets so the web app cannot be used
    to probe the machine's own network. Returns the validated IP, if we resolved one."""
    try:
        infos = {i[4][0] for i in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        if proxied:
            return None            # the proxy resolves names for us
        raise ValueError(f"Could not find '{host}'. Check the spelling and your connection.") from None
    ips = sorted(infos)
    if not allow_private and not all(ipaddress.ip_address(i).is_global for i in ips):
        raise ValueError(f"'{host}' points to a private or local address. Live checks only "
                         "connect to public servers.")
    return ips[0]


def _open(host, port, ip, proxy, timeout):
    if proxy is not None:
        s = socket.create_connection((proxy.hostname, proxy.port or 8080), timeout)
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if proxy.username:
            cred = f"{proxy.username}:{proxy.password or ''}".encode()
            req += "Proxy-Authorization: Basic " + base64.b64encode(cred).decode() + "\r\n"
        s.sendall((req + "\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            part = s.recv(1024)
            if not part:
                break
            buf += part
        status = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if " 200" not in status:
            s.close()
            raise OSError(f"the proxy refused the connection ({status or 'no reply'})")
        return s
    return socket.create_connection((ip or host, port), timeout)


def fetch(host: str, port: int = 443, *, allow_private: bool = False,
          timeout: float = CONNECT_TIMEOUT) -> LiveFetch:
    proxy = _proxy_for(host)
    try:
        ipaddress.ip_address(host)
        sni, literal = None, True
    except ValueError:
        sni, literal = host, False
    ip = _check_public(host, proxy is not None, allow_private)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")      # we want to *inspect* weak servers, not fail early
    raw = _open(host, port, ip if not literal else host, proxy, timeout)
    try:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            ders = tls.get_unverified_chain()
            chain = [x509.load_der_x509_certificate(d if isinstance(d, bytes) else d.public_bytes(Encoding.DER))
                     for d in ders]
            return LiveFetch(chain, host, port, ip or host, tls.version() or "?",
                             (tls.cipher() or ("?",))[0], proxy is not None)
    finally:
        raw.close()

