"""Network side of the lab: TLS servers, MITM simulation module, and clients.

All sockets bind to 127.0.0.1. The "attacker" is an in-process TLS-terminating
proxy standing in for what mitmproxy/bettercap would do on a hostile network.
"""
from __future__ import annotations

import socket
import ssl
import threading
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .analyzer import Analyzer, Verdict
from .certgen import HOST, Lab, Scenario

LOOPBACK = "127.0.0.1"
SECRET = b"POST /login user=alice&password=hunter2 HTTP/1.1\r\n\r\n"
REPLY = b"HTTP/1.1 200 OK\r\n\r\nwelcome to the real bank"


def _server_ctx(chain_file: str, key_file: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # lab must be able to serve deliberately weak certs
    ctx.load_cert_chain(chain_file, key_file)
    return ctx


class _Listener(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((LOOPBACK, 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()

    def handle(self, conn):  # pragma: no cover - overridden
        raise NotImplementedError

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._safe, args=(conn,), daemon=True).start()

    def _safe(self, conn):
        try:
            conn.settimeout(5)
            self.handle(conn)
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()

    def stop(self):
        self._stop.set()
        self.join(1)
        self.sock.close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *a):
        self.stop()


class TLSServer(_Listener):
    """A 'bank' server that answers any request with REPLY."""

    def __init__(self, chain_file: str, key_file: str):
        super().__init__()
        self.ctx = _server_ctx(chain_file, key_file)
        self.received: list[bytes] = []

    def handle(self, conn):
        with self.ctx.wrap_socket(conn, server_side=True) as tls:
            data = tls.recv(4096)
            if data:
                self.received.append(data)
                tls.sendall(REPLY)


class MitmProxy(_Listener):
    """MITM Simulation Module: terminates the client's TLS with the attacker's
    certificate, opens its own (unverified) TLS session to the real server, and
    relays traffic while recording the plaintext it can now read."""

    def __init__(self, chain_file: str, key_file: str, upstream_port: int):
        super().__init__()
        self.ctx = _server_ctx(chain_file, key_file)
        self.upstream_port = upstream_port
        self.captured: list[bytes] = []

    def handle(self, conn):
        with self.ctx.wrap_socket(conn, server_side=True) as client:
            data = client.recv(4096)
            if not data:
                return
            self.captured.append(data)
            up_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            up_ctx.check_hostname, up_ctx.verify_mode = False, ssl.CERT_NONE
            up_ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            with socket.create_connection((LOOPBACK, self.upstream_port), 5) as raw, \
                    up_ctx.wrap_socket(raw, server_hostname=HOST) as up:
                up.sendall(data)
                client.sendall(up.recv(4096))


@dataclass
class ClientResult:
    client: str
    connected: bool
    leaked_to_attacker: bool = False
    verdict: Verdict | None = None
    error: str = ""


def fetch_chain(port: int, hostname: str) -> tuple[ssl.SSLSocket, list[x509.Certificate]]:
    """Handshake with verification OFF only to *obtain* the presented chain; the
    caller must not send application data until the analyzer approves it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # inspect weak certs instead of failing early
    raw = socket.create_connection((LOOPBACK, port), 5)
    tls = ctx.wrap_socket(raw, server_hostname=hostname)
    ders = tls.get_unverified_chain()
    chain = [x509.load_der_x509_certificate(d if isinstance(d, bytes) else d.public_bytes(serialization.Encoding.DER))
             for d in ders]
    return tls, chain


def naive_client(port: int, hostname: str = HOST) -> ClientResult:
    """Models a mobile app / IoT client that disabled certificate validation."""
    try:
        tls, _ = fetch_chain(port, hostname)
        with tls:
            tls.sendall(SECRET)
            tls.recv(4096)
        return ClientResult("naive", True)
    except (ssl.SSLError, OSError) as e:
        return ClientResult("naive", False, error=str(e))


def stdlib_client(port: int, cafile: str, hostname: str = HOST) -> ClientResult:
    """Baseline: Python's own default validation against the lab root."""
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection((LOOPBACK, port), 5) as raw, \
                ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            tls.sendall(SECRET)
            tls.recv(4096)
        return ClientResult("stdlib", True)
    except (ssl.SSLError, OSError) as e:
        return ClientResult("stdlib", False, error=str(e).split("] ")[-1])


def guarded_client(port: int, analyzer: Analyzer, hostname: str = HOST) -> ClientResult:
    """Client fronted by the Certificate Analysis Engine: the chain is vetted
    right after the handshake and *before* any application data is sent."""
    try:
        tls, chain = fetch_chain(port, hostname)
    except (ssl.SSLError, OSError) as e:
        return ClientResult("guarded", False, error=str(e))
    verdict = analyzer.analyze(chain, hostname)
    with tls:
        if not verdict.allow:
            return ClientResult("guarded", False, verdict=verdict, error=verdict.reason)
        tls.sendall(SECRET)
        tls.recv(4096)
    return ClientResult("guarded", True, verdict=verdict)


def make_analyzer(lab: Lab, **kw) -> Analyzer:
    return Analyzer(lab.trust_store, crls=[lab.crl], ct_log=lab.ct, **kw)


@dataclass
class ScenarioOutcome:
    scenario: Scenario
    verdict: Verdict
    guarded: ClientResult
    naive: ClientResult
    stdlib: ClientResult
    naive_leaked: bool


def run_scenario(lab: Lab, sc: Scenario, *, via_mitm: bool = True) -> ScenarioOutcome:
    """Deploy the scenario cert on a server, optionally put it behind the MITM
    attacker (which presents that cert to the client), and test every client."""
    real_chain, real_key = lab.paths(lab.get("legitimate"))
    analyzer = make_analyzer(lab)
    chain_file, key_file = lab.paths(sc)
    cafile = lab.workdir + "/root_ca.pem"
    if via_mitm:
        with TLSServer(real_chain, real_key) as bank, \
                MitmProxy(chain_file, key_file, bank.port) as mitm:
            g = guarded_client(mitm.port, analyzer)
            s = stdlib_client(mitm.port, cafile)
            n = naive_client(mitm.port)
            leaked = any(b"password=" in c for c in mitm.captured)
            return ScenarioOutcome(sc, g.verdict, g, n, s, leaked and n.connected)
    with TLSServer(chain_file, key_file) as srv:
        g = guarded_client(srv.port, analyzer)
        s = stdlib_client(srv.port, cafile)
        n = naive_client(srv.port)
        return ScenarioOutcome(sc, g.verdict, g, n, s, False)
