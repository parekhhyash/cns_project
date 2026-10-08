"""Certificate Generator: a small PKI lab producing legitimate and malicious certs.

Everything is local and uses the reserved ``.test`` TLD; nothing touches the
public PKI.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

HOST = "bank.lab.test"
UTC = dt.timezone.utc


def _now() -> dt.datetime:
    return dt.datetime.now(UTC)


def new_key(kind: str = "ec"):
    if kind == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    if kind.startswith("rsa"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(kind[3:]))
    raise ValueError(kind)


def _name(cn: str, org: str = "CNS Lab") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


@dataclass
class Identity:
    """A certificate together with its private key."""
    cert: x509.Certificate
    key: object
    chain: list = field(default_factory=list)  # issuer certs, nearest first

    def chain_pem(self) -> bytes:
        return b"".join(c.public_bytes(serialization.Encoding.PEM)
                        for c in [self.cert, *self.chain])

    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())


def _aki(issuer_cert, own_key):
    if issuer_cert is None:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(own_key.public_key())
    ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)


def make_ca(cn: str, issuer: Identity | None = None, *, days: int = 3650,
            path_length: int | None = None) -> Identity:
    key = new_key("ec")
    signer = issuer.key if issuer else key
    issuer_name = issuer.cert.subject if issuer else _name(cn)
    now = _now()
    b = (x509.CertificateBuilder()
         .subject_name(_name(cn)).issuer_name(issuer_name)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(days=1))
         .not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(_aki(issuer.cert if issuer else None, key), critical=False)
         .add_extension(x509.KeyUsage(
             digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
             key_encipherment=False, data_encipherment=False, key_agreement=False,
             encipher_only=False, decipher_only=False), critical=True))
    cert = b.sign(signer, hashes.SHA256())
    chain = [issuer.cert, *issuer.chain] if issuer else []
    return Identity(cert, key, chain)


def issue_leaf(issuer: Identity, hostname: str = HOST, *, cn: str | None = None,
               sans: list[str] | None = None, not_before_days: int = -1,
               valid_days: int = 90, key_kind: str = "ec") -> Identity:
    """Issue a server certificate. ``not_before_days``/``valid_days`` allow
    expired or not-yet-valid certs to be produced on purpose."""
    key = new_key(key_kind)
    now = _now()
    nb = now + dt.timedelta(days=not_before_days)
    names = sans if sans is not None else [hostname]
    b = (x509.CertificateBuilder()
         .subject_name(_name(cn or hostname)).issuer_name(issuer.cert.subject)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(nb + dt.timedelta(days=valid_days))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(_aki(issuer.cert, key), critical=False)
         .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                        critical=False))
    if names:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),
                            critical=False)
    cert = b.sign(issuer.key, hashes.SHA256())
    return Identity(cert, key, [issuer.cert, *issuer.chain])


def issue_sha1_leaf(issuer: Identity, hostname: str = HOST) -> Identity:
    """Modern ``cryptography`` refuses to sign with SHA-1, so shell out to the
    OpenSSL CLI to mint a deliberately weak certificate."""
    key = new_key("ec")
    with tempfile.TemporaryDirectory() as d:
        def w(name, data):
            path = os.path.join(d, name)
            with open(path, "wb") as f:
                f.write(data)
            return path
        pem = serialization.Encoding.PEM
        csr = (x509.CertificateSigningRequestBuilder().subject_name(_name(hostname))
               .sign(key, hashes.SHA256()))
        csr_f = w("l.csr", csr.public_bytes(pem))
        ca_f = w("ca.pem", issuer.cert.public_bytes(pem))
        cak_f = w("ca.key", issuer.key_pem())
        ext_f = w("ext.cnf", (f"basicConstraints=critical,CA:FALSE\n"
                              f"subjectAltName=DNS:{hostname}\n").encode())
        out_f = os.path.join(d, "l.pem")
        subprocess.run(["openssl", "x509", "-req", "-sha1", "-in", csr_f, "-CA", ca_f,
                        "-CAkey", cak_f, "-CAcreateserial", "-days", "90",
                        "-extfile", ext_f, "-out", out_f],
                       check=True, capture_output=True)
        with open(out_f, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
    return Identity(cert, key, [issuer.cert, *issuer.chain])


def make_self_signed(hostname: str = HOST) -> Identity:
    key = new_key("ec")
    now = _now()
    cert = (x509.CertificateBuilder()
            .subject_name(_name(hostname)).issuer_name(_name(hostname))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .sign(key, hashes.SHA256()))
    return Identity(cert, key, [])


def make_crl(ca: Identity, revoked_serials: list[int]) -> x509.CertificateRevocationList:
    now = _now()
    b = (x509.CertificateRevocationListBuilder()
         .issuer_name(ca.cert.subject)
         .last_update(now - dt.timedelta(hours=1)).next_update(now + dt.timedelta(days=7)))
    for s in revoked_serials:
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(s).revocation_date(now).build())
    return b.sign(ca.key, hashes.SHA256())


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


class CTLog:
    """Toy append-only Certificate Transparency log (hash-chained JSON).

    Stands in for real CT logs / SCTs, which need network access to public logs.
    """

    def __init__(self, path: str):
        self.path = path
        self.entries: list[dict] = []
        if os.path.exists(path):
            with open(path) as f:
                self.entries = json.load(f)

    @staticmethod
    def _h(prev: str, fp: str) -> str:
        return hashlib.sha256((prev + fp).encode()).hexdigest()

    def add(self, cert: x509.Certificate) -> None:
        fp = fingerprint(cert)
        if self.contains(cert):
            return
        prev = self.entries[-1]["hash"] if self.entries else "0" * 64
        self.entries.append({"index": len(self.entries), "fingerprint": fp,
                             "hash": self._h(prev, fp)})

    def contains(self, cert: x509.Certificate) -> bool:
        fp = fingerprint(cert)
        return any(e["fingerprint"] == fp for e in self.entries)

    def verify_integrity(self) -> bool:
        prev = "0" * 64
        for e in self.entries:
            if e["hash"] != self._h(prev, e["fingerprint"]):
                return False
            prev = e["hash"]
        return True

    def save(self) -> None:
        with open(self.path, "w") as f:
            json.dump(self.entries, f, indent=1)


@dataclass
class Scenario:
    name: str
    description: str
    identity: Identity
    expect: str                 # "allow" | "block"
    expected_failures: tuple[str, ...] = ()


class Lab:
    """Builds the whole PKI lab: trusted root/intermediate, rogue CA, CT log,
    CRL, and the catalogue of legitimate and malicious scenarios."""

    def __init__(self, workdir: str):
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)
        self.root = make_ca("CNS Lab Root CA", path_length=1)
        self.inter = make_ca("CNS Lab Intermediate CA", self.root, days=1825, path_length=0)
        self.rogue_root = make_ca("Totally Legit Root CA", path_length=1)  # in no trust store
        self.rogue_inter = make_ca("Totally Legit Issuing CA", self.rogue_root, path_length=0)
        self.ct = CTLog(os.path.join(workdir, "ct_log.json"))
        self.scenarios: list[Scenario] = []
        self._build()
        self.crl = make_crl(self.inter, [self._revoked.cert.serial_number])
        self.ct.save()
        self._write_files()

    @property
    def trust_store(self) -> list[x509.Certificate]:
        return [self.root.cert]

    def _logged(self, ident: Identity, ct: bool = True) -> Identity:
        if ct:
            self.ct.add(ident.cert)
        return ident

    def _add(self, name, desc, ident, expect, fails=(), ct=True):
        self.scenarios.append(Scenario(name, desc, self._logged(ident, ct), expect, tuple(fails)))

    def _build(self):
        i = self.inter
        self._add("legitimate", "Valid chain, correct host, logged in CT",
                  issue_leaf(i), "allow")
        self._add("self_signed", "Attacker self-signs a cert for the host",
                  make_self_signed(), "block", ["chain"], ct=False)
        self._add("expired", "Genuine CA-issued cert that expired 30 days ago",
                  issue_leaf(i, not_before_days=-120, valid_days=90), "block", ["validity"])
        self._add("not_yet_valid", "Cert whose validity starts in the future",
                  issue_leaf(i, not_before_days=10), "block", ["validity"])
        self._add("hostname_mismatch", "Valid cert issued for a different domain",
                  issue_leaf(i, "evil.lab.test"), "block", ["hostname"])
        self._add("cn_only_no_san", "Right CN but no SAN (modern clients ignore CN)",
                  issue_leaf(i, sans=[]), "block", ["hostname"])
        self._add("rogue_ca", "Cert issued by a CA that is in no trust store",
                  issue_leaf(self.rogue_inter), "block", ["chain"], ct=False)
        self._revoked = issue_leaf(i)
        self._add("revoked", "Valid-looking cert whose serial is on the CRL",
                  self._revoked, "block", ["revocation"])
        self._add("weak_key", "1024-bit RSA key", issue_leaf(i, key_kind="rsa1024"),
                  "block", ["strength"])
        self._add("weak_signature", "Cert signed with SHA-1",
                  issue_sha1_leaf(i), "block", ["strength"])
        self._add("compromised_ca_misissue",
                  "Trusted CA mis-issues a cert (DigiNotar-style) but it never reaches CT logs",
                  issue_leaf(i), "block", ["ct"], ct=False)

    def _write_files(self):
        w = self.workdir
        def dump(name, data):
            with open(os.path.join(w, name), "wb") as f:
                f.write(data)
        pem = serialization.Encoding.PEM
        dump("root_ca.pem", self.root.cert.public_bytes(pem))
        dump("intermediate_ca.pem", self.inter.cert.public_bytes(pem))
        dump("rogue_root_ca.pem", self.rogue_root.cert.public_bytes(pem))
        dump("intermediate.crl.pem", self.crl.public_bytes(pem))
        for s in self.scenarios:
            dump(f"{s.name}.chain.pem", s.identity.chain_pem())
            dump(f"{s.name}.key.pem", s.identity.key_pem())

    def paths(self, scenario: Scenario) -> tuple[str, str]:
        return (os.path.join(self.workdir, f"{scenario.name}.chain.pem"),
                os.path.join(self.workdir, f"{scenario.name}.key.pem"))

    def get(self, name: str) -> Scenario:
        return next(s for s in self.scenarios if s.name == name)
