"""Certificate Analysis Engine + Decision & Alerting.

Takes the certificate chain a server presented (leaf first) and runs independent
checks. Each check contributes to a trust score. The verdict has three levels:

* TRUSTED     every critical check passed and the score is above the threshold.
* SUSPICIOUS  the signatures are genuine but trust cannot be established (unknown
              issuer, self-signed, never logged). Held back, not proven malicious.
* BLOCKED     something is demonstrably wrong: bad signature, modified certificate,
              expired, wrong host, revoked, weak cryptography.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import logging
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

log = logging.getLogger("certlab.decision")

PASS, WARN, FAIL, SKIP = "pass", "warn", "fail", "skip"
TRUSTED, SUSPICIOUS, BLOCKED = "trusted", "suspicious", "blocked"
# Failures that mean "we cannot establish trust" rather than "this is broken".
TRUST_ONLY_FAILURES = {"chain", "ct"}


@dataclass
class CheckResult:
    name: str
    status: str
    detail: str
    weight: int
    critical: bool = True

    @property
    def points(self) -> float:
        return self.weight if self.status == PASS else self.weight / 2 if self.status == WARN else 0


@dataclass
class Verdict:
    hostname: str
    checks: list[CheckResult]
    score: int
    level: str
    reason: str

    @property
    def allow(self) -> bool:
        return self.level == TRUSTED

    @property
    def failed(self) -> list[str]:
        return [c.name for c in self.checks if c.status == FAIL]

    def report(self) -> str:
        lines = [f"{self.level.upper()}  {self.hostname}  trust={self.score}/100  ({self.reason})"]
        for c in self.checks:
            lines.append(f"  [{c.status.upper():4}] {c.name:<10} {c.detail}")
        return "\n".join(lines)


@dataclass
class Policy:
    threshold: int = 80
    require_ct: bool = True
    revocation_hard_fail: bool = True   # no CRL for the issuer => fail (not soft-fail)
    min_rsa_bits: int = 2048
    min_ec_bits: int = 256
    now: dt.datetime | None = None


def _cn(name: x509.Name) -> str:
    a = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return a[0].value if a else name.rfc4514_string()


def pretty_fingerprint(cert: x509.Certificate) -> str:
    h = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """True if ``issuer``'s key produced ``cert``'s signature. Done by hand because
    ``verify_directly_issued_by`` refuses legacy hashes (SHA-1), and such certs
    should be reported as weak rather than crash path building."""
    if cert.issuer != issuer.subject:
        return False
    pub, h = issuer.public_key(), cert.signature_hash_algorithm
    params = cert.signature_algorithm_parameters
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, params, h)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(h))
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError):
        return False
    return True


def _utc(d: dt.datetime) -> dt.datetime:
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


class Analyzer:
    def __init__(self, trust_store: list[x509.Certificate], *, crls=(), ct_log=None,
                 policy: Policy | None = None):
        self.trust = list(trust_store)
        self.crls = list(crls)
        self.ct = ct_log
        self.policy = policy or Policy()

    # ---- individual checks -------------------------------------------------

    def check_signature(self, chain):
        """Is every certificate's signature produced by its issuer's private key?
        This says nothing about whether that issuer is *trusted*; see check_chain."""
        pool = list(chain) + self.trust
        for c in chain:
            cands = [x for x in pool if x.subject == c.issuer]
            if not cands:
                return CheckResult("signature", FAIL,
                                   f"issuer '{_cn(c.issuer)}' of '{_cn(c.subject)}' is not in the chain or "
                                   "trust store, so its signature cannot be checked", 20)
            if not any(issued_by(c, x) for x in cands):
                return CheckResult("signature", FAIL,
                                   f"signature on '{_cn(c.subject)}' does NOT verify with the public key of "
                                   f"'{_cn(c.issuer)}': contents changed after signing, or signed by another key", 20)
        leaf = chain[0]
        algo = leaf.signature_algorithm_oid._name or leaf.signature_algorithm_oid.dotted_string
        return CheckResult("signature", PASS,
                           f"{len(chain)} signature(s) verified with the issuers' public keys "
                           f"(leaf: {algo})", 20)

    def _build_path(self, chain):
        """Order leaf -> ... -> trust anchor using signatures, not names alone.
        Returns (path, error). Path ends in the trust anchor on success."""
        leaf, pool = chain[0], list(chain[1:])
        path = [leaf]
        while True:
            cur = path[-1]
            for anchor in self.trust:
                if issued_by(cur, anchor):
                    path.append(anchor)
                    return path, None
            nxt = None
            for cand in pool:
                if cand is cur or cand in path:
                    continue
                if issued_by(cur, cand):
                    nxt = cand
                    break
            if nxt is None:
                if cur.issuer == cur.subject:
                    what = "self-signed certificate" if len(path) == 1 else "chain ends in untrusted root"
                    return path, f"{what} '{cur.subject.rfc4514_string()}' not in trust store"
                named = [x for x in pool + self.trust if x.subject == cur.issuer]
                if named:
                    return path, (f"'{_cn(cur.subject)}' claims issuer '{_cn(cur.issuer)}' but its "
                                  "signature does not verify against that issuer")
                return path, f"no trusted issuer found for '{cur.issuer.rfc4514_string()}'"
            path.append(nxt)
            pool.remove(nxt)

    def check_chain(self, chain):
        path, err = self._build_path(chain)
        if err:
            return CheckResult("chain", FAIL, err, 20), path
        # every non-leaf must be a CA, and path-length constraints must hold
        for depth, c in enumerate(path[1:], start=0):
            try:
                bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
            except x509.ExtensionNotFound:
                return CheckResult("chain", FAIL, f"issuer '{c.subject.rfc4514_string()}' lacks BasicConstraints", 20), path
            if not bc.ca:
                return CheckResult("chain", FAIL, "issuer is not a CA", 20), path
            if bc.path_length is not None and depth > bc.path_length:
                return CheckResult("chain", FAIL, "path length constraint violated", 20), path
        return CheckResult("chain", PASS, f"anchored at '{path[-1].subject.rfc4514_string()}' ({len(path)} certs)", 20), path

    def check_validity(self, path):
        now = _utc(self.policy.now or dt.datetime.now(dt.timezone.utc))
        for c in path:
            nb, na = _utc(c.not_valid_before_utc), _utc(c.not_valid_after_utc)
            if now < nb:
                return CheckResult("validity", FAIL, f"not valid until {nb:%Y-%m-%d}", 15)
            if now > na:
                return CheckResult("validity", FAIL, f"expired {na:%Y-%m-%d}", 15)
        na = _utc(path[0].not_valid_after_utc)
        return CheckResult("validity", PASS, f"valid until {na:%Y-%m-%d}", 15)

    @staticmethod
    def _match(pattern: str, host: str) -> bool:
        p, h = pattern.lower().rstrip("."), host.lower().rstrip(".")
        if p.startswith("*."):  # wildcard covers exactly one label
            return h.count(".") == p.count(".") and h.split(".", 1)[1] == p[2:]
        return p == h

    def check_hostname(self, leaf, hostname):
        try:
            san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        except x509.ExtensionNotFound:
            return CheckResult("hostname", FAIL, "no SubjectAltName (CN is not accepted)", 15)
        try:
            ip = ipaddress.ip_address(hostname)
            ok = ip in san.get_values_for_type(x509.IPAddress)
        except ValueError:
            ok = any(self._match(n, hostname) for n in san.get_values_for_type(x509.DNSName))
        dns = san.get_values_for_type(x509.DNSName)
        names = ", ".join(dns[:6]) + (f", … (+{len(dns) - 6})" if len(dns) > 6 else "") if dns else "-"
        if ok:
            return CheckResult("hostname", PASS, f"'{hostname}' matches SAN [{names}]", 15)
        return CheckResult("hostname", FAIL, f"'{hostname}' not in SAN [{names}]", 15)

    def check_integrity(self, leaf):
        """SHA-256 fingerprint compared with what the CA recorded when it issued this
        serial number. A changed byte anywhere changes the fingerprint."""
        fp = leaf.fingerprint(hashes.SHA256()).hex()
        pretty = pretty_fingerprint(leaf)
        lookup = getattr(self.ct, "fingerprint_for_serial", None)
        if lookup is None:
            return CheckResult("integrity", SKIP, f"SHA-256 {pretty[:23]}… (no issuance record to compare)", 0, False)
        known = lookup(leaf)
        if known is None:
            return CheckResult("integrity", SKIP, f"SHA-256 {pretty[:23]}… (no issuance record for this serial)", 0, False)
        if known == fp:
            return CheckResult("integrity", PASS, f"SHA-256 {pretty[:23]}… matches what the CA issued", 5)
        k = ":".join(known[i:i + 2].upper() for i in range(0, 8, 2))
        return CheckResult("integrity", FAIL,
                           f"the CA issued this serial with SHA-256 {k}… but this copy is {pretty[:11]}…: "
                           "modified after issuance", 5)

    def check_revocation(self, path):
        if len(path) < 2:
            return CheckResult("revocation", SKIP, "no issuer to consult", 10)
        leaf, issuer = path[0], path[1]
        for crl in self.crls:
            if crl.issuer != issuer.subject:
                continue
            if not crl.is_signature_valid(issuer.public_key()):
                return CheckResult("revocation", FAIL, "CRL signature invalid", 10)
            now = _utc(self.policy.now or dt.datetime.now(dt.timezone.utc))
            if crl.next_update_utc and now > _utc(crl.next_update_utc):
                return CheckResult("revocation", FAIL, "CRL is stale", 10)
            if crl.get_revoked_certificate_by_serial_number(leaf.serial_number):
                return CheckResult("revocation", FAIL, f"serial {leaf.serial_number:x} is REVOKED", 10)
            return CheckResult("revocation", PASS, "serial not on CRL", 10)
        if self.policy.revocation_hard_fail:
            return CheckResult("revocation", FAIL, "no CRL available for issuer (hard-fail)", 10)
        return CheckResult("revocation", WARN, "no CRL available for issuer (soft-fail)", 10)

    @staticmethod
    def _embedded_scts(leaf) -> int:
        try:
            return len(leaf.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps).value)
        except x509.ExtensionNotFound:
            return 0

    def check_ct(self, leaf):
        crit = self.policy.require_ct
        if self.ct is not None and self.ct.contains(leaf):
            return CheckResult("ct", PASS, "present in CT log", 10, crit)
        n = self._embedded_scts(leaf)
        if n:
            return CheckResult("ct", PASS, f"{n} embedded signed certificate timestamp(s) from public logs "
                                           "(log signatures not verified here)", 10, crit)
        if self.ct is None:
            return CheckResult("ct", SKIP, "no CT log configured and no embedded timestamps", 10, crit)
        return CheckResult("ct", FAIL, "certificate not found in CT log", 10, crit)

    def check_strength(self, path):
        p = self.policy
        for c in path:
            h = c.signature_hash_algorithm       # None for Ed25519/Ed448, which are strong
            if isinstance(h, (hashes.MD5, hashes.SHA1)):
                return CheckResult("strength", FAIL, f"weak signature hash {h.name}", 5)
            k = c.public_key()
            if isinstance(k, rsa.RSAPublicKey) and k.key_size < p.min_rsa_bits:
                return CheckResult("strength", FAIL, f"RSA-{k.key_size} below minimum {p.min_rsa_bits}", 5)
            if isinstance(k, ec.EllipticCurvePublicKey) and k.key_size < p.min_ec_bits:
                return CheckResult("strength", FAIL, f"EC-{k.key_size} below minimum {p.min_ec_bits}", 5)
        k = path[0].public_key()
        if isinstance(k, rsa.RSAPublicKey):
            desc = f"RSA-{k.key_size}"
        elif isinstance(k, ec.EllipticCurvePublicKey):
            desc = f"EC-{k.key_size}"
        else:
            desc = type(k).__name__.replace("PublicKey", "")
        h = path[0].signature_hash_algorithm
        return CheckResult("strength", PASS, f"{desc}, {h.name if h else 'built-in hash'}", 5)

    # ---- decision ----------------------------------------------------------

    def analyze(self, chain: list[x509.Certificate], hostname: str) -> Verdict:
        if not chain:
            return Verdict(hostname, [], 0, BLOCKED, "server presented no certificate")
        leaf = chain[0]
        chain_res, path = self.check_chain(chain)
        checks = [self.check_signature(chain), chain_res, self.check_validity(path),
                  self.check_hostname(leaf, hostname), self.check_integrity(leaf)]
        if chain_res.status == PASS:
            checks.append(self.check_revocation(path))
        else:
            checks.append(CheckResult("revocation", SKIP, "skipped: chain untrusted", 10))
        checks += [self.check_ct(leaf), self.check_strength(path)]

        score = round(sum(c.points for c in checks) / sum(c.weight for c in checks) * 100)
        failed = {c.name for c in checks if c.critical and c.status == FAIL}
        if not failed and score >= self.policy.threshold:
            level, reason = TRUSTED, "all critical checks passed"
        elif not failed:
            level, reason = SUSPICIOUS, f"trust score {score} below threshold {self.policy.threshold}"
        elif failed <= TRUST_ONLY_FAILURES:
            level = SUSPICIOUS
            reason = ("signatures are genuine but trust cannot be established: "
                      + ", ".join(sorted(failed)))
        else:
            level, reason = BLOCKED, "critical check failed: " + ", ".join(
                c.name for c in checks if c.name in failed)
        v = Verdict(hostname, checks, score, level, reason)
        (log.info if v.allow else log.warning)("%s %s: %s", level.upper(), hostname, reason)
        return v
