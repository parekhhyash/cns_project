"""Certificate Analysis Engine + Decision & Alerting.

Takes the certificate chain a server presented (leaf first) and runs independent
checks. Each check contributes to a trust score; a failed *critical* check, or a
score under the threshold, blocks the connection.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import logging
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID

log = logging.getLogger("certlab.decision")

PASS, WARN, FAIL, SKIP = "pass", "warn", "fail", "skip"


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
    allow: bool
    reason: str

    @property
    def failed(self) -> list[str]:
        return [c.name for c in self.checks if c.status == FAIL]

    def report(self) -> str:
        lines = [f"{'ALLOW' if self.allow else 'BLOCK'}  {self.hostname}  trust={self.score}/100  ({self.reason})"]
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


def issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """True if ``issuer``'s key produced ``cert``'s signature. Done by hand because
    ``verify_directly_issued_by`` refuses legacy hashes (SHA-1), and such certs
    should be reported as weak rather than crash path building."""
    if cert.issuer != issuer.subject:
        return False
    pub, h = issuer.public_key(), cert.signature_hash_algorithm
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), h)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(h))
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
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
                return path, f"no trusted issuer found for '{cur.issuer.rfc4514_string()}'"
            path.append(nxt)
            pool.remove(nxt)

    def check_chain(self, chain):
        path, err = self._build_path(chain)
        if err:
            return CheckResult("chain", FAIL, err, 30), path
        # every non-leaf must be a CA, and path-length constraints must hold
        for depth, c in enumerate(path[1:], start=0):
            try:
                bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
            except x509.ExtensionNotFound:
                return CheckResult("chain", FAIL, f"issuer '{c.subject.rfc4514_string()}' lacks BasicConstraints", 30), path
            if not bc.ca:
                return CheckResult("chain", FAIL, "issuer is not a CA", 30), path
            if bc.path_length is not None and depth > bc.path_length:
                return CheckResult("chain", FAIL, "path length constraint violated", 30), path
        return CheckResult("chain", PASS, f"anchored at '{path[-1].subject.rfc4514_string()}' ({len(path)} certs)", 30), path

    def check_validity(self, path):
        now = _utc(self.policy.now or dt.datetime.now(dt.timezone.utc))
        for c in path:
            nb, na = _utc(c.not_valid_before_utc), _utc(c.not_valid_after_utc)
            if now < nb:
                return CheckResult("validity", FAIL, f"not valid until {nb:%Y-%m-%d}", 20)
            if now > na:
                return CheckResult("validity", FAIL, f"expired {na:%Y-%m-%d}", 20)
        na = _utc(path[0].not_valid_after_utc)
        return CheckResult("validity", PASS, f"valid until {na:%Y-%m-%d}", 20)

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
            return CheckResult("hostname", FAIL, "no SubjectAltName (CN is not accepted)", 20)
        try:
            ip = ipaddress.ip_address(hostname)
            ok = ip in san.get_values_for_type(x509.IPAddress)
        except ValueError:
            ok = any(self._match(n, hostname) for n in san.get_values_for_type(x509.DNSName))
        names = ", ".join(san.get_values_for_type(x509.DNSName)) or "-"
        if ok:
            return CheckResult("hostname", PASS, f"'{hostname}' matches SAN [{names}]", 20)
        return CheckResult("hostname", FAIL, f"'{hostname}' not in SAN [{names}]", 20)

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

    def check_ct(self, leaf):
        if self.ct is None:
            return CheckResult("ct", SKIP, "no CT log configured", 15, self.policy.require_ct)
        if self.ct.contains(leaf):
            return CheckResult("ct", PASS, "present in CT log", 15, self.policy.require_ct)
        return CheckResult("ct", FAIL, "certificate not found in CT log", 15, self.policy.require_ct)

    def check_strength(self, path):
        p = self.policy
        for c in path:
            h = c.signature_hash_algorithm
            if h is None or isinstance(h, (hashes.MD5, hashes.SHA1)):
                return CheckResult("strength", FAIL, f"weak signature hash {getattr(h, 'name', 'none')}", 10)
            k = c.public_key()
            if isinstance(k, rsa.RSAPublicKey) and k.key_size < p.min_rsa_bits:
                return CheckResult("strength", FAIL, f"RSA-{k.key_size} below minimum {p.min_rsa_bits}", 10)
            if isinstance(k, ec.EllipticCurvePublicKey) and k.key_size < p.min_ec_bits:
                return CheckResult("strength", FAIL, f"EC-{k.key_size} below minimum {p.min_ec_bits}", 10)
        k = path[0].public_key()
        desc = f"RSA-{k.key_size}" if isinstance(k, rsa.RSAPublicKey) else f"EC-{getattr(k, 'key_size', '?')}"
        return CheckResult("strength", PASS, f"{desc}, {path[0].signature_hash_algorithm.name}", 10)

    # ---- decision ----------------------------------------------------------

    def analyze(self, chain: list[x509.Certificate], hostname: str) -> Verdict:
        if not chain:
            return Verdict(hostname, [], 0, False, "server presented no certificate")
        leaf = chain[0]
        chain_res, path = self.check_chain(chain)
        # Checks that depend on a trusted path only make sense once it exists,
        # but validity/hostname/strength are still reported on what we have.
        checks = [chain_res, self.check_validity(path), self.check_hostname(leaf, hostname)]
        if chain_res.status == PASS:
            checks.append(self.check_revocation(path))
        else:
            checks.append(CheckResult("revocation", SKIP, "skipped: chain untrusted", 10))
        checks += [self.check_ct(leaf), self.check_strength(path)]

        score = round(sum(c.points for c in checks) / sum(c.weight for c in checks) * 100)
        crit = [c for c in checks if c.critical and c.status == FAIL]
        # a skipped check on an untrusted chain contributes nothing and is not a pass
        if crit:
            allow, reason = False, "critical check failed: " + ", ".join(c.name for c in crit)
        elif score < self.policy.threshold:
            allow, reason = False, f"trust score {score} below threshold {self.policy.threshold}"
        else:
            allow, reason = True, "all critical checks passed"
        v = Verdict(hostname, checks, score, allow, reason)
        (log.info if allow else log.warning)("%s %s: %s", "ALLOW" if allow else "BLOCK", hostname, reason)
        return v
