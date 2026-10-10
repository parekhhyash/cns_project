"""Glue between the lab, the rule engine, the ML model and the web UI."""
from __future__ import annotations

import json
import os
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .analyzer import Analyzer, Policy, Verdict
from .certgen import HOST, Lab, fingerprint
from .ml.model import METRICS_PATH, MODEL_PATH, RiskModel
from .netlab import run_scenario

MAX_PEM_BYTES = 64 * 1024
MAX_CERTS = 8


def cert_info(c: x509.Certificate) -> dict:
    def cn(name):
        a = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return a[0].value if a else name.rfc4514_string()
    try:
        sans = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value \
            .get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    try:
        is_ca = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    k = c.public_key()
    if isinstance(k, rsa.RSAPublicKey):
        key = f"RSA-{k.key_size}"
    elif isinstance(k, ec.EllipticCurvePublicKey):
        key = f"EC {k.curve.name} ({k.key_size})"
    else:
        key = type(k).__name__
    h = c.signature_hash_algorithm
    return {
        "subject": cn(c.subject), "issuer": cn(c.issuer), "serial": f"{c.serial_number:x}"[:16],
        "not_before": c.not_valid_before_utc.strftime("%Y-%m-%d"),
        "not_after": c.not_valid_after_utc.strftime("%Y-%m-%d"),
        "sans": sans[:12], "san_total": len(sans), "is_ca": is_ca, "key": key,
        "signature": h.name if h else "none", "sha256": fingerprint(c)[:24],
    }


class LabService:
    def __init__(self, workdir: str | None = None):
        self.lab = Lab(workdir or tempfile.mkdtemp(prefix="certlab_web_"))
        self.risk = RiskModel(MODEL_PATH) if os.path.exists(MODEL_PATH) else None
        self.metrics = None
        if os.path.exists(METRICS_PATH):
            with open(METRICS_PATH) as f:
                self.metrics = json.load(f)
        self._lock = threading.Lock()   # scenarios open sockets; keep them one at a time

    # ---- shared pieces ------------------------------------------------------
    def analyzer(self, policy: Policy | None = None) -> Analyzer:
        return Analyzer(self.lab.trust_store, crls=[self.lab.crl], ct_log=self.lab.ct, policy=policy)

    def _verdict(self, v: Verdict) -> dict:
        return {"allow": v.allow, "score": v.score, "reason": v.reason,
                "checks": [{"name": c.name, "status": c.status, "detail": c.detail,
                            "weight": c.weight, "critical": c.critical} for c in v.checks]}

    def _assess(self, chain, host, verdict: Verdict) -> dict:
        ml = self.risk.score(chain, host) if self.risk else None
        rules_ok = verdict.allow
        ml_ok = not (ml and ml["flag"])
        if rules_ok and ml_ok:
            h = {"allow": True, "reason": "Rules passed and ML risk is low"}
        elif not rules_ok and ml_ok:
            h = {"allow": False, "reason": "Blocked by the rule engine"}
        elif rules_ok and not ml_ok:
            h = {"allow": False, "reason": "Rules passed, but the ML model rates it high risk"}
        else:
            h = {"allow": False, "reason": "Blocked by the rules and rated high risk by ML"}
        return {"verdict": self._verdict(verdict), "ml": ml, "hybrid": h,
                "chain": [cert_info(c) for c in chain], "host": host}

    # ---- API ------------------------------------------------------------------
    def state(self) -> dict:
        return {
            "host": HOST,
            "scenarios": [{"name": s.name, "description": s.description, "expect": s.expect,
                           "expected_failures": list(s.expected_failures)} for s in self.lab.scenarios],
            "ml_ready": self.risk is not None,
            "live": True,
        }

    def pem(self, name: str) -> str:
        return self.lab.get(name).identity.chain_pem().decode()

    def run(self, name: str) -> dict:
        sc = self.lab.get(name)
        with self._lock:
            o = run_scenario(self.lab, sc, via_mitm=(name != "legitimate"))
        chain = [sc.identity.cert, *sc.identity.chain]
        out = self._assess(chain, HOST, o.verdict)
        out.update({
            "scenario": {"name": sc.name, "description": sc.description, "expect": sc.expect},
            "via_mitm": name != "legitimate",
            "clients": {
                "naive": {"connected": o.naive.connected, "leaked": o.naive_leaked},
                "stdlib": {"connected": o.stdlib.connected, "error": o.stdlib.error[:140]},
                "guarded": {"connected": o.guarded.connected, "error": o.guarded.error[:140]},
            }})
        return out

    def analyze(self, pem: str, host: str, *, require_ct: bool = True,
                revocation_hard_fail: bool = True) -> dict:
        data = pem.encode()
        if not data.strip():
            raise ValueError("Paste at least one PEM certificate.")
        if len(data) > MAX_PEM_BYTES:
            raise ValueError("Input is too large (limit 64 KB).")
        host = (host or "").strip()
        if not host or len(host) > 253 or any(c.isspace() for c in host):
            raise ValueError("Enter the hostname the client was trying to reach.")
        try:
            chain = x509.load_pem_x509_certificates(data)
        except ValueError:
            raise ValueError("Could not read a PEM certificate. Paste text starting with "
                             "-----BEGIN CERTIFICATE-----.") from None
        if len(chain) > MAX_CERTS:
            raise ValueError(f"At most {MAX_CERTS} certificates per chain.")
        v = self.analyzer(Policy(require_ct=require_ct,
                                 revocation_hard_fail=revocation_hard_fail)).analyze(chain, host)
        return self._assess(chain, host, v)

    def export(self) -> dict:
        """Everything the static page needs; runs each scenario once, live."""
        runs = {s.name: self.run(s.name) for s in self.lab.scenarios}
        st = self.state()
        st["live"] = False
        return {"state": st, "runs": runs, "ml": self.metrics,
                "pems": {s.name: self.pem(s.name) for s in self.lab.scenarios}}
