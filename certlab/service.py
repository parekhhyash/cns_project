"""Glue between the lab, the rule engine, the ML model and the web UI."""
from __future__ import annotations

import json
import os
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .analyzer import Analyzer, Policy, Verdict, pretty_fingerprint
from . import live as livemod
from .certgen import HOST, Lab
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
        "signature": h.name if h else c.signature_algorithm_oid._name, "sha256": pretty_fingerprint(c),
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
        self._live_lock = threading.Lock()

    # ---- shared pieces ------------------------------------------------------
    def analyzer(self, policy: Policy | None = None) -> Analyzer:
        return Analyzer(self.lab.trust_store, crls=[self.lab.crl], ct_log=self.lab.ct, policy=policy)

    def _verdict(self, v: Verdict) -> dict:
        return {"allow": v.allow, "level": v.level, "score": v.score, "reason": v.reason,
                "checks": [{"name": c.name, "status": c.status, "detail": c.detail,
                            "weight": c.weight, "critical": c.critical} for c in v.checks]}

    def _assess(self, chain, host, verdict: Verdict, *, use_ml: bool = True) -> dict:
        """Rules first; the ML score can only make a trusted verdict more cautious."""
        ml = self.risk.score(chain, host) if self.risk else None
        flagged = bool(use_ml and ml and ml["flag"])
        if verdict.level == "blocked":
            level, why = "blocked", "Blocked by the rule engine" + (" and rated high risk by ML" if flagged else "")
        elif verdict.level == "suspicious":
            level, why = "suspicious", "Held back: not trusted by the rule engine" + (" and rated high risk by ML" if flagged else "")
        elif flagged:
            level, why = "suspicious", "Rules passed, but the ML model rates it high risk"
        else:
            level, why = "trusted", "Rules passed and ML risk is low" if use_ml else "All rule checks passed"
        return {"verdict": self._verdict(verdict), "ml": ml, "ml_advisory": not use_ml,
                "hybrid": {"level": level, "allow": level == "trusted", "reason": why},
                "chain": [cert_info(c) for c in chain], "host": host}

    # ---- API ------------------------------------------------------------------
    def state(self) -> dict:
        return {
            "host": HOST,
            "scenarios": [{"name": s.name, "description": s.description, "expect": s.expect,
                           "level": s.level, "expected_failures": list(s.expected_failures)}
                          for s in self.lab.scenarios],
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

    def live(self, target: str, *, _trust=None, _allow_private: bool = False) -> dict:
        """Mode 1: read a real server's certificate chain and judge it. The underscore
        arguments exist for tests (a local server and a lab trust store)."""
        host, port = livemod.parse_target(target)
        with self._live_lock:
            got = livemod.fetch(host, port, allow_private=_allow_private)
        trust = list(_trust if _trust is not None else livemod.system_trust())
        policy = Policy(require_ct=False, revocation_hard_fail=False)  # no CRL/CT servers to ask
        v = Analyzer(trust, policy=policy).analyze(got.chain, host)
        out = self._assess(got.chain, host, v, use_ml=False)
        out["live"] = {"host": host, "port": port, "ip": got.ip, "tls": got.tls_version,
                       "cipher": got.cipher, "proxied": got.proxied, "trusted_roots": len(trust),
                       "sent": len(got.chain)}
        return out

    def export(self) -> dict:
        """Everything the static page needs; runs each scenario once, live."""
        runs = {s.name: self.run(s.name) for s in self.lab.scenarios}
        st = self.state()
        st["live"] = False
        return {"state": st, "runs": runs, "ml": self.metrics,
                "pems": {s.name: self.pem(s.name) for s in self.lab.scenarios}}
