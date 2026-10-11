"""Synthetic training data: thousands of certificates from the lab PKI.

Every sample is (chain, requested hostname, label, kind). Labels come from how the
certificate was generated, not from the rule engine, so the model is not just
imitating the rules.

Training kinds are attacks that leave a trace in the certificate or hostname.
BLIND_KINDS (rogue CA, revoked, mis-issued) look identical to a good cert from the
handshake alone; they are held out of training and used to show the model's limits.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from ..certgen import (CTLog, Identity, issue_leaf, issue_sha1_leaf, make_ca, make_crl,
                       make_self_signed, new_key)
from .features import PROTECTED

TRAIN_ATTACKS = {
    "self_signed": "Self-signed certificate",
    "expired": "Expired certificate",
    "not_yet_valid": "Validity starts in the future",
    "hostname_mismatch": "Cert issued for a different host",
    "no_san": "No SubjectAltName",
    "weak_key": "RSA-1024 key",
    "weak_signature": "SHA-1 signature",
    "long_validity": "Lifetime far above the 398-day norm",
    "sloppy_issuance": "Missing key-usage and key-id extensions",
    "san_stuffing": "Dozens of unrelated names in one cert",
    "phishing_lookalike": "Valid cert for a look-alike domain",
}
BLIND_KINDS = {
    "rogue_ca": "Issued by a CA nobody trusts",
    "revoked": "Valid-looking cert that was revoked",
    "tampered": "Name edited after signing (signature no longer verifies)",
    "misissued_not_in_ct": "Trusted CA mis-issue never logged in CT",
}
ALL_KINDS = {"benign": "Legitimate certificate", **TRAIN_ATTACKS, **BLIND_KINDS}

COMMON = ["portal", "docs", "api", "status", "blog", "store", "support", "app", "cdn", "wiki",
          "mail", "shop", "login", "pay", "bank", "secure", "www", "admin", "intranet", "media"]
SUFFIXES = ["", "", "", "-eu", "-us", "-v2", "2", "-staging", "-01", "-dev"]
DOMAIN = "lab.test"


@dataclass
class Sample:
    chain: list
    host: str
    label: int
    kind: str
    cert_id: int = 0


class Factory:
    """Builds samples; owns the CAs, key pools, CT log and CRL for one dataset."""

    def __init__(self, seed: int = 7):
        self.rng = random.Random(seed)
        self.root = make_ca("Dataset Root CA", path_length=1)
        self.inter = make_ca("Dataset Intermediate CA", self.root, path_length=0)
        self.rogue_root = make_ca("Dataset Rogue Root", path_length=1)
        self.rogue_inter = make_ca("Dataset Rogue Issuer", self.rogue_root, path_length=0)
        self.ec = [new_key("ec") for _ in range(24)]
        self.rsa2048 = [new_key("rsa2048") for _ in range(3)]
        self.rsa3072 = [new_key("rsa3072")]
        self.rsa1024 = [new_key("rsa1024") for _ in range(3)]
        self.ct = CTLog("/nonexistent/ct.json")      # in-memory only, never saved
        self._ct_fps: set[str] = set()
        self.revoked: list[int] = []

    # --- name helpers -------------------------------------------------------
    def host(self) -> str:
        r = self.rng
        base = r.choice(COMMON)
        if base in PROTECTED:
            suffix = ""                       # protected names appear bare on legit certs
        else:
            suffix = r.choice(SUFFIXES)
        # a few legit names that merely *contain* a protected word
        if r.random() < 0.06:
            base, suffix = r.choice(["banking", "paypoint", "mailroom", "shopfront", "securelink"]), ""
        return f"{base}{suffix}.{DOMAIN}"

    def lookalike(self) -> str:
        r = self.rng
        brand = r.choice(PROTECTED)
        kind = r.choice(["typo", "leet", "extra", "swap", "hyphen"])
        if kind == "typo":                     # drop / duplicate / replace one character
            i = r.randrange(len(brand))
            op = r.choice(["drop", "dup", "sub"])
            if op == "drop" and len(brand) > 3:
                name = brand[:i] + brand[i + 1:]
            elif op == "dup":
                name = brand[:i] + brand[i] + brand[i:]
            else:
                name = brand[:i] + r.choice("abcdefghijklmnoprstuvw") + brand[i + 1:]
        elif kind == "leet":
            table = {"a": "4", "e": "3", "l": "1", "o": "0", "i": "1"}
            idx = [i for i, c in enumerate(brand) if c in table] or [0]
            i = r.choice(idx)
            name = brand[:i] + table.get(brand[i], "x") + brand[i + 1:]
        elif kind == "swap":
            name = brand.replace("m", "rn").replace("l", "i") if any(c in brand for c in "ml") \
                else brand + brand[-1]
        elif kind == "extra":
            name = brand + r.choice(["-secure", "-login", "-verify", "-support", "-account"])
        else:
            name = r.choice(["secure-", "my-", "update-"]) + brand
        if name in PROTECTED:
            name += "x"
        return f"{name}.{DOMAIN}"

    def random_host(self) -> str:
        return f"{self.rng.choice(['alpha', 'omega', 'nova', 'delta', 'orbit'])}{self.rng.randint(1, 99)}.{DOMAIN}"

    # --- certificate helpers ------------------------------------------------
    def good_key(self):
        r = self.rng.random()
        if r < 0.62:
            return self.rng.choice(self.ec)
        if r < 0.95:
            return self.rng.choice(self.rsa2048)
        return self.rng.choice(self.rsa3072)

    def typical_dates(self):
        valid = self.rng.choice([30, 60, 90, 90, 90, 180, 365, 397, 398, self.rng.randint(30, 398)])
        age = self.rng.randint(0, max(valid - 5, 1))
        return -age, valid

    def leaf(self, host, **kw):
        nb, valid = kw.pop("dates", None) or self.typical_dates()
        kw.setdefault("key", self.good_key())
        return issue_leaf(self.inter, host, not_before_days=nb, valid_days=valid, **kw)

    def _log(self, ident: Identity):
        self.ct.add(ident.cert)
        return ident

    def make(self, kind: str) -> Sample:
        r = self.rng
        host = self.host()
        label = int(kind != "benign")
        if kind == "benign":
            sans = [host]
            if r.random() < 0.3:
                sans += [self.random_host() for _ in range(r.randint(1, 5))]
            if r.random() < 0.12:
                sans = [f"*.{DOMAIN}"] + sans[:1]
            ident = self.leaf(host, sans=sans, eku=r.random() > 0.08, ids=r.random() > 0.05)
            ident = self._log(ident)
        elif kind == "self_signed":
            host = self.random_host() if r.random() < 0.5 else host
            ident = make_self_signed(host)
        elif kind == "expired":
            valid = r.choice([30, 90, 365, 397])
            ident = self.leaf(host, dates=(-(valid + r.randint(1, 250)), valid)); self._log(ident)
        elif kind == "not_yet_valid":
            ident = self.leaf(host, dates=(r.randint(1, 120), r.choice([90, 365]))); self._log(ident)
        elif kind == "hostname_mismatch":
            other = self.random_host() if r.random() < 0.6 else self.host()
            while other == host:
                other = self.random_host()
            ident = self.leaf(other); self._log(ident)
        elif kind == "no_san":
            ident = self.leaf(host, sans=[]); self._log(ident)
        elif kind == "weak_key":
            ident = self.leaf(host, key=r.choice(self.rsa1024)); self._log(ident)
        elif kind == "weak_signature":
            ident = issue_sha1_leaf(self.inter, host); self._log(ident)
        elif kind == "long_validity":
            valid = r.choice([r.randint(420, 825), r.randint(826, 3650), 3650])
            ident = self.leaf(host, dates=(-r.randint(0, 200), valid)); self._log(ident)
        elif kind == "sloppy_issuance":
            ident = self.leaf(host, eku=False, ids=False); self._log(ident)
        elif kind == "san_stuffing":
            sans = [host] + [f"{r.choice(COMMON)}{r.randint(1, 999)}.{r.choice(['lab.test', 'corp.test', 'edge.test'])}"
                             for _ in range(r.randint(12, 40))]
            ident = self.leaf(host, sans=sans); self._log(ident)
        elif kind == "phishing_lookalike":
            host = self.lookalike()
            ident = self.leaf(host); self._log(ident)
        elif kind == "rogue_ca":
            nb, valid = self.typical_dates()
            ident = issue_leaf(self.rogue_inter, host, key=self.good_key(),
                               not_before_days=nb, valid_days=valid)
        elif kind == "revoked":
            ident = self.leaf(host); self._log(ident)
            self.revoked.append(ident.cert.serial_number)
        elif kind == "tampered":
            target = r.choice(["bank", "mail", "shop", "blog", "wiki", "docs"])
            other = "".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(4))
            while other == target:
                other = "".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(4))
            orig = self._log(self.leaf(f"{other}.{DOMAIN}"))
            der = orig.cert.public_bytes(serialization.Encoding.DER)
            forged = x509.load_der_x509_certificate(
                der.replace(f"{other}.{DOMAIN}".encode(), f"{target}.{DOMAIN}".encode()))
            ident = Identity(forged, orig.key, orig.chain)
            host = f"{target}.{DOMAIN}"
        elif kind == "misissued_not_in_ct":
            ident = self.leaf(host)             # valid chain, never logged
        else:
            raise ValueError(kind)
        return Sample([ident.cert, *ident.chain], host, label, kind)

    def crl(self):
        return make_crl(self.inter, self.revoked)


def build(n_benign: int = 1500, n_attack: int = 130, n_blind: int = 70, seed: int = 7):
    """Returns (factory, train_kind_samples, blind_samples)."""
    f = Factory(seed)
    main = [f.make("benign") for _ in range(n_benign)]
    for k in TRAIN_ATTACKS:
        main += [f.make(k) for _ in range(n_attack if k != "weak_signature" else 70)]
    blind = [f.make(k) for k in BLIND_KINDS for _ in range(n_blind)]
    f.rng.shuffle(main)
    return f, main, blind
