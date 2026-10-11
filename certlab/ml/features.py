"""Turn (certificate chain, requested hostname) into a numeric feature vector.

Only information visible in the handshake is used. The trust store, CRL and CT log
are deliberately NOT inputs, so the model still works when those lookups are
unavailable (soft-fail revocation, offline device) and it complements the rule engine.
"""
from __future__ import annotations

import datetime as dt
import math
from collections import Counter

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID

from ..analyzer import Analyzer

# Names a user is likely to be tricked into visiting (the lab's "brands").
PROTECTED = ("bank", "pay", "mail", "shop", "login", "secure")
LAB_SUFFIX = ("lab", "test")

FEATURES = [
    ("self_signed", "Certificate signed by its own key"),
    ("chain_len", "Certificates sent by the server"),
    ("validity_days", "Total lifetime in days"),
    ("days_left", "Days until expiry (negative = expired)"),
    ("days_old", "Days since issued (negative = not yet valid)"),
    ("host_match", "Requested hostname is covered by the SAN"),
    ("has_san", "Has a SubjectAltName"),
    ("san_count", "Number of names in the SAN"),
    ("san_wildcard", "SAN contains a wildcard"),
    ("cn_in_san", "Common Name also listed in the SAN"),
    ("key_is_rsa", "RSA key (otherwise EC)"),
    ("key_bits", "Public key size in bits"),
    ("sig_weak", "MD5/SHA-1 signature"),
    ("has_eku", "Declares an Extended Key Usage"),
    ("has_ski", "Has a Subject Key Identifier"),
    ("has_aki", "Has an Authority Key Identifier"),
    ("leaf_is_ca", "Leaf certificate claims to be a CA"),
    ("host_len", "Length of the requested name"),
    ("host_depth", "Number of dots in the requested name"),
    ("host_entropy", "Character entropy of the name's first label"),
    ("host_digit_ratio", "Share of digits in the first label"),
    ("host_hyphens", "Hyphens in the first label"),
    ("brand_exact", "First label is exactly a protected name"),
    ("brand_edit_dist", "Edit distance to the closest protected name (9 = far)"),
    ("brand_substring", "First label contains a protected name but is not it"),
    ("leet_swap", "Digit that mimics a letter (0/o, 1/l, 3/e, 4/a)"),
]
NAMES = [n for n, _ in FEATURES]
DESCRIPTIONS = dict(FEATURES)


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _first_label(host: str) -> str:
    return host.lower().rstrip(".").split(".")[0]


def _ext(cert, cls):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def extract(chain: list[x509.Certificate], hostname: str, now: dt.datetime | None = None) -> dict:
    leaf = chain[0]
    now = now or dt.datetime.now(dt.timezone.utc)
    nb, na = leaf.not_valid_before_utc, leaf.not_valid_after_utc

    san = _ext(leaf, x509.SubjectAlternativeName)
    dns = san.get_values_for_type(x509.DNSName) if san else []
    cn = leaf.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    cn = cn[0].value if cn else ""

    pub = leaf.public_key()
    is_rsa = isinstance(pub, rsa.RSAPublicKey)
    bits = pub.key_size if isinstance(pub, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)) else 0
    h = leaf.signature_hash_algorithm
    bc = _ext(leaf, x509.BasicConstraints)

    label = _first_label(hostname)
    letters_digits = [c for c in label if c.isalnum()]
    dist = min((levenshtein(label, b) for b in PROTECTED), default=9)
    leet = 0
    if any(c.isdigit() for c in label) and any(c.isalpha() for c in label):
        # replace look-alike digits and see if the result is a protected name
        table = str.maketrans("0134", "olea")
        leet = int(label.translate(table) in PROTECTED or
                   any(levenshtein(label.translate(table), b) <= 1 for b in PROTECTED))

    return {
        "self_signed": int(leaf.issuer == leaf.subject),
        "chain_len": len(chain),
        "validity_days": (na - nb).days,
        "days_left": (na - now).days,
        "days_old": (now - nb).days,
        "host_match": int(any(Analyzer._match(n, hostname) for n in dns)),
        "has_san": int(bool(dns)),
        "san_count": len(dns),
        "san_wildcard": int(any(n.startswith("*") for n in dns)),
        "cn_in_san": int(cn in dns),
        "key_is_rsa": int(is_rsa),
        "key_bits": bits,
        "sig_weak": int(isinstance(h, (hashes.MD5, hashes.SHA1))),
        "has_eku": int(_ext(leaf, x509.ExtendedKeyUsage) is not None),
        "has_ski": int(_ext(leaf, x509.SubjectKeyIdentifier) is not None),
        "has_aki": int(_ext(leaf, x509.AuthorityKeyIdentifier) is not None),
        "leaf_is_ca": int(bool(bc and bc.ca)),
        "host_len": len(hostname),
        "host_depth": hostname.count("."),
        "host_entropy": round(_entropy(label), 3),
        "host_digit_ratio": round(sum(c.isdigit() for c in label) / max(len(label), 1), 3),
        "host_hyphens": label.count("-"),
        "brand_exact": int(label in PROTECTED),
        "brand_edit_dist": min(dist, 9),
        "brand_substring": int(label not in PROTECTED and any(b in label for b in PROTECTED)),
        "leet_swap": leet,
    }


def vector(feats: dict) -> list[float]:
    return [float(feats[n]) for n in NAMES]
