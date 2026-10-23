# Crypto Graphers: Certificate Validation Testbed (CE305/CS305, ACNS-DC 2026-27)

A controlled PKI lab plus a certificate analysis engine, implementing the proposal
in *"Problem Understanding & Solution Approach"*. It shows the difference between a
connection that merely looks encrypted and one whose certificate has actually been
verified. **Everything runs on 127.0.0.1 with private lab CAs; nothing touches the public PKI.**

## Architecture (maps to the proposal's 5 steps)

| Proposal component | Code |
|---|---|
| (1) Certificate Generator: legitimate + malicious certs | `certlab/certgen.py` (`Lab`, `make_ca`, `issue_leaf`, ...) |
| Step 2: simulated deployment on isolated servers | `certlab/netlab.py` `TLSServer` |
| (2) MITM Simulation Module | `certlab/netlab.py` `MitmProxy` (TLS-terminating attacker proxy) |
| (3) Certificate Analysis Engine | `certlab/analyzer.py` `Analyzer` |
| (4) Decision & Alerting Module | `Analyzer.analyze` -> `Verdict` (trusted/suspicious/blocked, reason, log record); `certlab/service.py` combines it with the ML score |
| Frontend + ML (extension) | `certlab/web/` (Flask + single-page UI), `certlab/ml/` (features, dataset, model) |

```
Cert generation -> deploy on lab server -> MITM presents cert to client
   -> guarded client reads chain after handshake, BEFORE sending app data
   -> Analyzer: chain | validity | hostname/SAN | revocation | CT | strength
   -> trust score + critical-check gate -> ALLOW or BLOCK + log
```

### Checks, trust score and the three verdicts

| Check | Weight | What it does |
|---|---|---|
| signature | 20 | every certificate's signature is verified with its issuer's public key (ECDSA, RSA incl. PSS, Ed25519). Says nothing about trust |
| chain | 20 | signature-verified path to the trust store; CA flag + path-length enforced. A root shipped by the server is never trusted |
| validity | 15 | every cert in the path, injectable clock for testing |
| hostname | 15 | SAN only (CN ignored, per RFC 6125); wildcard = one label |
| integrity | 5 | SHA-256 fingerprint compared with what the CA recorded for that serial; skipped (weight 0) when there is no record |
| revocation | 10 | signed, non-stale CRL; hard-fail by default (policy can soft-fail) |
| ct | 10 | in the CT log, or carries embedded signed certificate timestamps (`Policy.require_ct`) |
| strength | 5 | rejects MD5/SHA-1, RSA < 2048, EC < 256 |

* **TRUSTED:** every critical check passed and the score is at least 80.
* **SUSPICIOUS:** the signatures are genuine but trust cannot be established (self-signed, unknown issuer, never logged). Held back, not proven malicious.
* **BLOCKED:** a signature fails, the certificate was modified, it is expired or for the wrong host, revoked, or cryptographically weak.

A valid signature never means trusted: `signature` and `chain` are separate checks.

### Scenarios generated

`legitimate`, `self_signed`, `expired`, `not_yet_valid`, `hostname_mismatch`,
`cn_only_no_san`, `rogue_ca`, `revoked`, `weak_key` (RSA-1024), `weak_signature` (SHA-1),
`compromised_ca_misissue` (valid chain from a trusted CA, never logged in CT; the DigiNotar pattern),
and `tampered` (a real certificate the CA issued for another site, with its name edited to the bank's:
the hostname and dates look perfect, but the signature no longer verifies and the SHA-256 differs from the CA's record).
Expected levels: self-signed, rogue CA and mis-issued are *suspicious*; every other attack is *blocked*.

## Web app and ML model

```bash
pip install -r requirements.txt   # the SHA-1 test certificate also needs the openssl CLI
python -m certlab serve            # http://127.0.0.1:5000  (localhost only)
python -m certlab train            # regenerate dataset, retrain, rewrite certlab/ml/{model.joblib,metrics.json}
python -m certlab check example.com  # Mode 1: read a real server's certificate and judge it
python -m certlab export page.html # self-contained snapshot of every result (no server needed)
```

The UI has four tabs: **Overview** (headline results and the 5-step pipeline), **Attack lab**
(pick any of the 12 certificates, see what each client did, the six rule checks, the ML risk score
and the final decision), **Check a certificate** (Mode 1: type a real domain; Mode 2: paste a PEM chain; same report either way) and **ML model** (metrics, per-attack comparison, confusion matrix, ROC, feature importance).

### The ML component

A random forest scores risk from 26 features of the certificate and the requested hostname
(`certlab/ml/features.py`): lifetime, days left, SAN size, key size, signature hash, missing
extensions, hostname/SAN match, and name features such as edit distance to a protected name
(`b4nk`, `bamk`, `bank-secure`). It is deliberately **blind to the trust store, CRL and CT log**, so it
still works when those lookups are unavailable and complements the rule engine instead of copying it.

Training data (`certlab/ml/dataset.py`) is generated from the lab PKI: about 1,500 good certificates and
11 attack types (about 130 each). Labels come from how each certificate was generated, not from the rules.
Four attack types that look identical to a good certificate in the handshake fields (rogue CA, revoked,
tampered, mis-issued and not logged) are held out as **blind spots** to show where the model cannot help.

Latest run (seed 7, 25% held-out test set, 5-fold CV on the rest):

| | Rules | ML | Rules + ML |
|---|---|---|---|
| Average catch rate over 15 attack types | 73% | 73% | 99.8% |
| Good certificates wrongly blocked | 0% | 1.1% | 1.1% |

ML alone: F1 0.993, ROC AUC 0.997, CV F1 0.992 (logistic regression baseline: F1 0.79).
The model catches what the rules never look at (long lifetimes, missing extensions, SAN stuffing,
look-alike domains: 0% by rules), while the rules catch what the model cannot see (rogue CA, revoked,
tampered, mis-issued: 0% by ML). The final decision allows a connection only if both agree.

**Read the numbers with care:** the training and test sets come from the same generator, so they measure
how well the model learned this lab's attack patterns, not how it would do on internet traffic.
`model.joblib` is a pickle; only load model files you trained yourself, and retrain after changing
scikit-learn versions.

### API

| Route | Purpose |
|---|---|
| `GET /api/export` | every scenario run once (cached): verdicts, ML scores, client outcomes |
| `POST /api/run/<scenario>` | re-run one attack against the lab servers |
| `POST /api/live` | `{target}`: one read-only handshake with a real public server, judged against this computer's trusted roots (ports 443/8443, private addresses refused) |
| `POST /api/analyze` | `{pem, host, require_ct, revocation_hard_fail}` -> verdict + ML + hybrid decision |
| `GET /api/ml`, `/api/state`, `/api/pem/<scenario>` | metrics, scenario list, chain PEM |

### Live mode

`python -m certlab check DOMAIN` (and the web UI's Mode 1) opens one TLS handshake with verification off only to *read*
the chain, sends no data, and closes. The chain is then judged by the same engine against the operating system's
trusted roots. No CRL or CT server is queried, so revocation is a soft-fail warning and CT passes only when the
certificate carries embedded timestamps. The ML score is shown for reference but never changes a live decision,
because it was trained on lab certificates. Loopback, private and link-local targets are refused, and the check
follows `HTTPS_PROXY` when set. If a network sits in the middle and re-signs TLS (corporate proxies, this
development sandbox), the chain will anchor at *that* CA, which is exactly what the tool is meant to reveal.

The server binds to 127.0.0.1, accepts JSON only on POST routes, caps request size, and never
executes anything from uploaded certificates.

## CLI

```bash
python -m certlab demo -v                      # every scenario through MITM + 3 clients, with full reports
python -m certlab generate lab_out             # write CA/leaf/CRL/CT files (PEM/JSON) for openssl or mitmproxy
python -m certlab analyze 127.0.0.1:8443 --sni bank.lab.test --lab-dir lab_out   # a local lab server
python -m unittest discover -s tests -t .      # 44 tests
```

The demo compares three clients per scenario: **naive** (validation disabled, as in
weak mobile/IoT apps), **stdlib** (Python default validation, baseline), and **guarded**
(chain vetted by the analyzer before any data is sent). Typical result: naive leaks
credentials to the MITM in every attack; stdlib still accepts `revoked`,
`cn_only_no_san` and `compromised_ca_misissue`; guarded blocks all 10 attacks.

## Scope and honest limitations

- **CT log** is a local hash-chained JSON log standing in for public CT logs / embedded SCTs.
- **Revocation** uses a local signed CRL; there is no OCSP responder or stapling yet.
- **MITM** is an in-process proxy rather than mitmproxy/bettercap, so the lab is self-contained
  and deterministic. Certs from `generate` can be loaded into those tools for a lab LAN.
- The guard needs a second look at the handshake: the client completes TLS with verification off
  only to read the chain, sends no application data until approved, then closes on BLOCK.
  A production integration would hook the verify callback / proxy instead.
- DANE/TLSA is out of scope (not enforced by mainstream browsers; needs DNSSEC).

---

## Team Members

| Sr. No. | Name |  UID |
|---|---|---|
| 1 | Darsh Sharma | 2024300235 |

