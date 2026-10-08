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
| (4) Decision & Alerting Module | `Analyzer.analyze` -> `Verdict` (allow/block, reason, log record) |

```
Cert generation -> deploy on lab server -> MITM presents cert to client
   -> guarded client reads chain after handshake, BEFORE sending app data
   -> Analyzer: chain | validity | hostname/SAN | revocation | CT | strength
   -> trust score + critical-check gate -> ALLOW or BLOCK + log
```

### Checks and trust score

| Check | Weight | Notes |
|---|---|---|
| chain | 30 | signature-verified path to the trust store; CA flag + path-length enforced. A root shipped by the server is never trusted |
| validity | 20 | every cert in the path, injectable clock for testing |
| hostname | 20 | SAN only (CN ignored, per RFC 6125); wildcard = one label |
| revocation | 10 | signed, non-stale CRL; hard-fail by default (policy can soft-fail) |
| ct | 15 | cert must be in the CT log (`Policy.require_ct`) |
| strength | 10 | rejects MD5/SHA-1, RSA < 2048, EC < 256 |

Any failed critical check blocks; otherwise the score must be >= `Policy.threshold` (80).

### Scenarios generated

`legitimate`, `self_signed`, `expired`, `not_yet_valid`, `hostname_mismatch`,
`cn_only_no_san`, `rogue_ca`, `revoked`, `weak_key` (RSA-1024), `weak_signature` (SHA-1),
`compromised_ca_misissue` (valid chain from a trusted CA, never logged in CT; the DigiNotar pattern).

## Usage

```bash
pip install -r requirements.txt          # cryptography; the SHA-1 cert needs the openssl CLI
python -m certlab demo -v                # run all scenarios through MITM and 3 clients
python -m certlab generate lab_out       # write CA/leaf/CRL/CT PEM+JSON (usable with openssl s_server, mitmproxy)
python -m certlab analyze 127.0.0.1:8443 --sni bank.lab.test --lab-dir lab_out   # vet any TLS endpoint
python -m unittest discover -s tests -t .
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
