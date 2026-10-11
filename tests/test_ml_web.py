import json
import logging
import os
import unittest

from certlab.ml import dataset
from certlab.ml.features import NAMES, extract, levenshtein, vector
from certlab.ml.model import METRICS_PATH, MODEL_PATH, RiskModel
from certlab.service import LabService
from certlab.web.app import create_app
from certlab.web.page import MARKER, fragment, with_data

logging.disable(logging.CRITICAL)
SVC = APP = CLIENT = RISK = None


def setUpModule():
    global SVC, APP, CLIENT, RISK
    assert os.path.exists(MODEL_PATH), "run: python -m certlab train"
    SVC = LabService()
    from certlab.web.app import RateLimiter
    APP = create_app(SVC)
    APP.limiter = RateLimiter({k: (10 ** 6, 1) for k in ("run", "live", "analyze")})   # limits tested separately
    CLIENT = APP.test_client()
    RISK = RiskModel()


def chain_of(name):
    s = SVC.lab.get(name)
    return [s.identity.cert, *s.identity.chain]


class Features(unittest.TestCase):
    def test_levenshtein(self):
        self.assertEqual(0, levenshtein("bank", "bank"))
        self.assertEqual(1, levenshtein("bank", "bamk"))
        self.assertEqual(4, levenshtein("", "bank"))

    def test_vector_shape_and_values(self):
        f = extract(chain_of("legitimate"), "bank.lab.test")
        self.assertEqual(set(NAMES), set(f))
        self.assertEqual(len(NAMES), len(vector(f)))
        self.assertEqual(1, f["host_match"])
        self.assertEqual(1, f["brand_exact"])
        self.assertEqual(0, f["self_signed"])

    def test_lookalike_features(self):
        f = extract(chain_of("legitimate"), "b4nk.lab.test")
        self.assertEqual(1, f["leet_swap"])
        self.assertEqual(1, f["brand_edit_dist"])
        f = extract(chain_of("legitimate"), "bank-secure.lab.test")
        self.assertEqual(1, f["brand_substring"])


class Model(unittest.TestCase):
    def test_metrics_file_is_sane(self):
        with open(METRICS_PATH) as fh:
            m = json.load(fh)
        self.assertGreater(m["random_forest"]["f1"], 0.95)
        self.assertLess(m["false_alarm"]["ml"], 0.05)
        self.assertGreater(m["catch_rate_macro"]["hybrid"], m["catch_rate_macro"]["rules"])
        self.assertGreater(m["catch_rate_macro"]["hybrid"], m["catch_rate_macro"]["ml"])

    def test_good_cert_low_risk_bad_certs_high_risk(self):
        self.assertLess(RISK.score(chain_of("legitimate"), "bank.lab.test")["risk"], 0.3)
        for name in ("self_signed", "expired", "not_yet_valid", "hostname_mismatch",
                     "cn_only_no_san", "weak_key", "weak_signature"):
            with self.subTest(name):
                self.assertTrue(RISK.score(chain_of(name), "bank.lab.test")["flag"])

    def test_blind_spots_are_documented_behaviour(self):
        # context-only attacks look normal on the wire: the model must not pretend to see them
        for name in ("rogue_ca", "revoked", "tampered", "compromised_ca_misissue"):
            with self.subTest(name):
                self.assertFalse(RISK.score(chain_of(name), "bank.lab.test")["flag"])

    def test_lookalike_domains_flagged_on_valid_certs(self):
        f = dataset.Factory(seed=99)
        hits = 0
        for _ in range(40):
            s = f.make("phishing_lookalike")
            hits += RISK.score(s.chain, s.host)["flag"]
        self.assertGreaterEqual(hits, 34)

    def test_explanation_names_the_cause(self):
        r = RISK.score(chain_of("hostname_mismatch"), "bank.lab.test")
        self.assertIn("host_match", [x["feature"] for x in r["reasons"]])


class Api(unittest.TestCase):
    def test_index_is_a_full_page(self):
        r = CLIENT.get("/")
        self.assertEqual(200, r.status_code)
        body = r.get_data(as_text=True)
        self.assertTrue(body.startswith("<!doctype html>"))
        self.assertIn("<title>Cert Guard Lab</title>", body)

    def test_state(self):
        d = CLIENT.get("/api/state").get_json()
        self.assertEqual(12, len(d["scenarios"]))
        self.assertTrue(d["ml_ready"])

    def test_run_attack_is_blocked_by_hybrid_and_leaks_to_naive(self):
        d = CLIENT.post("/api/run/rogue_ca").get_json()
        self.assertFalse(d["hybrid"]["allow"])
        self.assertTrue(d["clients"]["naive"]["leaked"])
        self.assertFalse(d["clients"]["guarded"]["connected"])

    def test_analyze_genuine_chain_allowed(self):
        d = CLIENT.post("/api/analyze", json={"pem": SVC.pem("legitimate"), "host": "bank.lab.test"}).get_json()
        self.assertTrue(d["hybrid"]["allow"])
        self.assertEqual(100, d["verdict"]["score"])

    def test_tampered_is_blocked_by_rules_while_ml_sees_nothing(self):
        d = CLIENT.post("/api/run/tampered").get_json()
        self.assertEqual("blocked", d["hybrid"]["level"])
        self.assertFalse(d["ml"]["flag"])
        self.assertTrue(d["clients"]["naive"]["leaked"])
        self.assertFalse(d["clients"]["guarded"]["connected"])

    def test_levels_exposed(self):
        self.assertEqual("suspicious", CLIENT.post("/api/run/rogue_ca").get_json()["hybrid"]["level"])
        self.assertEqual("trusted", CLIENT.post("/api/run/legitimate").get_json()["hybrid"]["level"])

    def test_run_legitimate_allowed(self):
        d = CLIENT.post("/api/run/legitimate").get_json()
        self.assertTrue(d["hybrid"]["allow"])
        self.assertFalse(d["via_mitm"])

    def test_unknown_scenario_404(self):
        self.assertEqual(404, CLIENT.post("/api/run/nope").status_code)

    def test_analyze_bad_input(self):
        self.assertEqual(400, CLIENT.post("/api/analyze", json={"pem": "garbage", "host": "x.test"}).status_code)
        self.assertEqual(400, CLIENT.post("/api/analyze", json={"pem": "", "host": "x.test"}).status_code)
        self.assertEqual(400, CLIENT.post("/api/analyze", json={"pem": SVC.pem("expired"), "host": ""}).status_code)
        self.assertEqual(400, CLIENT.post("/api/analyze", json={"pem": "A" * 70000, "host": "x.test"}).status_code)
        self.assertEqual(415, CLIENT.post("/api/analyze", data="pem=x").status_code)

    def test_analyze_attack_chain(self):
        d = CLIENT.post("/api/analyze", json={"pem": SVC.pem("revoked"), "host": "bank.lab.test"}).get_json()
        self.assertFalse(d["hybrid"]["allow"])
        self.assertIn("revocation", [c["name"] for c in d["verdict"]["checks"] if c["status"] == "fail"])

    def test_analyze_policy_toggle(self):
        pem = SVC.pem("compromised_ca_misissue")
        strict = CLIENT.post("/api/analyze", json={"pem": pem, "host": "bank.lab.test"}).get_json()
        lax = CLIENT.post("/api/analyze", json={"pem": pem, "host": "bank.lab.test", "require_ct": False}).get_json()
        self.assertFalse(strict["verdict"]["allow"])
        self.assertTrue(lax["verdict"]["allow"])


class LiveCheck(unittest.TestCase):
    def test_parse_target(self):
        from certlab.live import parse_target
        self.assertEqual(("example.com", 443), parse_target("Example.com"))
        self.assertEqual(("example.com", 8443), parse_target("https://example.com:8443/a/b"))
        for bad in ("", "   ", "not a host", "a" * 300 + ".com", "x.com:99999"):
            with self.subTest(bad[:12]):
                with self.assertRaises(ValueError):
                    parse_target(bad)

    def test_private_and_local_targets_refused(self):
        for t in ("localhost", "127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "[::1]"):
            with self.subTest(t):
                r = CLIENT.post("/api/live", json={"target": t})
                self.assertEqual(400, r.status_code, r.get_data(as_text=True))
                self.assertIn("private or local", r.get_json()["error"])

    def test_only_https_ports_and_json(self):
        self.assertEqual(400, CLIENT.post("/api/live", json={"target": "example.com:22"}).status_code)
        self.assertEqual(400, CLIENT.post("/api/live", json={"target": ""}).status_code)
        self.assertEqual(415, CLIENT.post("/api/live", data="target=example.com").status_code)

    def test_reads_a_real_tls_handshake_and_judges_it(self):
        from certlab import live as livemod
        from certlab.netlab import TLSServer
        chain_file, key_file = SVC.lab.paths(SVC.lab.get("legitimate"))
        with TLSServer(chain_file, key_file) as srv:
            got = livemod.fetch("127.0.0.1", srv.port, allow_private=True)
            self.assertEqual(3, len(got.chain))
            self.assertTrue(got.tls_version.startswith("TLS"))
            r = SVC.live(f"127.0.0.1:{srv.port}", _trust=SVC.lab.trust_store, _allow_private=True)
        checks = {c["name"]: c["status"] for c in r["verdict"]["checks"]}
        self.assertEqual("pass", checks["signature"])
        self.assertEqual("pass", checks["chain"])
        self.assertEqual("fail", checks["hostname"])      # we asked for an IP, the cert names bank.lab.test
        self.assertEqual("blocked", r["hybrid"]["level"])
        self.assertTrue(r["ml_advisory"])
        self.assertEqual(srv.port, r["live"]["port"])
        self.assertEqual(64 + 31, len(r["chain"][0]["sha256"]))   # full colon-separated SHA-256

    def test_live_ignores_ml_for_the_decision(self):
        from certlab.netlab import TLSServer
        chain_file, key_file = SVC.lab.paths(SVC.lab.get("legitimate"))
        with TLSServer(chain_file, key_file) as srv:
            r = SVC.live(f"127.0.0.1:{srv.port}", _trust=SVC.lab.trust_store, _allow_private=True)
        self.assertNotIn("rated high risk by ML", r["hybrid"]["reason"])


class Hardening(unittest.TestCase):
    def test_healthz_and_headers(self):
        r = CLIENT.get("/healthz")
        self.assertEqual({"ok": True, "ml_ready": True}, r.get_json())
        page = CLIENT.get("/")
        self.assertIn("default-src 'none'", page.headers["Content-Security-Policy"])
        self.assertEqual("DENY", page.headers["X-Frame-Options"])
        self.assertEqual("nosniff", page.headers["X-Content-Type-Options"])
        self.assertEqual("no-store", CLIENT.get("/api/state").headers["Cache-Control"])

    def test_rate_limiter_window(self):
        from certlab.web.app import RateLimiter
        t = [0.0]
        rl = RateLimiter({"x": (3, 10)}, clock=lambda: t[0])
        self.assertTrue(all(rl.allow("x", "a")[0] for _ in range(3)))
        ok, wait = rl.allow("x", "a")
        self.assertFalse(ok)
        self.assertGreater(wait, 0)
        self.assertTrue(rl.allow("x", "b")[0])           # other clients unaffected
        t[0] = 11.0
        self.assertTrue(rl.allow("x", "a")[0])           # window slid

    def test_endpoint_returns_429_with_retry_after(self):
        from certlab.web.app import RateLimiter, create_app
        app = create_app(SVC)
        app.limiter = RateLimiter({"run": (1, 60), "live": (1, 60), "analyze": (1, 60)})
        c = app.test_client()
        self.assertEqual(400, c.post("/api/analyze", json={"pem": "x", "host": "h.test"}).status_code)
        r = c.post("/api/analyze", json={"pem": "x", "host": "h.test"})
        self.assertEqual(429, r.status_code)
        self.assertIn("Retry-After", r.headers)


class StaticExport(unittest.TestCase):
    def test_embeds_data_and_escapes_script_end(self):
        page = with_data({"x": "</script><b>"})
        self.assertNotIn(MARKER, page)
        self.assertNotIn('"</script><b>"', page)
        self.assertIn("window.__STATIC__=", page)

    def test_fragment_has_marker(self):
        self.assertIn(MARKER, fragment())


if __name__ == "__main__":
    unittest.main()
