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
    APP = create_app(SVC)
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
        for name in ("rogue_ca", "revoked", "compromised_ca_misissue"):
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
        self.assertEqual(11, len(d["scenarios"]))
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
