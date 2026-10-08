import datetime as dt
import tempfile
import unittest

from certlab.analyzer import Analyzer, Policy
from certlab.certgen import CTLog, Lab
from certlab.netlab import (MitmProxy, TLSServer, guarded_client, make_analyzer,
                            naive_client, run_scenario)

LAB = None


def setUpModule():
    global LAB
    LAB = Lab(tempfile.mkdtemp(prefix="certlab_test_"))


class AnalyzerScenarios(unittest.TestCase):
    """Offline: every scenario gets the expected decision and failing checks."""

    def test_all_scenarios(self):
        an = make_analyzer(LAB)
        for sc in LAB.scenarios:
            with self.subTest(sc.name):
                chain = [sc.identity.cert, *sc.identity.chain]
                v = an.analyze(chain, "bank.lab.test")
                self.assertEqual("allow" if v.allow else "block", sc.expect, v.report())
                for f in sc.expected_failures:
                    self.assertIn(f, v.failed, v.report())

    def test_legitimate_scores_100(self):
        sc = LAB.get("legitimate")
        v = make_analyzer(LAB).analyze([sc.identity.cert, *sc.identity.chain], "bank.lab.test")
        self.assertEqual(100, v.score)

    def test_wrong_host_requested(self):
        sc = LAB.get("legitimate")
        v = make_analyzer(LAB).analyze([sc.identity.cert, *sc.identity.chain], "other.lab.test")
        self.assertIn("hostname", v.failed)

    def test_validity_uses_injected_clock(self):
        sc = LAB.get("legitimate")
        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=400)
        an = make_analyzer(LAB, policy=Policy(now=future))
        v = an.analyze([sc.identity.cert, *sc.identity.chain], "bank.lab.test")
        self.assertIn("validity", v.failed)

    def test_revocation_soft_vs_hard_fail(self):
        sc = LAB.get("legitimate")
        chain = [sc.identity.cert, *sc.identity.chain]
        hard = Analyzer(LAB.trust_store, crls=[], ct_log=LAB.ct).analyze(chain, "bank.lab.test")
        self.assertFalse(hard.allow)
        soft = Analyzer(LAB.trust_store, crls=[], ct_log=LAB.ct,
                        policy=Policy(revocation_hard_fail=False)).analyze(chain, "bank.lab.test")
        self.assertTrue(soft.allow)
        self.assertLess(soft.score, 100)

    def test_ct_optional_by_policy(self):
        sc = LAB.get("compromised_ca_misissue")
        chain = [sc.identity.cert, *sc.identity.chain]
        an = make_analyzer(LAB, policy=Policy(require_ct=False))
        self.assertTrue(an.analyze(chain, "bank.lab.test").allow)

    def test_untrusted_anchor_even_if_server_sends_root(self):
        # attacker ships its own root in the chain: must still be rejected
        sc = LAB.get("rogue_ca")
        v = make_analyzer(LAB).analyze([sc.identity.cert, *sc.identity.chain], "bank.lab.test")
        self.assertIn("chain", v.failed)

    def test_empty_chain_blocked(self):
        self.assertFalse(make_analyzer(LAB).analyze([], "x").allow)

    def test_wildcard_matches_one_label_only(self):
        m = Analyzer._match
        self.assertTrue(m("*.lab.test", "bank.lab.test"))
        self.assertFalse(m("*.lab.test", "a.bank.lab.test"))
        self.assertFalse(m("*.lab.test", "lab.test"))


class CTLogTests(unittest.TestCase):
    def test_integrity_and_tamper_detection(self):
        self.assertTrue(LAB.ct.verify_integrity())
        log = CTLog(LAB.ct.path)
        log.entries[0]["fingerprint"] = "00" * 32
        self.assertFalse(log.verify_integrity())


class EndToEnd(unittest.TestCase):
    """Real TLS sockets on loopback."""

    def test_direct_legitimate_connection_allowed(self):
        o = run_scenario(LAB, LAB.get("legitimate"), via_mitm=False)
        self.assertTrue(o.guarded.connected)
        self.assertTrue(o.stdlib.connected)

    def test_mitm_leaks_to_naive_client_but_not_guarded(self):
        real_chain, real_key = LAB.paths(LAB.get("legitimate"))
        atk_chain, atk_key = LAB.paths(LAB.get("rogue_ca"))
        an = make_analyzer(LAB)
        with TLSServer(real_chain, real_key) as bank, \
                MitmProxy(atk_chain, atk_key, bank.port) as mitm:
            g = guarded_client(mitm.port, an)
            self.assertFalse(g.connected)
            self.assertEqual([], mitm.captured, "guard must not send data before approval")
            n = naive_client(mitm.port)
            self.assertTrue(n.connected)
            self.assertTrue(any(b"password=" in c for c in mitm.captured))

    def test_every_attack_blocked_and_never_leaks_via_guard(self):
        for sc in LAB.scenarios:
            if sc.expect != "block":
                continue
            with self.subTest(sc.name):
                o = run_scenario(LAB, sc)
                self.assertFalse(o.guarded.connected, o.verdict.report())
                self.assertTrue(o.naive_leaked)


if __name__ == "__main__":
    unittest.main()
