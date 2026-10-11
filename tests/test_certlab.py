import datetime as dt
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

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
                self.assertEqual(sc.level, v.level, v.report())
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


class SignatureAndLevels(unittest.TestCase):
    def verdict(self, name, **kw):
        sc = LAB.get(name)
        return make_analyzer(LAB, **kw).analyze([sc.identity.cert, *sc.identity.chain], "bank.lab.test")

    @staticmethod
    def status(v, check):
        return next(c.status for c in v.checks if c.name == check)

    def test_tampered_cert_fails_signature_and_integrity_only_on_those(self):
        v = self.verdict("tampered")
        self.assertEqual("blocked", v.level)
        self.assertEqual("fail", self.status(v, "signature"))
        self.assertEqual("fail", self.status(v, "integrity"))
        # the forged fields look perfect: that is exactly why a signature check is needed
        self.assertEqual("pass", self.status(v, "hostname"))
        self.assertEqual("pass", self.status(v, "validity"))

    def test_valid_signature_is_not_the_same_as_trust(self):
        for name in ("self_signed", "rogue_ca"):
            with self.subTest(name):
                v = self.verdict(name)
                self.assertEqual("pass", self.status(v, "signature"))
                self.assertEqual("fail", self.status(v, "chain"))
                self.assertEqual("suspicious", v.level)
                self.assertFalse(v.allow)

    def test_integrity_passes_for_genuine_and_skips_without_a_record(self):
        self.assertEqual("pass", self.status(self.verdict("legitimate"), "integrity"))
        v = Analyzer(LAB.trust_store, crls=[LAB.crl], ct_log=None,
                     policy=Policy(require_ct=False)).analyze(
            [LAB.get("legitimate").identity.cert, *LAB.get("legitimate").identity.chain], "bank.lab.test")
        self.assertEqual("skip", self.status(v, "integrity"))
        self.assertTrue(v.allow)

    def test_any_flipped_byte_breaks_signature(self):
        sc = LAB.get("legitimate")
        der = bytearray(sc.identity.cert.public_bytes(serialization.Encoding.DER))
        der[len(der) // 3] ^= 0x01          # somewhere inside the signed body
        try:
            forged = x509.load_der_x509_certificate(bytes(der))
        except ValueError:
            self.skipTest("flip produced unparsable DER")
        v = make_analyzer(LAB).analyze([forged, *sc.identity.chain], "bank.lab.test")
        self.assertFalse(v.allow)

    def test_ed25519_chain_is_verified_and_not_called_weak(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from certlab.certgen import make_ca
        root_key = ed25519.Ed25519PrivateKey.generate()
        import datetime as dt
        now = dt.datetime.now(dt.timezone.utc)
        name = lambda cn: x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])
        root = (x509.CertificateBuilder().subject_name(name("Ed Root")).issuer_name(name("Ed Root"))
                .public_key(root_key.public_key()).serial_number(1)
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(root_key, None))
        leaf_key = ed25519.Ed25519PrivateKey.generate()
        leaf = (x509.CertificateBuilder().subject_name(name("ed.test")).issuer_name(root.subject)
                .public_key(leaf_key.public_key()).serial_number(2)
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("ed.test")]), False)
                .sign(root_key, None))
        v = Analyzer([root], policy=Policy(require_ct=False, revocation_hard_fail=False)).analyze([leaf], "ed.test")
        self.assertEqual("pass", self.status(v, "signature"), v.report())
        self.assertEqual("pass", self.status(v, "strength"), v.report())
        self.assertTrue(v.allow, v.report())


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
