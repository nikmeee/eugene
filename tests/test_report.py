import unittest

from eugene.doctor import Doctor
from eugene.report import FAIL, WARN, Report, reason_of, score_network, to_json


class ScoreTests(unittest.TestCase):
    def test_clean_network_is_100(self):
        self.assertEqual(score_network([], {}), 100)

    def test_warn_and_fail_penalties(self):
        self.assertEqual(score_network([(WARN, "a", "b")], {}), 93)
        self.assertEqual(score_network([(WARN, "a", "b"), (WARN, "c", "d")], {}), 86)
        self.assertEqual(score_network([(FAIL, "a", "b"), (WARN, "c", "d")], {}), 71)

    def test_ok_finding_does_not_change_score(self):
        self.assertEqual(score_network([("ok", "VPN выручает", "tip")], {}), 100)

    def test_dead_link_caps_at_zero(self):
        nodes = {"link": {"status": FAIL}}
        self.assertEqual(score_network([], nodes), 0)

    def test_dead_isp_caps_below_the_finding_penalty(self):
        nodes = {"isp": {"status": FAIL}}
        self.assertEqual(score_network([(FAIL, "нет интернета", "tip")], nodes), 10)

    def test_captive_portal_caps_at_20(self):
        self.assertEqual(score_network([], {}, captive=True), 20)

    def test_router_latency_penalty(self):
        self.assertEqual(score_network([], {}, router_ping={"avg": 20}), 95)

    def test_no_access_is_unscored(self):
        self.assertIsNone(score_network([(FAIL, "x", "y")], {"link": {"status": FAIL}}, no_access="EPERM"))

    def test_many_failures_do_not_go_negative(self):
        findings = [(FAIL, "x", "y")] * 10
        self.assertEqual(score_network(findings, {}), 0)


class FinishTests(unittest.TestCase):
    def test_finish_uses_the_same_score(self):
        doc = Doctor()
        doc.finding(FAIL, "Нет интернета за роутером", "Перезагрузи роутер")
        doc.node("isp", FAIL, "нет связи")
        doc.finish()
        self.assertEqual(doc.report.score, 10)
        self.assertEqual(doc.report.headline, "Нет интернета за роутером")
        self.assertEqual(doc.report.mood, "sad")
        self.assertTrue(doc.report.done)

    def test_healthy_finish(self):
        doc = Doctor()
        doc.finish()
        self.assertEqual(doc.report.score, 100)
        self.assertEqual(doc.report.mood, "happy")
        self.assertEqual(doc.report.headline, "Сеть здорова, как краб в отпуске!")

    def test_snapshot_does_not_follow_later_writes(self):
        doc = Doctor()
        doc.finding(WARN, "слабо", "подойди")
        snap = doc.snapshot()
        doc.finding(FAIL, "пропало", "перезагрузи")
        self.assertEqual(len(snap.findings), 1)
        self.assertEqual(len(doc.report.findings), 2)


class JsonTests(unittest.TestCase):
    def test_vpn_off_shape(self):
        rep = Report(score=71, headline="нюансы", phys="en0", gw="192.168.1.1",
                     findings=[(WARN, "Слабый сигнал", "Подойди ближе")], sys_dns="192.168.1.1")
        data = to_json(rep)
        self.assertEqual(data["score"], 71)
        self.assertEqual(data["interface"], "en0")
        self.assertEqual(data["vpn"], {"active": False})
        self.assertEqual(data["dns"], {"system": "192.168.1.1"})
        self.assertEqual(data["findings"][0]["tip"], "Подойди ближе")
        self.assertIsNone(data["router_ping"])

    def test_site_error_carries_reason(self):
        bad = {"error": "домен не резолвится", "stage": "dns", "status": None,
               "dns": None, "tcp": None, "tls": None, "http": None}
        data = to_json(Report(site_results=[("Яндекс", "ya.ru", None, bad)]))
        site = data["sites"]["Яндекс"]
        self.assertIsNone(site["via_vpn"])
        self.assertFalse(site["direct"]["ok"])
        self.assertEqual(site["direct"]["reason"], "dns")
        self.assertEqual(site["direct"]["reason"], reason_of(bad))

    def test_active_vpn(self):
        rep = Report(vpn=True, vpn_apps=["AmneziaVPN"], meta_vpn={"country": "FI"}, vpn_rtt=42.2)
        vpn = to_json(rep)["vpn"]
        self.assertTrue(vpn["active"])
        self.assertEqual(vpn["apps"], ["AmneziaVPN"])
        self.assertEqual(vpn["exit_country"], "FI")
        self.assertEqual(vpn["rtt_ms"], 42.2)


if __name__ == "__main__":
    unittest.main()
