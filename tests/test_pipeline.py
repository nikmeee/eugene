import unittest

from eugene.doctor import Doctor
from eugene.report import SKIP


def _wire(doc, isp_up):
    called = {}
    doc.step_scan = lambda pool: True
    doc.step_link = lambda: None
    doc.step_router = lambda pool: True
    doc.step_isp = lambda pool: isp_up
    doc.step_vpn = lambda pool: called.__setitem__("vpn", True)
    doc.step_dns = lambda pool: called.__setitem__("dns", True)
    doc.step_sites = lambda pool: called.__setitem__("sites", True)
    return called


class PipelineTests(unittest.TestCase):
    def test_silence_behind_router_keeps_dns_and_skips_sites(self):
        doc = Doctor()
        doc.report.vpn = True
        called = _wire(doc, isp_up=False)
        doc.run()
        self.assertTrue(called.get("dns"))
        self.assertNotIn("sites", called)
        self.assertNotIn("vpn", called)
        self.assertEqual(doc.report.nodes["sites"]["status"], SKIP)
        self.assertEqual(doc.report.nodes["sites"]["value"], "пропуск")
        self.assertEqual(doc.report.nodes["vpn"]["value"], "нет канала")

    def test_live_isp_still_checks_vpn(self):
        doc = Doctor()
        doc.report.vpn = True
        called = _wire(doc, isp_up=True)
        doc.run()
        self.assertTrue(called.get("vpn"))
        self.assertTrue(called.get("sites"))

    def test_live_isp_still_probes_sites(self):
        doc = Doctor()
        called = _wire(doc, isp_up=True)
        doc.run()
        self.assertTrue(called.get("dns"))
        self.assertTrue(called.get("sites"))
        self.assertNotIn("vpn", called)

    def test_no_route_stops_before_dns(self):
        doc = Doctor()
        called = {}
        doc.step_scan = lambda pool: False
        doc.step_dns = lambda pool: called.__setitem__("dns", True)
        doc.step_sites = lambda pool: called.__setitem__("sites", True)
        doc.run()
        self.assertNotIn("dns", called)
        self.assertNotIn("sites", called)
        self.assertTrue(doc.report.done)


if __name__ == "__main__":
    unittest.main()
