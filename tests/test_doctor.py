import unittest
from unittest.mock import patch

from eugene.doctor import Doctor


def _result(ip, stage=None, error=None):
    return {
        "host": "example.com", "ip": ip, "dns": None, "tcp": 1.0,
        "tls": 2.0 if stage != "tcp" else None, "http": None,
        "status": 200 if error is None else None, "stage": stage, "error": error,
    }


class DirectProbeTests(unittest.TestCase):
    def test_direct_ips_are_deduplicated_and_limited(self):
        answers = [
            {"ips": ["1.1.1.1", "2.2.2.2"]},
            {"ips": ["2.2.2.2", "3.3.3.3"]},
            {"ips": ["4.4.4.4"]},
        ]
        with patch("eugene.doctor.p.dns_query", side_effect=answers):
            self.assertEqual(
                Doctor()._direct_ips("example.com"),
                ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
            )

    def test_direct_probe_tries_next_address(self):
        attempts = [
            _result("1.1.1.1", "tcp", "TCP timeout"),
            _result("2.2.2.2"),
        ]
        doc = Doctor()
        with patch.object(doc, "_direct_ips", return_value=["1.1.1.1", "2.2.2.2"]), \
                patch("eugene.doctor.p.http_probe", side_effect=attempts) as probe:
            result = doc._probe_direct("example.com")
        self.assertIsNone(result["error"])
        self.assertEqual(result["ip"], "2.2.2.2")
        self.assertEqual(probe.call_count, 2)

    def test_site_result_and_progress_are_published_together(self):
        doc = Doctor(sites=[("A", "a.example"), ("B", "b.example")])
        doc._record_site_result(("A", "a.example", None, _result("1.1.1.1")))
        snap = doc.snapshot()
        self.assertEqual(len(snap.site_results), 1)
        self.assertEqual(snap.nodes["sites"]["value"], "1/2")


if __name__ == "__main__":
    unittest.main()
