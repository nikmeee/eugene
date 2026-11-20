import struct
import unittest

from eugene.probes import DnsParseError, _skip_name, parse_dns_answers


def _name(host):
    out = b""
    for part in host.split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def _response(tid=0x1234, ip=b"\x01\x02\x03\x04"):
    header = struct.pack(">HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    question = _name("example.com") + struct.pack(">HH", 1, 1)
    answer = b"\xC0\x0C" + struct.pack(">HHIH", 1, 1, 60, 4) + ip
    return header + question + answer


class DnsNameTests(unittest.TestCase):
    def test_plain_name(self):
        raw = _name("example.com")
        self.assertEqual(_skip_name(raw, 0), len(raw))

    def test_compression_pointer_is_not_followed(self):
        # A pointer to itself. Following it would never end.
        self.assertEqual(_skip_name(b"\xC0\x00", 0), 2)

    def test_label_then_pointer(self):
        self.assertEqual(_skip_name(b"\x03www\xC0\x0C", 0), 6)

    def test_truncated_label_raises(self):
        with self.assertRaises(DnsParseError):
            _skip_name(b"\x05ab", 0)


class DnsMessageTests(unittest.TestCase):
    def test_parses_a_record(self):
        parsed = parse_dns_answers(_response(), 0x1234)
        self.assertEqual(parsed["rcode"], 0)
        self.assertEqual(parsed["ips"], ["1.2.3.4"])

    def test_foreign_tid_is_ignored(self):
        self.assertIsNone(parse_dns_answers(_response(), 0x0001))

    def test_short_packet_is_ignored(self):
        self.assertIsNone(parse_dns_answers(b"\x12\x34", 0x1234))

    def test_truncated_matching_packet_raises(self):
        with self.assertRaises(DnsParseError):
            parse_dns_answers(_response()[:20], 0x1234)


if __name__ == "__main__":
    unittest.main()
