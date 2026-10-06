"""Offline unit tests for the bounded DNS wire codec.

No network, DNS, socket, or process activity occurs: only byte buffers are built
and parsed.
"""

import unittest

from red_teaming.recon import dns_wire
from red_teaming.recon.dns_wire import (
    DnsMessageError,
    build_query,
    build_response_for_query,
    extract_addresses,
    extract_cnames,
    is_truncated,
    parse_query,
    parse_response,
)
from red_teaming.recon.netpolicy import (
    MAX_DNS_MESSAGE,
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
)


def _question_end(data):
    return parse_query(data).question_end


class BuildQueryTests(unittest.TestCase):
    def test_round_trip(self):
        query = build_query("acme.example", DNS_TYPE_A, 0x1234)
        parsed = parse_query(query)
        self.assertEqual(parsed.transaction_id, 0x1234)
        self.assertEqual(parsed.name, "acme.example")
        self.assertEqual(parsed.qtype, DNS_TYPE_A)
        self.assertEqual(parsed.qclass, 1)

    def test_normalizes_and_uppercases(self):
        parsed = parse_query(build_query("WWW.Acme.Example.", DNS_TYPE_AAAA, 1))
        self.assertEqual(parsed.name, "www.acme.example")

    def test_rejects_bad_inputs(self):
        with self.assertRaises(DnsMessageError):
            build_query("acme.example", 15, 1)  # MX unsupported
        with self.assertRaises(DnsMessageError):
            build_query("acme.example", DNS_TYPE_A, 0x10000)
        with self.assertRaises(DnsMessageError):
            build_query("bad name", DNS_TYPE_A, 1)

    def test_question_end_matches_wire_layout(self):
        query = build_query("acme.example", DNS_TYPE_A, 1)
        # 12-byte header + 1+4 (acme) + 1+7 (example) + 1 (root) + 2 + 2
        self.assertEqual(_question_end(query), 12 + 1 + 4 + 1 + 7 + 1 + 2 + 2)


class ParseQueryRejectionTests(unittest.TestCase):
    def test_too_short(self):
        with self.assertRaises(DnsMessageError):
            parse_query(b"\x00" * 5)

    def test_oversized(self):
        with self.assertRaises(DnsMessageError):
            parse_query(b"\x00" * (MAX_DNS_MESSAGE + 1))

    def test_response_is_not_a_query(self):
        query = bytearray(build_query("acme.example", DNS_TYPE_A, 1))
        query[2] |= 0x80  # set QR
        with self.assertRaises(DnsMessageError):
            parse_query(bytes(query))

    def test_bad_opcode(self):
        query = bytearray(build_query("acme.example", DNS_TYPE_A, 1))
        query[2] |= 0x08  # opcode 1
        with self.assertRaises(DnsMessageError):
            parse_query(bytes(query))

    def test_multiple_questions(self):
        query = bytearray(build_query("acme.example", DNS_TYPE_A, 1))
        query[4:6] = (2).to_bytes(2, "big")
        with self.assertRaises(DnsMessageError):
            parse_query(bytes(query))

    def test_non_in_class(self):
        query = bytearray(build_query("acme.example", DNS_TYPE_A, 1))
        query[-2:] = (3).to_bytes(2, "big")
        with self.assertRaises(DnsMessageError):
            parse_query(bytes(query))

    def test_pointer_loop(self):
        # header + a name that is a compression pointer to itself
        header = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        body = b"\xc0\x0c" + DNS_TYPE_A.to_bytes(2, "big") + b"\x00\x01"
        with self.assertRaises(DnsMessageError):
            parse_query(header + body)


class BuildResponseTests(unittest.TestCase):
    def test_a_record_round_trip(self):
        query = build_query("acme.example", DNS_TYPE_A, 0x2222)
        response = build_response_for_query(
            query, [("acme.example", DNS_TYPE_A, "8.8.8.8")]
        )
        parsed = parse_response(
            response, expect_id=0x2222, expect_name="acme.example", expect_type=DNS_TYPE_A
        )
        self.assertEqual(extract_addresses(parsed), ("8.8.8.8",))
        self.assertFalse(parsed.truncated)

    def test_aaaa_and_cname(self):
        query = build_query("www.acme.example", DNS_TYPE_CNAME, 7)
        response = build_response_for_query(
            query, [("www.acme.example", DNS_TYPE_CNAME, "target.acme.example")]
        )
        parsed = parse_response(
            response, expect_id=7, expect_name="www.acme.example", expect_type=DNS_TYPE_CNAME
        )
        self.assertEqual(extract_cnames(parsed), ("target.acme.example",))

    def test_truncated_flag(self):
        query = build_query("acme.example", DNS_TYPE_A, 1)
        response = build_response_for_query(query, [], truncated=True)
        self.assertTrue(is_truncated(response))
        parsed = parse_response(
            response, expect_id=1, expect_name="acme.example", expect_type=DNS_TYPE_A
        )
        self.assertTrue(parsed.truncated)

    def test_rejects_bad_rcode_and_type(self):
        query = build_query("acme.example", DNS_TYPE_A, 1)
        with self.assertRaises(DnsMessageError):
            build_response_for_query(query, [], rcode=99)
        with self.assertRaises(DnsMessageError):
            build_response_for_query(query, [("acme.example", 15, "x")])


class ParseResponseRejectionTests(unittest.TestCase):
    def _valid(self, qtype=DNS_TYPE_A, name="acme.example", qid=5):
        query = build_query(name, qtype, qid)
        answer = {
            DNS_TYPE_A: (name, DNS_TYPE_A, "8.8.8.8"),
            DNS_TYPE_AAAA: (name, DNS_TYPE_AAAA, "2606:4700::1111"),
            DNS_TYPE_CNAME: (name, DNS_TYPE_CNAME, "target.acme.example"),
        }[qtype]
        return build_response_for_query(query, [answer])

    def test_wrong_transaction_id(self):
        with self.assertRaises(DnsMessageError):
            parse_response(
                self._valid(qid=5), expect_id=6, expect_name="acme.example", expect_type=DNS_TYPE_A
            )

    def test_wrong_question_name(self):
        with self.assertRaises(DnsMessageError):
            parse_response(
                self._valid(), expect_id=5, expect_name="other.acme.example", expect_type=DNS_TYPE_A
            )

    def test_wrong_question_type(self):
        with self.assertRaises(DnsMessageError):
            parse_response(
                self._valid(), expect_id=5, expect_name="acme.example", expect_type=DNS_TYPE_AAAA
            )

    def test_query_is_not_a_response(self):
        query = build_query("acme.example", DNS_TYPE_A, 5)
        with self.assertRaises(DnsMessageError):
            parse_response(
                query, expect_id=5, expect_name="acme.example", expect_type=DNS_TYPE_A
            )

    def test_rdlength_overrun(self):
        response = bytearray(self._valid())
        # last 2 bytes hold rdlength for the A record; make it huge
        response[-6:-4] = (0xFFFF).to_bytes(2, "big")
        with self.assertRaises(DnsMessageError):
            parse_response(
                bytes(response), expect_id=5, expect_name="acme.example", expect_type=DNS_TYPE_A
            )

    def test_non_ascii_label(self):
        header = b"\x00\x05\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        question = b"\x05\xff\xff\xff\xff\xff\x02lt\x00" + (1).to_bytes(2, "big") + b"\x00\x01"
        with self.assertRaises(DnsMessageError):
            parse_response(
                header + question, expect_id=5, expect_name="x.lt", expect_type=DNS_TYPE_A
            )

    def test_compression_pointer_owner_name(self):
        header = b"\x00\x05\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        question = (
            b"\x04" + b"acme" + b"\x07" + b"example" + b"\x00"
            + (1).to_bytes(2, "big") + b"\x00\x01"
        )
        answer = (
            b"\xc0\x0c"  # owner name -> pointer to offset 12
            + (1).to_bytes(2, "big") + b"\x00\x01"
            + (60).to_bytes(4, "big")
            + (4).to_bytes(2, "big") + b"\x08\x08\x08\x08"
        )
        parsed = parse_response(
            header + question + answer,
            expect_id=5,
            expect_name="acme.example",
            expect_type=DNS_TYPE_A,
        )
        self.assertEqual(extract_addresses(parsed), ("8.8.8.8",))


if __name__ == "__main__":
    unittest.main()
