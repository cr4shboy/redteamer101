"""Offline unit tests for the bounded IPC framing and message codecs.

Only in-memory ``socketpair`` descriptors are used; no external network, files,
or processes are involved. Descriptor-passing tests are skipped on platforms
without ``SCM_RIGHTS`` (for example Windows).
"""

import socket
import unittest

from red_teaming.recon import ipc


def _pair():
    return socket.socketpair()


class FramingTests(unittest.TestCase):
    def test_round_trip(self):
        a, b = _pair()
        try:
            ipc.send_frame(a, b"hello")
            self.assertEqual(ipc.recv_frame(b), b"hello")
        finally:
            a.close()
            b.close()

    def test_empty_payload_rejected(self):
        a, b = _pair()
        try:
            with self.assertRaises(ipc.IpcProtocolError):
                ipc.send_frame(a, b"")
        finally:
            a.close()
            b.close()

    def test_oversized_payload_rejected_before_send(self):
        a, b = _pair()
        try:
            with self.assertRaises(ipc.IpcProtocolError):
                ipc.send_frame(a, b"x" * (ipc.MAX_IPC_FRAME + 1))
        finally:
            a.close()
            b.close()

    def test_closed_peer_returns_none(self):
        a, b = _pair()
        a.close()
        try:
            self.assertIsNone(ipc.recv_frame(b))
        finally:
            b.close()

    def test_non_bytes_rejected(self):
        a, b = _pair()
        try:
            with self.assertRaises(ipc.IpcProtocolError):
                ipc.send_frame(a, "not bytes")  # type: ignore[arg-type]
        finally:
            a.close()
            b.close()


class ConnectCodecTests(unittest.TestCase):
    def test_request_round_trip(self):
        payload = ipc.encode_connect_request("crt.sh", 443)
        self.assertEqual(ipc.decode_connect_request(payload), ("crt.sh", 443))

    def test_request_rejects_unknown_op_and_fields(self):
        with self.assertRaises(ipc.IpcProtocolError):
            ipc.decode_connect_request(b'{"op":"other","host":"crt.sh","port":443}')
        with self.assertRaises(ipc.IpcProtocolError):
            ipc.decode_connect_request(
                b'{"op":"connect","host":"crt.sh","port":443,"extra":1}'
            )
        with self.assertRaises(ipc.IpcProtocolError):
            ipc.encode_connect_request("crt.sh", 0)

    def test_response_round_trip(self):
        self.assertEqual(ipc.decode_connect_response(ipc.encode_connect_response(True)), (True, None))
        ok, reason = ipc.decode_connect_response(ipc.encode_connect_response(False, "denied"))
        self.assertFalse(ok)
        self.assertEqual(reason, "denied")

    def test_response_rejects_unknown_fields(self):
        with self.assertRaises(ipc.IpcProtocolError):
            ipc.decode_connect_response(b'{"ok":false,"reason":"x","extra":1}')


class DnsCodecTests(unittest.TestCase):
    def test_request_round_trip(self):
        payload = ipc.encode_dns_request(ipc.DNS_PROTO_TCP, b"query")
        self.assertEqual(ipc.decode_dns_request(payload), (ipc.DNS_PROTO_TCP, b"query"))

    def test_bad_transport_rejected(self):
        with self.assertRaises(ipc.IpcProtocolError):
            ipc.encode_dns_request(9, b"query")
        with self.assertRaises(ipc.IpcProtocolError):
            ipc.decode_dns_request(b"\x09query")

    def test_response_round_trip(self):
        payload = ipc.encode_dns_response(ipc.DNS_PROTO_UDP, ipc.STATUS_OK, b"resp")
        self.assertEqual(ipc.decode_dns_response(payload), (ipc.DNS_PROTO_UDP, ipc.STATUS_OK, b"resp"))

    def test_bad_status_rejected(self):
        with self.assertRaises(ipc.IpcProtocolError):
            ipc.encode_dns_response(ipc.DNS_PROTO_UDP, 42)
        with self.assertRaises(ipc.IpcProtocolError):
            ipc.decode_dns_response(b"\x00\x63resp")


class StatusEventTests(unittest.TestCase):
    def test_empty_string_allowed(self):
        payload = ipc.encode_status_event({"event": "done", "route4": ""})
        self.assertEqual(ipc.decode_status_event(payload)["route4"], "")

    def test_control_characters_rejected(self):
        with self.assertRaises(ipc.IpcProtocolError):
            ipc.encode_status_event({"event": "bad\nvalue"})

    def test_too_many_fields_rejected(self):
        document = {f"k{i}": i for i in range(ipc._MAX_STATUS_FIELDS + 1)}
        payload = ipc.encode_status_event(document)
        with self.assertRaises(ipc.IpcProtocolError):
            ipc.decode_status_event(payload)

    def test_unsupported_value_rejected(self):
        with self.assertRaises(ipc.IpcProtocolError):
            ipc.encode_status_event({"event": {"nested": 1}})


@unittest.skipUnless(ipc.fd_passing_supported(), "SCM_RIGHTS unavailable")
class FdPassingTests(unittest.TestCase):
    def test_send_and_receive_one_descriptor(self):
        control_a, control_b = _pair()
        payload_a, payload_b = _pair()
        try:
            fd = payload_a.fileno()
            ipc.send_fd_message(control_a, b"here", fd)
            message, received = ipc.recv_message_fd(control_b)
            self.assertEqual(message, b"here")
            self.assertIsNotNone(received)
            passed = socket.socket(fileno=received)
            payload_b.sendall(b"through")
            self.assertEqual(passed.recv(16), b"through")
            passed.close()
        finally:
            control_a.close()
            control_b.close()
            payload_a.close()
            payload_b.close()

    def test_receive_without_descriptor(self):
        control_a, control_b = _pair()
        try:
            ipc.send_fd_message(control_a, b"plain")
            message, received = ipc.recv_message_fd(control_b)
            self.assertEqual(message, b"plain")
            self.assertIsNone(received)
        finally:
            control_a.close()
            control_b.close()


if __name__ == "__main__":
    unittest.main()
