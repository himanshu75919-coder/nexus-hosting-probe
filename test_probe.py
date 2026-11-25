import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import probe


class ProbeTests(unittest.TestCase):
    def test_restart_counter(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(probe.mark_start(d)['launch_count'], 1)
            self.assertEqual(probe.mark_start(d)['launch_count'], 2)

    def test_unknown_state_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'state.json'
            p.write_text('{"production":"do not touch"}')
            with self.assertRaises(ValueError):
                probe.mark_start(d)
            self.assertEqual(json.loads(p.read_text())['production'], 'do not touch')

    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'foreign'
            p.write_text('do not touch')
            (Path(d) / 'state.json').symlink_to(p)
            with self.assertRaises(ValueError):
                probe.mark_start(d)
            self.assertEqual(p.read_text(), 'do not touch')

    def test_request_has_no_auth_key(self):
        packet = probe.make_request(b'x' * 16)
        self.assertEqual(packet[:2], b'\xef\x0a')
        self.assertEqual(packet[2:10], b'\0' * 8)
        self.assertEqual(len(packet), 42)
        with self.assertRaises(ValueError):
            probe.make_request(b'bad')

    def test_reply_nonce_validation(self):
        body = struct.pack('<I', 0x05162463) + b'x' * 16
        reply = b'\0' * 8 + b'\0' * 8 + struct.pack('<I', len(body)) + body
        self.assertTrue(probe.validate_reply(reply, b'x' * 16))
        with self.assertRaises(ValueError):
            probe.validate_reply(reply, b'y' * 16)
        with self.assertRaises(ValueError):
            probe.validate_reply(reply[:12], b'x' * 16)

    def test_unknown_limits_not_faked(self):
        with patch.object(probe, 'read_text', return_value=None):
            self.assertIsNone(probe.limits()['memory_limit_bytes'])
            self.assertIsNone(probe.limits()['cpu_quota'])


if __name__ == '__main__':
    unittest.main()
