#!/usr/bin/env python3
"""
Test local Xray proxy reachability and SOCKS5 remote resolution
"""
import unittest
import socket
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

import vpnguard

class TestProxy(unittest.TestCase):
    def test_local_ports_listening(self):
        """Verify that at least dedicated SOCKS port 18088 is active."""
        socks_up = vpnguard.check_port_listening("127.0.0.1", 18088)
        self.assertTrue(socks_up, "SOCKS port 18088 is not listening on 127.0.0.1")

    def test_socks5_handshake(self):
        """Verify SOCKS5 handshake on port 18088."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", 18088))
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        s.close()
        self.assertEqual(resp, b"\x05\x00", f"SOCKS5 handshake failed: {resp}")

if __name__ == "__main__":
    unittest.main()
