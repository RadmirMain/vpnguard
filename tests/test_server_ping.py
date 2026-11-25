#!/usr/bin/env python3
"""
Tests for GID 890 + IP_BOUND_IF server latency probing and netstat interface detection.
"""
import argparse
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

import vpnguard


class TestServerPing(unittest.TestCase):
    def test_get_physical_default_interface_ignores_utun(self):
        netstat_sample = (
            "Routing tables\n"
            "Internet:\n"
            "Destination        Gateway            Flags               Netif Expire\n"
            "default            link#22            UCSg               utun99\n"
            "default            192.168.1.1        UGScIg                en5\n"
        )
        fake_res = mock.MagicMock(returncode=0, stdout=netstat_sample)
        with mock.patch("subprocess.run", return_value=fake_res):
            iface = vpnguard._get_physical_default_interface()
        self.assertEqual(iface, "en5")

    def test_resolve_server_probe_ip_prefers_cached_resolved_ips(self):
        srv = {
            "id": "s1",
            "host": "nonexistent.invalid",
            "resolvedIps": ["203.0.113.10"],
        }
        self.assertEqual(vpnguard._resolve_server_probe_ip(srv), "203.0.113.10")

    def test_cmd_server_ping_json_uses_gid890_probe(self):
        store = {
            "activeId": "s1",
            "servers": [
                {"id": "s1", "name": "Server 1", "host": "203.0.113.10", "resolvedIps": ["203.0.113.10"], "port": 443},
                {"id": "s2", "name": "Server 2", "host": "203.0.113.20", "resolvedIps": ["203.0.113.20"], "port": 8443},
            ],
        }

        def fake_probe(ip, port, if_idx, timeout=2.0):
            return (24, None) if ip == "203.0.113.10" else (None, "timed out")

        buf = io.StringIO()
        with mock.patch.object(vpnguard, "load_servers_store", return_value=store), \
             mock.patch("os.geteuid", return_value=1000), \
             mock.patch.object(vpnguard, "_get_physical_default_interface", return_value="en0"), \
             mock.patch("socket.if_nametoindex", return_value=14), \
             mock.patch.object(vpnguard, "_probe_tcp_rtt_single", side_effect=fake_probe), \
             redirect_stdout(buf):
            rc = vpnguard.cmd_server_ping(argparse.Namespace(json=True))

        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(len(data), 2)
        self.assertTrue(data[0]["reachable"])
        self.assertEqual(data[0]["latencyMs"], 24)
        self.assertFalse(data[1]["reachable"])
        self.assertIsNone(data[1]["latencyMs"])


if __name__ == "__main__":
    unittest.main()
