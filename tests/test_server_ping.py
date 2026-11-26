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

    def test_dns_a_query_build_and_parse_response(self):
        import socket, struct
        tx_id = 0x1234
        query = vpnguard._build_dns_a_query("relay.example.com", tx_id)
        self.assertGreater(len(query), 12)

        # Build synthetic DNS response with pointer compression (0xC0 0x0C) to QNAME
        question_part = query[12:]
        header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("203.0.113.77")
        resp = header + question_part + answer

        ips = vpnguard._parse_dns_a_response(resp, tx_id)
        self.assertEqual(ips, ["203.0.113.77"])
        self.assertEqual(vpnguard._parse_dns_a_response(resp, tx_id + 1), [])

    def test_cmd_server_sync_pf_uses_direct_gid890_dns_bypass(self):
        store = {
            "activeId": "s1",
            "servers": [
                {"id": "s1", "name": "Relay", "host": "relay.example.com", "resolvedIps": ["203.0.113.10"], "port": 443}
            ],
        }
        buf = io.StringIO()
        with mock.patch("os.path.exists", return_value=True), \
             mock.patch.object(vpnguard, "load_servers_store", return_value=store), \
             mock.patch.object(vpnguard, "resolve_ipv4_direct_via_gid890", return_value=["203.0.113.88"]) as dns_mock, \
             mock.patch.object(vpnguard, "apply_pf_egress", return_value=(True, "Loaded")) as pf_mock, \
             mock.patch.object(vpnguard, "save_servers_store"), \
             mock.patch.object(vpnguard, "build_singbox_config", return_value={"route": {"final": "xray-upstream"}}), \
             mock.patch.object(vpnguard, "atomic_write_text"), \
             mock.patch("subprocess.run", return_value=mock.MagicMock(returncode=1)), \
             redirect_stdout(buf):
            rc = vpnguard.cmd_server_sync_pf(argparse.Namespace())

        self.assertEqual(rc, 0)
        dns_mock.assert_called_once_with("relay.example.com")
        pf_mock.assert_called_once_with(["203.0.113.88"], 443)
        out = json.loads(buf.getvalue())
        self.assertTrue(out["ipsChanged"])
        self.assertEqual(out["ips"], ["203.0.113.88"])

    def _make_server_store(self):
        return {
            "activeId": "s1",
            "servers": [
                {
                    "id": "s1",
                    "name": "Server 1",
                    "host": "203.0.113.10",
                    "port": 443,
                    "resolvedIps": ["203.0.113.10"],
                    "xrayConfig": {
                        "inbounds": [{"port": 18088, "listen": "127.0.0.1", "protocol": "socks"}],
                        "outbounds": [{
                            "tag": "proxy",
                            "protocol": "vless",
                            "settings": {"vnext": [{"address": "203.0.113.10", "port": 443, "users": [{"id": "11111111-1111-4111-8111-111111111111"}]}]}
                        }],
                    },
                },
                {
                    "id": "s2",
                    "name": "Server 2",
                    "host": "relay2.example.com",
                    "port": 8443,
                    "resolvedIps": ["203.0.113.20"],
                    "xrayConfig": {
                        "inbounds": [{"port": 18088, "listen": "127.0.0.1", "protocol": "socks"}],
                        "outbounds": [{
                            "tag": "proxy",
                            "protocol": "vless",
                            "settings": {"vnext": [{"address": "relay2.example.com", "port": 8443, "users": [{"id": "22222222-2222-4222-8222-222222222222"}]}]}
                        }],
                    },
                },
            ],
        }

    def test_activate_server_offline_updates_configs_without_kickstart(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            srv_path = os.path.join(tmpdir, "servers.json")
            active_path = os.path.join(tmpdir, "active_server.json")
            xray_path = os.path.join(tmpdir, "xray.json")
            sb_path = os.path.join(tmpdir, "sing-box.json")
            pf_egress_path = os.path.join(tmpdir, "pf.egress.conf")
            rules_path = os.path.join(tmpdir, "rules.json")

            with open(srv_path, "w", encoding="utf-8") as f:
                json.dump(self._make_server_store(), f)
            with open(xray_path, "w", encoding="utf-8") as f:
                f.write('{"old": "xray"}')
            with open(sb_path, "w", encoding="utf-8") as f:
                f.write('{"old": "sb"}')
            with open(rules_path, "w", encoding="utf-8") as f:
                json.dump(vpnguard.DEFAULT_RULES, f)

            sub_mock = mock.MagicMock(return_value=mock.MagicMock(returncode=0, stderr="", stdout=""))
            with mock.patch.object(vpnguard, "SERVERS_FILE_PATH", srv_path), \
                 mock.patch.object(vpnguard, "XRAY_CONF_PATH", xray_path), \
                 mock.patch.object(vpnguard, "SINGBOX_CONF_PATH", sb_path), \
                 mock.patch.object(vpnguard, "PF_EGRESS_FILE", pf_egress_path), \
                 mock.patch.object(vpnguard, "RULES_FILE_PATH", rules_path), \
                 mock.patch.object(vpnguard, "resolve_ipv4_direct_via_gid890", return_value=["203.0.113.99"]) as dns_mock, \
                 mock.patch.object(vpnguard, "validate_xray_config", return_value=(True, "OK")), \
                 mock.patch.object(vpnguard, "apply_pf_egress", return_value=(True, "OK")), \
                 mock.patch.object(vpnguard, "read_desired_state", return_value="off"), \
                 mock.patch.object(vpnguard, "get_pf_status", return_value={"anchor_loaded": False}), \
                 mock.patch.object(vpnguard, "get_xray_process_status", return_value={"running": False}), \
                 mock.patch.object(vpnguard, "get_singbox_process_status", return_value={"running": False}), \
                 mock.patch("subprocess.run", sub_mock):
                ok, msg = vpnguard.activate_server("s2")

            self.assertTrue(ok, msg)
            self.assertIn("VPN is currently off", msg)
            dns_mock.assert_called_once_with("relay2.example.com")
            for call in sub_mock.call_args_list:
                self.assertNotIn("launchctl", call.args[0])

            with open(srv_path, "r", encoding="utf-8") as f:
                updated_store = json.load(f)
            self.assertEqual(updated_store["activeId"], "s2")
            s2 = next(s for s in updated_store["servers"] if s["id"] == "s2")
            self.assertEqual(s2["resolvedIps"], ["203.0.113.99"])
            with open(sb_path, "r", encoding="utf-8") as f:
                self.assertIn("203.0.113.99", f.read())

    def test_activate_server_online_requires_utun99_and_rolls_back_on_failure(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            srv_path = os.path.join(tmpdir, "servers.json")
            xray_path = os.path.join(tmpdir, "xray.json")
            sb_path = os.path.join(tmpdir, "sing-box.json")
            pf_egress_path = os.path.join(tmpdir, "pf.egress.conf")
            rules_path = os.path.join(tmpdir, "rules.json")

            with open(srv_path, "w", encoding="utf-8") as f:
                json.dump(self._make_server_store(), f)
            with open(xray_path, "w", encoding="utf-8") as f:
                f.write('{"old": "xray"}')
            with open(sb_path, "w", encoding="utf-8") as f:
                f.write('{"old": "sb"}')
            with open(pf_egress_path, "w", encoding="utf-8") as f:
                f.write("pass out quick inet proto tcp to 203.0.113.10 port 443\n")
            with open(rules_path, "w", encoding="utf-8") as f:
                json.dump(vpnguard.DEFAULT_RULES, f)

            sub_mock = mock.MagicMock(return_value=mock.MagicMock(returncode=0, stderr="", stdout=""))
            priv_mock = mock.MagicMock(return_value=mock.MagicMock(returncode=0, stderr="", stdout=""))
            with mock.patch.object(vpnguard, "SERVERS_FILE_PATH", srv_path), \
                 mock.patch.object(vpnguard, "XRAY_CONF_PATH", xray_path), \
                 mock.patch.object(vpnguard, "SINGBOX_CONF_PATH", sb_path), \
                 mock.patch.object(vpnguard, "PF_EGRESS_FILE", pf_egress_path), \
                 mock.patch.object(vpnguard, "RULES_FILE_PATH", rules_path), \
                 mock.patch.object(vpnguard, "resolve_ipv4_direct_via_gid890", return_value=["203.0.113.99"]), \
                 mock.patch.object(vpnguard, "validate_xray_config", return_value=(True, "OK")), \
                 mock.patch.object(vpnguard, "apply_pf_egress", return_value=(True, "OK")), \
                 mock.patch.object(vpnguard, "run_privileged", priv_mock), \
                 mock.patch.object(vpnguard, "read_desired_state", return_value="on"), \
                 mock.patch.object(vpnguard, "get_pf_status", return_value={"anchor_loaded": True}), \
                 mock.patch.object(vpnguard, "get_xray_process_status", return_value={"running": True}), \
                 mock.patch.object(vpnguard, "get_singbox_process_status", return_value={"running": True}), \
                 mock.patch.object(vpnguard, "check_port_listening", return_value=True), \
                 mock.patch.object(vpnguard, "get_utun_status", return_value={"active": False, "interface": "utun99"}), \
                 mock.patch("time.sleep"), \
                 mock.patch("subprocess.run", sub_mock):
                ok, msg = vpnguard.activate_server("s2")

            self.assertFalse(ok)
            self.assertIn("utun99", msg)
            with open(xray_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), '{"old": "xray"}')
            with open(sb_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), '{"old": "sb"}')
            priv_mock.assert_any_call(["pfctl", "-a", "vpnguard/egress", "-f", pf_egress_path], timeout=10)
            kickstarts = [
                call.args[0] for call in sub_mock.call_args_list
                if isinstance(call.args[0], list) and call.args[0][:3] == ["launchctl", "kickstart", "-k"]
            ]
            # 2 kickstarts for initial activation attempt + 2 kickstarts for rollback
            self.assertEqual(
                kickstarts,
                [
                    ["launchctl", "kickstart", "-k", "system/com.vpnguard.xray"],
                    ["launchctl", "kickstart", "-k", "system/com.vpnguard.singbox"],
                    ["launchctl", "kickstart", "-k", "system/com.vpnguard.xray"],
                    ["launchctl", "kickstart", "-k", "system/com.vpnguard.singbox"],
                ],
            )

            # Now succeed when utun99 comes up
            with mock.patch.object(vpnguard, "SERVERS_FILE_PATH", srv_path), \
                 mock.patch.object(vpnguard, "XRAY_CONF_PATH", xray_path), \
                 mock.patch.object(vpnguard, "SINGBOX_CONF_PATH", sb_path), \
                 mock.patch.object(vpnguard, "PF_EGRESS_FILE", pf_egress_path), \
                 mock.patch.object(vpnguard, "RULES_FILE_PATH", rules_path), \
                 mock.patch.object(vpnguard, "resolve_ipv4_direct_via_gid890", return_value=["203.0.113.99"]), \
                 mock.patch.object(vpnguard, "validate_xray_config", return_value=(True, "OK")), \
                 mock.patch.object(vpnguard, "apply_pf_egress", return_value=(True, "OK")), \
                 mock.patch.object(vpnguard, "read_desired_state", return_value="on"), \
                 mock.patch.object(vpnguard, "get_pf_status", return_value={"anchor_loaded": True}), \
                 mock.patch.object(vpnguard, "get_xray_process_status", return_value={"running": True}), \
                 mock.patch.object(vpnguard, "get_singbox_process_status", return_value={"running": True}), \
                 mock.patch.object(vpnguard, "check_port_listening", return_value=True), \
                 mock.patch.object(vpnguard, "get_utun_status", return_value={"active": True, "interface": "utun99"}), \
                 mock.patch("time.sleep"), \
                 mock.patch("subprocess.run", sub_mock):
                ok2, msg2 = vpnguard.activate_server("s2")

            self.assertTrue(ok2, msg2)


if __name__ == "__main__":
    unittest.main()
