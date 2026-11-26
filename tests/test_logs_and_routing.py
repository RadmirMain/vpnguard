#!/usr/bin/env python3
"""
Tests for sanitized diagnostic logs (vpnguard logs --json) and CLI binary process_path rules.
"""
import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

import vpnguard


class TestLogsAndRouting(unittest.TestCase):
    def test_redact_sensitive_text_masks_uuids_vless_keys_and_relays(self):
        raw = (
            "Connecting to 203.0.113.55:443 sni=secret-relay.example.net\n"
            "URI: vless://12345678-1234-4234-8234-1234567890ab@203.0.113.55:443?pbk=SuperSecretPubKey&sid=abcd1234#Node\n"
            "Authorization: Bearer deadbeef0123456789abcdef\n"
            "Local loopback 127.0.0.1:18088 and DNS 1.1.1.1 remain visible.\n"
        )
        cleaned = vpnguard.redact_sensitive_text(raw, extra_secrets=["203.0.113.55", "secret-relay.example.net"])
        self.assertNotIn("203.0.113.55", cleaned)
        self.assertNotIn("secret-relay.example.net", cleaned)
        self.assertNotIn("12345678-1234-4234-8234-1234567890ab", cleaned)
        self.assertNotIn("SuperSecretPubKey", cleaned)
        self.assertNotIn("deadbeef0123456789abcdef", cleaned)
        self.assertIn("vless://[REDACTED]", cleaned)
        self.assertIn("[REDACTED_SECRET]", cleaned)
        self.assertIn("127.0.0.1:18088", cleaned)
        self.assertIn("1.1.1.1", cleaned)

    def test_redact_sensitive_text_masks_trojan_ss_vmess_and_json_secrets(self):
        raw = (
            "trojan://topsecretpass@203.0.113.5:443?sni=example.com#T\n"
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@203.0.113.6:8388#SS\n"
            "vmess://eyJhZGQiOiIyMDMuMC4xMTMuNyJ9\n"
            '{"password": "my_json_password", "psk": "secret_psk_value", "privateKey": "priv_key_xyz"}\n'
            "https://example.com/hook?token=tok_secret_1&auth=auth_secret_2\n"
        )
        cleaned = vpnguard.redact_sensitive_text(raw)
        for leak in [
            "topsecretpass",
            "YWVzLTI1Ni1nY206c2VjcmV0",
            "eyJhZGQiOiIyMDMuMC4xMTMuNyJ9",
            "my_json_password",
            "secret_psk_value",
            "priv_key_xyz",
            "tok_secret_1",
            "auth_secret_2",
        ]:
            self.assertNotIn(leak, cleaned)
        self.assertIn("trojan://[REDACTED]", cleaned)
        self.assertIn("ss://[REDACTED]", cleaned)
        self.assertIn("vmess://[REDACTED]", cleaned)

    def test_tail_file_lines_handles_empty_missing_large_and_utf8_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = os.path.join(tmpdir, "missing.log")
            self.assertIn("Файл не найден", vpnguard._tail_file_lines(missing))

            empty = os.path.join(tmpdir, "empty.log")
            with open(empty, "wb"):
                pass
            self.assertEqual(vpnguard._tail_file_lines(empty), "(Лог пуст)")

            # Write > 100 KB file so multiple 8192-byte seek chunks are crossed with multibyte UTF-8
            large = os.path.join(tmpdir, "large_utf8.log")
            total_lines = 1500
            with open(large, "w", encoding="utf-8") as f:
                for i in range(total_lines):
                    f.write(f"line-{i:04d} 🔒 Запись кириллицы №{i} payload=abcdef0123456789\n")

            tail = vpnguard._tail_file_lines(large, max_lines=150)
            lines = tail.splitlines()
            self.assertEqual(len(lines), 150)
            self.assertTrue(lines[0].startswith("line-1350 "))
            self.assertTrue(lines[-1].startswith("line-1499 "))
            self.assertNotIn("\ufffd", tail)
            self.assertIn("🔒 Запись кириллицы №1499", tail)

    def test_rotate_log_if_needed_before_daemon_restart(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "vpnguard-singbox.log")
            with open(log_path, "wb") as f:
                f.write(b"a" * 100)

            self.assertFalse(vpnguard.rotate_log_if_needed(log_path, max_bytes=200))
            self.assertFalse(os.path.exists(f"{log_path}.1"))

            self.assertTrue(vpnguard.rotate_log_if_needed(log_path, max_bytes=50))
            self.assertTrue(os.path.exists(f"{log_path}.1"))
            with open(f"{log_path}.1", "rb") as f:
                self.assertEqual(len(f.read()), 100)
            with open(log_path, "rb") as f:
                self.assertEqual(f.read(), b"")

    def test_get_pf_status_uses_single_verbose_rules_query_and_parses_blocked_packets(self):
        rules_v_output = (
            "pass quick on lo0 inet proto tcp from 127.0.0.0/8 to 127.0.0.0/8 group = 888\n"
            "  [ Evaluations: 100        Packets: 50         Bytes: 4000        States: 1     ]\n"
            "pass out quick inet proto tcp all group = 890\n"
            "  [ Evaluations: 20         Packets: 10         Bytes: 800         States: 0     ]\n"
            "block return out quick all\n"
            "  [ Evaluations: 300        Packets: 42         Bytes: 2688        States: 0     ]\n"
        )
        calls = []

        def fake_run_pfctl(args, timeout=5.0):
            calls.append(args)
            if args == ["-s", "info"]:
                return mock.MagicMock(returncode=0, stdout="Status: Enabled\n")
            if args == ["-sr"]:
                return mock.MagicMock(returncode=0, stdout='anchor "vpnguard" all\n')
            if args == ["-a", "vpnguard", "-s", "rules", "-v"]:
                return mock.MagicMock(returncode=0, stdout=rules_v_output)
            if args == ["-a", "vpnguard/egress", "-s", "rules"]:
                return mock.MagicMock(returncode=0, stdout="pass out quick inet proto tcp from any to 203.0.113.10 port = 443 group = 889\n")
            return mock.MagicMock(returncode=1, stdout="")

        with mock.patch.object(vpnguard, "_run_pfctl", side_effect=fake_run_pfctl):
            st = vpnguard.get_pf_status()

        self.assertEqual(calls.count(["-a", "vpnguard", "-s", "rules", "-v"]), 1)
        self.assertFalse(["-a", "vpnguard", "-s", "rules"] in calls)
        self.assertEqual(st["blocked_packets"], 42)
        self.assertEqual(st["rules_count"], 4)  # 3 main anchor rules + 1 egress rule
        self.assertTrue(st["has_group_888"])
        self.assertTrue(st["has_group_889"])
        self.assertTrue(st["has_group_890"])
        self.assertTrue(st["has_global_killswitch"])

    def test_sync_system_dns_skips_inactive_interfaces_and_flushes_only_on_change(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_path = os.path.join(tmpdir, "dns_backup.json")
            ns_order = (
                "An asterisk (*) denotes that a network service is disabled.\n"
                "(1) Wi-Fi\n"
                "(Hardware Port: Wi-Fi, Device: en0)\n"
                "(2) USB 10/100/1000 LAN\n"
                "(Hardware Port: USB 10/100/1000 LAN, Device: en5)\n"
            )
            with mock.patch.object(vpnguard, "DNS_BACKUP_PATH", backup_path), \
                 mock.patch.object(vpnguard, "_get_active_en_interfaces", return_value={"en0"}), \
                 mock.patch.object(vpnguard, "_get_service_dns", return_value=["1.1.1.1"]), \
                 mock.patch.object(vpnguard, "_set_service_dns") as set_mock, \
                 mock.patch.object(vpnguard, "flush_dns_cache") as flush_mock, \
                 mock.patch("subprocess.run", return_value=mock.MagicMock(returncode=0, stdout=ns_order)):
                ok, _ = vpnguard.sync_system_dns()

            self.assertTrue(ok)
            set_mock.assert_not_called()
            flush_mock.assert_not_called()

    def test_cmd_logs_json_returns_tail_150_and_redacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sb_log = os.path.join(tmpdir, "sb.log")
            xr_log = os.path.join(tmpdir, "xr.log")
            pf_log = os.path.join(tmpdir, "pf.log")
            with open(sb_log, "w", encoding="utf-8") as f:
                for i in range(200):
                    f.write(f"line-{i} uuid=11111111-2222-3333-4444-555555555555\n")
            with open(xr_log, "w", encoding="utf-8") as f:
                f.write("xray ok\n")
            with open(pf_log, "w", encoding="utf-8") as f:
                f.write("pf ok\n")

            buf = io.StringIO()
            with mock.patch.object(vpnguard, "LOG_SINGBOX_PATH", sb_log), \
                 mock.patch.object(vpnguard, "LOG_XRAY_PATH", xr_log), \
                 mock.patch.object(vpnguard, "LOG_PF_PATH", pf_log), \
                 mock.patch.object(vpnguard, "_collect_sensitive_literals", return_value=["198.51.100.42"]), \
                 mock.patch.object(vpnguard, "_run_diag_cmd", return_value="pass out proto tcp to 198.51.100.42"), \
                 redirect_stdout(buf):
                rc = vpnguard.cmd_logs(argparse.Namespace(json=True))

            self.assertEqual(rc, 0)
            data = json.loads(buf.getvalue())
            sb_lines = data["logs"]["singbox"].splitlines()
            self.assertEqual(len(sb_lines), 150)
            self.assertTrue(sb_lines[0].startswith("line-50"))
            self.assertNotIn("11111111-2222-3333-4444-555555555555", data["logs"]["singbox"])
            self.assertNotIn("198.51.100.42", data["system"]["pfRules"])

    def test_build_singbox_config_supports_cli_exact_process_path(self):
        rules = {
            "apps": [
                {"id": "a1", "name": "Cursor", "bundlePath": "/Applications/Cursor.app", "action": "proxy", "enabled": True},
                {"id": "a2", "name": "node", "bundlePath": "/opt/homebrew/bin/node", "action": "direct", "enabled": True},
            ],
            "domains": [],
            "presets": {"aiServicesProxy": True, "ruDirect": True, "blockQuic": True},
        }
        cfg = vpnguard.build_singbox_config(rules, relay_ip="203.0.113.10")
        route_rules = cfg["route"]["rules"]
        self.assertTrue(any(r.get("process_path_regex") == ["^/Applications/Cursor\\.app/.*"] for r in route_rules))
        self.assertTrue(any(r.get("process_path") == ["/opt/homebrew/bin/node"] and r.get("outbound") == "direct" for r in route_rules))

        check_bin = vpnguard.SINGBOX_BIN if os.path.exists(vpnguard.SINGBOX_BIN) else "sing-box"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f, indent=2)
            tmp_path = f.name
        try:
            res = subprocess.run([check_bin, "check", "-c", tmp_path], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"sing-box check failed: {res.stderr}\n{res.stdout}")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_cmd_status_json_includes_decoupled_health_flags(self):
        import argparse, io, contextlib, time
        buf = io.StringIO()
        with mock.patch.object(vpnguard, "load_config", return_value={}), \
             mock.patch.object(vpnguard, "get_pf_status", return_value={"enabled": True, "anchor_loaded": True, "rules_count": 10, "blocked_packets": 3}), \
             mock.patch.object(vpnguard, "get_xray_process_status", return_value={"running": False, "pid": None, "group": None, "user": None}), \
             mock.patch.object(vpnguard, "get_singbox_process_status", return_value={"running": False, "pid": None, "gid": None, "user": None}), \
             mock.patch.object(vpnguard, "get_utun_status", return_value={"active": False, "interface": None}), \
             mock.patch.object(vpnguard, "get_netwatch_process_status", return_value={"running": True, "pid": 999}), \
             mock.patch.object(vpnguard, "get_active_relay_ip", return_value="203.0.113.10"), \
             mock.patch.object(vpnguard, "_read_pause_until", return_value=int(time.time()) + 120), \
             mock.patch.object(vpnguard, "_read_pause_token", return_value="abc123"):
            with contextlib.redirect_stdout(buf):
                rc = vpnguard.cmd_status(argparse.Namespace(json=True, fast=True))
        self.assertEqual(rc, 1)
        data = json.loads(buf.getvalue())
        self.assertFalse(data["isProtectionOn"])
        self.assertTrue(data["pf_active"])
        self.assertFalse(data["utun_active"])
        self.assertFalse(data["cores_alive"])
        self.assertTrue(data["netwatch_active"])
        self.assertTrue(data["captive_pause_active"])

    def test_cmd_test_json_emits_four_states_and_session_gid_check(self):
        import argparse, io, contextlib
        buf = io.StringIO()
        with mock.patch.object(vpnguard, "EXEC_HELPER_PATH", "/nonexistent/helper"), \
             mock.patch.object(vpnguard, "LOCAL_EXEC_HELPER", "/nonexistent/helper"), \
             mock.patch.object(vpnguard, "load_config", return_value={}), \
             mock.patch.object(vpnguard, "get_pf_status", return_value={
                 "enabled": False, "main_anchor_linked": False, "anchor_loaded": False,
                 "has_group_888": False, "has_group_889": False, "rules_count": 0
             }), \
             mock.patch.object(vpnguard, "query_physical_ip", return_value={"ip": "203.0.113.1"}), \
             mock.patch.object(vpnguard, "get_xray_process_status", return_value={"running": False, "pid": None, "group": None, "user": None, "is_root": False}), \
             mock.patch.object(vpnguard, "check_port_listening", return_value=False), \
             mock.patch.object(vpnguard, "get_utun_status", return_value={"active": False, "interface": None}), \
             mock.patch.object(vpnguard, "get_netwatch_process_status", return_value={"running": False, "pid": None}), \
             mock.patch.object(vpnguard, "read_desired_state", return_value="on"), \
             mock.patch("os.geteuid", return_value=501), \
             mock.patch("os.getgroups", return_value=[20, 12, 888]):
            with contextlib.redirect_stdout(buf):
                rc = vpnguard.cmd_test(argparse.Namespace(json=True))
        self.assertEqual(rc, 1)
        report = json.loads(buf.getvalue())
        self.assertEqual(report["total"], 14)
        self.assertGreater(report["unknownCount"], 0)
        self.assertGreater(report["degradedCount"], 0)
        self.assertGreater(report["failedCount"], 0)
        test13 = report["tests"][12]
        test14 = report["tests"][13]
        self.assertEqual(test13["status"], "degraded")
        self.assertEqual(test14["status"], "fail")

    def test_explain_routing_url_specificity_app_fallback_and_json(self):
        import argparse, io, contextlib
        rules = {
            "apps": [
                {"id": "a1", "name": "Cursor", "bundlePath": "/Applications/Cursor.app", "action": "proxy", "enabled": True},
                {"id": "a2", "name": "node", "bundlePath": "/opt/homebrew/bin/node", "action": "direct", "enabled": True},
            ],
            "domains": [
                {"id": "d1", "domain": "example.ru", "action": "direct", "enabled": True},
                {"id": "d2", "domain": "api.example.ru", "action": "proxy", "enabled": True},
            ],
            "presets": {"aiServicesProxy": True, "ruDirect": True, "blockQuic": True},
        }
        # 1. URL normalization + specificity shadowing
        res_dom = vpnguard.explain_routing_target("https://API.Example.RU:8443/v1/chat.", rules=rules)
        self.assertEqual(res_dom["targetType"], "domain")
        self.assertEqual(res_dom["normalizedTarget"], "api.example.ru")
        self.assertEqual(res_dom["policyMode"], "static")
        self.assertEqual(res_dom["resolvedAction"], "proxy")
        self.assertEqual(res_dom["resolvedOutbound"], "xray-upstream")
        self.assertEqual(res_dom["winningRule"]["domain"], "api.example.ru")
        self.assertTrue(any(r["domain"] == "example.ru" for r in res_dom["shadowedRules"]))

        # 2. App rule (.app and CLI binary)
        res_app = vpnguard.explain_routing_target("/Applications/Cursor.app", rules=rules)
        self.assertEqual(res_app["targetType"], "app")
        self.assertEqual(res_app["resolvedOutbound"], "xray-upstream")
        res_cli = vpnguard.explain_routing_target("node", rules=rules)
        self.assertEqual(res_cli["targetType"], "app")
        self.assertEqual(res_cli["resolvedOutbound"], "direct")

        # 3. Fallback (no match -> final xray-upstream)
        res_fb = vpnguard.explain_routing_target("unlisted-service.org", rules=rules)
        self.assertTrue(res_fb["fallback"])
        self.assertIsNone(res_fb["winningRule"])
        self.assertEqual(res_fb["resolvedOutbound"], "xray-upstream")

        # 4. cmd_explain --json
        buf = io.StringIO()
        with mock.patch("os.path.exists", return_value=False):
            with contextlib.redirect_stdout(buf):
                rc = vpnguard.cmd_explain(argparse.Namespace(target="https://claude.ai/chat", json=True))
        self.assertEqual(rc, 0)
        cli_json = json.loads(buf.getvalue())
        self.assertEqual(cli_json["policyMode"], "static")
        self.assertIn("normalSession", cli_json["pfLayers"])
        self.assertIn("sandboxSession", cli_json["pfLayers"])


if __name__ == "__main__":
    unittest.main()
