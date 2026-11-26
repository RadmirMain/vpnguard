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


if __name__ == "__main__":
    unittest.main()
