#!/usr/bin/env python3
"""
Test sing-box configuration generation and Clash API secret security
"""
import unittest
import os
import sys
import tempfile
import stat
import subprocess
import json

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

import vpnguard


class TestSingboxConfig(unittest.TestCase):
    def test_api_secret_generation_and_permissions(self):
        """Verify token generation, length, hex characters, and 600 permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_file = os.path.join(tmpdir, "api_secret")
            token = vpnguard.get_or_create_api_secret(secret_file)

            self.assertEqual(len(token), 32)
            int(token, 16)  # Verify valid hex string

            self.assertTrue(os.path.exists(secret_file))
            file_mode = stat.S_IMODE(os.stat(secret_file).st_mode)
            self.assertEqual(file_mode, 0o600, f"Expected 0600 permissions, got {oct(file_mode)}")

            with open(secret_file, "r", encoding="utf-8") as f:
                saved = f.read().strip()
            self.assertEqual(saved, token)

            # Idempotency check: next call must return identical token
            token2 = vpnguard.get_or_create_api_secret(secret_file)
            self.assertEqual(token, token2)

    def test_build_singbox_config_clash_api_structure(self):
        """Verify that build_singbox_config() includes secure clash_api block and find_process."""
        cfg = vpnguard.build_singbox_config(vpnguard.DEFAULT_RULES, relay_ip="1.2.3.4")

        self.assertIn("experimental", cfg)
        self.assertIn("clash_api", cfg["experimental"])
        clash_api = cfg["experimental"]["clash_api"]

        self.assertEqual(clash_api.get("external_controller"), "127.0.0.1:9090")
        secret = clash_api.get("secret")
        self.assertIsNotNone(secret)
        self.assertEqual(len(secret), 32)
        int(secret, 16)  # valid hex

        # Verify route.find_process is true for processPath metadata and final is xray-upstream
        self.assertIn("route", cfg)
        self.assertTrue(cfg["route"].get("find_process"), "route.find_process must be True for metadata.processPath")
        self.assertEqual(cfg["route"].get("final"), "xray-upstream")

        # Verify encrypted DoT 77.88.8.8 for direct RU DNS (no detour)
        dns_direct = next((s for s in cfg["dns"]["servers"] if s.get("tag") == "dns-direct"), None)
        self.assertIsNotNone(dns_direct)
        self.assertEqual(dns_direct.get("type"), "tls")
        self.assertEqual(dns_direct.get("server"), "77.88.8.8")
        self.assertNotIn("detour", dns_direct)

    def test_custom_ru_proxy_priority_and_app_regex(self):
        """Verify user .ru proxy domains precede ruDirect in DNS rules and apps emit process_path_regex."""
        rules = {
            "apps": [{"id": "a1", "name": "MyApp", "bundlePath": "/Applications/MyApp.app", "action": "proxy", "enabled": True}],
            "domains": [{"id": "d1", "domain": "special.ru", "action": "proxy", "enabled": True}],
            "presets": {"aiServicesProxy": True, "ruDirect": True, "blockQuic": True},
        }
        cfg = vpnguard.build_singbox_config(rules, relay_ip="1.2.3.4")
        dns_rules = cfg["dns"]["rules"]
        self.assertEqual(dns_rules[0]["domain_suffix"], ["special.ru"])
        self.assertEqual(dns_rules[0]["server"], "dns-remote")

        route_rules = cfg["route"]["rules"]
        app_rules = [r for r in route_rules if "process_path_regex" in r]
        self.assertEqual(len(app_rules), 1)
        self.assertEqual(app_rules[0]["outbound"], "xray-upstream")

    def test_singbox_syntax_validation(self):
        """Verify that sing-box binary validates the generated config without errors."""
        check_bin = vpnguard.SINGBOX_BIN if os.path.exists(vpnguard.SINGBOX_BIN) else "sing-box"
        cfg = vpnguard.build_singbox_config(vpnguard.DEFAULT_RULES, relay_ip="1.2.3.4")

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f, indent=2)
            tmp_path = f.name

        try:
            res = subprocess.run([check_bin, "check", "-c", tmp_path], capture_output=True, text=True)
            self.assertEqual(
                res.returncode, 0,
                f"sing-box syntax check failed: {res.stderr}\n{res.stdout}"
            )
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_clash_api_auth_and_connections(self):
        """Verify sing-box Clash API returns 401 without Bearer token and 200 with Bearer token."""
        import urllib.request
        import urllib.error
        import time

        check_bin = vpnguard.SINGBOX_BIN if os.path.exists(vpnguard.SINGBOX_BIN) else "sing-box"
        secret = "testsecret0123456789abcdef012345"
        test_port = 9097

        cfg = vpnguard.build_singbox_config(vpnguard.DEFAULT_RULES, relay_ip="1.2.3.4")
        cfg["experimental"]["clash_api"]["external_controller"] = f"127.0.0.1:{test_port}"
        cfg["experimental"]["clash_api"]["secret"] = secret
        # User-space loopback inbound for isolated test
        cfg["inbounds"] = [{
            "type": "mixed",
            "tag": "test-in",
            "listen": "127.0.0.1",
            "listen_port": 19998
        }]

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f, indent=2)
            tmp_path = f.name

        proc = None
        try:
            proc = subprocess.Popen([check_bin, "run", "-c", tmp_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.0)

            # 1. Without Auth -> 401
            with self.assertRaises(urllib.error.HTTPError) as ctx_no_auth:
                req = urllib.request.Request(f"http://127.0.0.1:{test_port}/connections")
                urllib.request.urlopen(req)
            self.assertEqual(ctx_no_auth.exception.code, 401, "Expected HTTP 401 Unauthorized without token")

            # 2. With Auth -> 200
            req = urllib.request.Request(f"http://127.0.0.1:{test_port}/connections")
            req.add_header("Authorization", f"Bearer {secret}")
            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertIn("connections", data)
                self.assertIn("downloadTotal", data)
                self.assertIn("uploadTotal", data)
        finally:
            if proc:
                proc.terminate()
                proc.wait()
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
