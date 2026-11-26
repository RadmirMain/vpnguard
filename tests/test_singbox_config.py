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

    def test_domain_specificity_precedence_shared_across_dns_and_route(self):
        """More specific domains (more labels) precede broader suffixes in both dns.rules and route.rules."""
        import copy
        rules = copy.deepcopy(vpnguard.DEFAULT_RULES)
        # Simulate UI appending special.ru -> proxy after .ru -> direct, plus 3-level interleaving
        # (sub.a.example.com -> proxy > a.example.com -> direct > local.example.com -> direct > example.com -> proxy),
        # plus explicit user override perplexity.ai -> direct against aiServicesProxy preset,
        # plus tie-break conflict on github.com (proxy in DEFAULT_RULES vs direct appended -> proxy wins), plus a block rule.
        rules["domains"].extend([
            {"id": "d-ru-proxy", "domain": "special.ru", "action": "proxy", "enabled": True},
            {"id": "d-ex-proxy", "domain": "example.com", "action": "proxy", "enabled": True},
            {"id": "d-ex-direct", "domain": "local.example.com", "action": "direct", "enabled": True},
            {"id": "d-a-ex-direct", "domain": "a.example.com", "action": "direct", "enabled": True},
            {"id": "d-sub-a-ex-proxy", "domain": "sub.a.example.com", "action": "proxy", "enabled": True},
            {"id": "d-perp-direct", "domain": "perplexity.ai", "action": "direct", "enabled": True},
            {"id": "d-gh-direct", "domain": "github.com", "action": "direct", "enabled": True},
            {"id": "d-ads-block", "domain": "ads.example.com", "action": "block", "enabled": True},
        ])
        cfg = vpnguard.build_singbox_config(rules, relay_ip="203.0.113.10")

        route_domain_rules = [
            (r["domain_suffix"][0], r["outbound"])
            for r in cfg["route"]["rules"]
            if "domain_suffix" in r
        ]
        idx = {dom: (i, out) for i, (dom, out) in enumerate(route_domain_rules)}

        # 1. special.ru (proxy) MUST precede .ru (direct)
        self.assertLess(idx["special.ru"][0], idx[".ru"][0])
        self.assertEqual(idx["special.ru"][1], "xray-upstream")
        self.assertEqual(idx[".ru"][1], "direct")

        # 2. 3-level interleaving and 2-level direct override MUST preserve strict specificity order
        self.assertLess(idx["sub.a.example.com"][0], idx["a.example.com"][0])
        self.assertLess(idx["a.example.com"][0], idx["example.com"][0])
        self.assertLess(idx["local.example.com"][0], idx["example.com"][0])
        self.assertEqual(idx["sub.a.example.com"][1], "xray-upstream")
        self.assertEqual(idx["a.example.com"][1], "direct")
        self.assertEqual(idx["local.example.com"][1], "direct")
        self.assertEqual(idx["example.com"][1], "xray-upstream")

        # 3. User explicit perplexity.ai -> direct overrides aiServicesProxy preset; equal-source conflict github.com resolves fail-safe to proxy
        self.assertEqual(idx["perplexity.ai"][1], "direct")
        self.assertEqual(idx["github.com"][1], "xray-upstream")
        self.assertEqual(idx["ads.example.com"][1], "block")

        # 4. DNS rules reflect identical ordering and batch ONLY contiguous elements
        dns_flat = []
        dns_rule_bucket_idx = {}
        for r_i, dr in enumerate(cfg["dns"]["rules"]):
            if "domain_suffix" in dr:
                target = dr.get("server") or dr.get("action")
                for d in dr["domain_suffix"]:
                    dns_flat.append((d, target))
                    dns_rule_bucket_idx[d] = (r_i, target)
        dns_idx = {d: (i, t) for i, (d, t) in enumerate(dns_flat)}
        self.assertLess(dns_idx["special.ru"][0], dns_idx[".ru"][0])
        self.assertEqual(dns_idx["special.ru"][1], "dns-remote")
        self.assertLess(dns_idx["sub.a.example.com"][0], dns_idx["a.example.com"][0])
        self.assertLess(dns_idx["a.example.com"][0], dns_idx["example.com"][0])
        self.assertLess(dns_idx["local.example.com"][0], dns_idx["example.com"][0])
        self.assertEqual(dns_idx["sub.a.example.com"][1], "dns-remote")
        self.assertEqual(dns_idx["a.example.com"][1], "dns-direct")
        self.assertEqual(dns_idx["local.example.com"][1], "dns-direct")
        self.assertEqual(dns_idx["example.com"][1], "dns-remote")
        self.assertNotEqual(dns_rule_bucket_idx["sub.a.example.com"][0], dns_rule_bucket_idx["example.com"][0])
        self.assertEqual(dns_idx["perplexity.ai"][1], "dns-direct")
        self.assertEqual(dns_idx["github.com"][1], "dns-remote")
        self.assertEqual(dns_idx["ads.example.com"][1], "reject")

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

    def test_desired_state_and_cmd_on_pf_boot_order(self):
        """cmd_on writes desired_state='on' before PF boot, arms PF before daemons, and aborts on PF failure."""
        import argparse
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "desired_state")
            self.assertEqual(vpnguard.read_desired_state(state_file), "on")
            vpnguard.write_desired_state("off", state_file)
            self.assertEqual(vpnguard.read_desired_state(state_file), "off")
            with self.assertRaises(ValueError):
                vpnguard.write_desired_state("invalid", state_file)

            events = []

            def fake_write_state(st, state_path=vpnguard.DESIRED_STATE_PATH):
                events.append(("write_state", st))

            def fake_run(cmd, **kwargs):
                events.append(("run", cmd[:3]))
                if cmd and cmd[0] == "/usr/local/libexec/vpnguard-pf-boot.sh":
                    return mock.MagicMock(returncode=1, stderr="pf syntax boom", stdout="")
                return mock.MagicMock(returncode=0, stderr="", stdout="")

            with mock.patch("os.geteuid", return_value=0), \
                 mock.patch.object(vpnguard, "_clear_pause_state"), \
                 mock.patch.object(vpnguard, "write_desired_state", side_effect=fake_write_state), \
                 mock.patch.object(vpnguard, "get_active_relay_endpoint", return_value=(["203.0.113.10"], 443)), \
                 mock.patch.object(vpnguard, "write_pf_egress_file"), \
                 mock.patch.object(vpnguard, "build_singbox_config", return_value={"route": {"final": "xray-upstream"}}), \
                 mock.patch.object(vpnguard, "atomic_write_text"), \
                 mock.patch.object(vpnguard, "sync_active_server_metadata"), \
                 mock.patch("os.replace"), \
                 mock.patch("os.chmod"), \
                 mock.patch("subprocess.run", side_effect=fake_run):
                rc = vpnguard.cmd_on(argparse.Namespace(json=True, fast=True))

            self.assertEqual(rc, 1)
            check_idx = next(i for i, e in enumerate(events) if e[0] == "run" and len(e[1]) >= 2 and e[1][1] == "check")
            state_idx = events.index(("write_state", "on"))
            pf_idx = next(i for i, e in enumerate(events) if e[0] == "run" and e[1][0] == "/usr/local/libexec/vpnguard-pf-boot.sh")
            self.assertLess(check_idx, state_idx)
            self.assertLess(state_idx, pf_idx)
            # Daemons must NOT be kickstarted after PF failure
            self.assertFalse(any(e[0] == "run" and "kickstart" in e[1] for e in events))

            # If sing-box check fails, desired_state='on' must NOT be written
            events_fail = []

            def fake_write_fail(st, state_path=vpnguard.DESIRED_STATE_PATH):
                events_fail.append(("write_state", st))

            def fake_run_check_fail(cmd, **kwargs):
                events_fail.append(("run", cmd[:3]))
                if cmd and len(cmd) >= 2 and cmd[1] == "check":
                    return mock.MagicMock(returncode=1, stderr="bad singbox json", stdout="")
                return mock.MagicMock(returncode=0, stderr="", stdout="")

            with mock.patch("os.geteuid", return_value=0), \
                 mock.patch.object(vpnguard, "_clear_pause_state"), \
                 mock.patch.object(vpnguard, "write_desired_state", side_effect=fake_write_fail), \
                 mock.patch.object(vpnguard, "get_active_relay_endpoint", return_value=(["203.0.113.10"], 443)), \
                 mock.patch.object(vpnguard, "write_pf_egress_file"), \
                 mock.patch.object(vpnguard, "build_singbox_config", return_value={"route": {"final": "xray-upstream"}}), \
                 mock.patch.object(vpnguard, "atomic_write_text"), \
                 mock.patch("os.path.exists", side_effect=lambda p: False if ".tmp_" in str(p) else True), \
                 mock.patch("subprocess.run", side_effect=fake_run_check_fail):
                rc2 = vpnguard.cmd_on(argparse.Namespace(json=True, fast=True))

            self.assertEqual(rc2, 1)
            self.assertFalse(any(e[0] == "write_state" for e in events_fail))


if __name__ == "__main__":
    unittest.main()
