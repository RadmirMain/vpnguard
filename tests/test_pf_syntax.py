#!/usr/bin/env python3
"""
Test pf configuration syntax validation with pfctl -n -v -f
"""
import subprocess
import os
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

import vpnguard


class TestPFSyntax(unittest.TestCase):
    def test_pf_conf_syntax(self):
        pf_conf_path = os.path.join(PROJECT_ROOT, "src", "pf", "vpnguard.pf.conf")
        self.assertTrue(os.path.exists(pf_conf_path), f"File not found: {pf_conf_path}")

        res = subprocess.run(
            ["pfctl", "-n", "-v", "-f", pf_conf_path],
            capture_output=True,
            text=True
        )
        self.assertEqual(
            res.returncode, 0,
            f"pfctl syntax check failed:\nStdout: {res.stdout}\nStderr: {res.stderr}"
        )
        self.assertIn("group = 888", res.stdout)
        self.assertIn("group = 889", res.stdout)
        self.assertIn("group = 890", res.stdout)
        self.assertIn('anchor "egress" all', res.stdout)
        self.assertIn("block return out quick", res.stdout)
        self.assertIn("pass quick on lo0", res.stdout)
        self.assertIn("pass quick on utun99", res.stdout)
        self.assertIn("port = 53", res.stdout)
        self.assertIn("fe80::/10", res.stdout)
        self.assertIn("ipv6-icmp", res.stdout)

    def test_captive_pf_conf_syntax(self):
        captive_path = os.path.join(PROJECT_ROOT, "src", "pf", "vpnguard-captive.pf.conf")
        self.assertTrue(os.path.exists(captive_path), f"File not found: {captive_path}")

        res = subprocess.run(
            ["pfctl", "-n", "-v", "-f", captive_path],
            capture_output=True,
            text=True
        )
        self.assertEqual(
            res.returncode, 0,
            f"pfctl syntax check failed:\nStdout: {res.stdout}\nStderr: {res.stderr}"
        )
        self.assertIn("group = 888", res.stdout)
        self.assertIn("group = 889", res.stdout)
        self.assertIn("group = 890", res.stdout)
        self.assertIn("pass quick on lo0", res.stdout)
        self.assertIn("pass out quick all", res.stdout)

    def test_dynamic_egress_rule_syntax_non_443(self):
        rule = vpnguard.format_pf_egress_rule(["1.2.3.4", "5.6.7.8"], 8443)
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write(rule)
            tmp_path = f.name
        try:
            res = subprocess.run(["pfctl", "-n", "-v", "-f", tmp_path], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("port = 8443", res.stdout)
            self.assertIn("group = 889", res.stdout)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
