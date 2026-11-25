#!/usr/bin/env python3
"""
Test vpnguard-exec launcher behavior and proxy environment injection
"""
import unittest
import subprocess
import os
import sys
import json

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
HELPER_BIN = "/usr/local/bin/vpnguard-exec" if os.path.exists("/usr/local/bin/vpnguard-exec") else os.path.join(PROJECT_ROOT, "bin", "vpnguard-exec")

class TestLauncher(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.path.exists(HELPER_BIN), f"Helper binary not found: {HELPER_BIN}")

    def test_environment_injection(self):
        """Verify that vpnguard-exec injects HTTP_PROXY, HTTPS_PROXY, and ALL_PROXY."""
        code = (
            "import os, json, sys\n"
            "env_data = {\n"
            "    'HTTP_PROXY': os.environ.get('HTTP_PROXY'),\n"
            "    'http_proxy': os.environ.get('http_proxy'),\n"
            "    'HTTPS_PROXY': os.environ.get('HTTPS_PROXY'),\n"
            "    'https_proxy': os.environ.get('https_proxy'),\n"
            "    'ALL_PROXY': os.environ.get('ALL_PROXY'),\n"
            "    'all_proxy': os.environ.get('all_proxy'),\n"
            "    'NO_PROXY': os.environ.get('NO_PROXY'),\n"
            "    'BROWSER': os.environ.get('BROWSER'),\n"
            "    'CLAUDE': os.environ.get('CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC'),\n"
            "    'TZ': os.environ.get('TZ'),\n"
            "    'VPNGUARD_ACTIVE': os.environ.get('VPNGUARD_ACTIVE'),\n"
            "}\n"
            "print(json.dumps(env_data))\n"
        )
        res = subprocess.run([HELPER_BIN, sys.executable, "-c", code], capture_output=True, text=True)
        lines = [l.strip() for l in res.stdout.strip().split("\n") if l.strip().startswith("{")]
        self.assertTrue(len(lines) > 0, f"No JSON output from child: {res.stdout}\nStderr: {res.stderr}")
        data = json.loads(lines[0])
        # HTTP proxy port: 18089 (new dedicated) or 18088 (pre-upgrade)
        self.assertTrue("18089" in data["HTTP_PROXY"] or "18088" in data["HTTP_PROXY"])
        self.assertTrue("18089" in data["HTTPS_PROXY"] or "18088" in data["HTTPS_PROXY"])
        self.assertIn("18088", data["ALL_PROXY"])
        self.assertIn("127.0.0.1", data.get("NO_PROXY", ""))
        self.assertEqual(data["BROWSER"], "/usr/local/bin/vpnguard-browser")
        self.assertEqual(data["CLAUDE"], "1")
        self.assertTrue(bool(data["TZ"]))
        self.assertEqual(data["VPNGUARD_ACTIVE"], "1")

if __name__ == "__main__":
    unittest.main()
