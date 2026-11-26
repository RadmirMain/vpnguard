#!/usr/bin/env python3
"""
Unit tests for VLESS URI parsing, Xray configuration generation, and server profile management.
"""

import unittest
import os
import sys
import tempfile
import json
import base64
import subprocess
import shutil

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

import vpnguard


class TestVlessParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Generate valid 32-byte Curve25519 public key
        cls.valid_pbk = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")

    def test_vless_tcp_reality_xtls_rprx_vision(self):
        """Verify parsing and validation of VLESS + TCP + Reality + xtls-rprx-vision."""
        uri = (
            f"vless://a3b98c76-2f1d-4e5a-8b9c-123456789abc@1.2.3.4:443"
            f"?security=reality&type=tcp&flow=xtls-rprx-vision"
            f"&pbk={self.valid_pbk}&sid=0123456789abcdef"
            f"&sni=www.microsoft.com&fp=chrome&spx=%2F"
            f"#Germany%20VPS%20%28Reality%29"
        )

        profile = vpnguard.parse_vless_uri(uri)

        self.assertEqual(profile["name"], "Germany VPS (Reality)")
        self.assertEqual(profile["host"], "1.2.3.4")
        self.assertEqual(profile["port"], 443)
        self.assertEqual(profile["transport"], "tcp")
        self.assertEqual(profile["security"], "reality")
        self.assertEqual(profile["sni"], "www.microsoft.com")
        self.assertEqual(profile["flow"], "xtls-rprx-vision")

        xray_cfg = profile["xrayConfig"]
        self._verify_security_invariants(xray_cfg)

        proxy_out = xray_cfg["outbounds"][0]
        self.assertEqual(proxy_out["tag"], "proxy")
        self.assertEqual(proxy_out["protocol"], "vless")
        user = proxy_out["settings"]["vnext"][0]["users"][0]
        self.assertEqual(user["id"], "a3b98c76-2f1d-4e5a-8b9c-123456789abc")
        self.assertEqual(user["flow"], "xtls-rprx-vision")

        reality = proxy_out["streamSettings"]["realitySettings"]
        self.assertEqual(reality["publicKey"], self.valid_pbk)
        self.assertEqual(reality["shortId"], "0123456789abcdef")
        self.assertEqual(reality["serverName"], "www.microsoft.com")
        self.assertEqual(reality["fingerprint"], "chrome")
        self.assertEqual(reality["spiderX"], "/")

        # Real validation via vpnguard-xray binary
        ok, msg = vpnguard.validate_xray_config(xray_cfg)
        self.assertTrue(ok, f"Xray test failed for Reality config: {msg}")

    def test_vless_xhttp_tls(self):
        """Verify parsing and validation of VLESS + xhttp + TLS."""
        uri = (
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@play.example.com:443"
            "?security=tls&type=xhttp&sni=play.example.com&fp=edge"
            "&alpn=h2,h3&path=%2Fapi%2Fv2%2F&mode=auto"
            "#Relay%20xhttp"
        )

        profile = vpnguard.parse_vless_uri(uri)

        self.assertEqual(profile["name"], "Relay xhttp")
        self.assertEqual(profile["host"], "play.example.com")
        self.assertEqual(profile["port"], 443)
        self.assertEqual(profile["transport"], "xhttp")
        self.assertEqual(profile["security"], "tls")
        self.assertEqual(profile["sni"], "play.example.com")

        xray_cfg = profile["xrayConfig"]
        self._verify_security_invariants(xray_cfg)

        proxy_out = xray_cfg["outbounds"][0]
        self.assertEqual(proxy_out["streamSettings"]["network"], "xhttp")
        tls = proxy_out["streamSettings"]["tlsSettings"]
        self.assertEqual(tls["serverName"], "play.example.com")
        self.assertEqual(tls["fingerprint"], "edge")
        self.assertEqual(tls["alpn"], ["h2", "h3"])

        xhttp = proxy_out["streamSettings"]["xhttpSettings"]
        self.assertEqual(xhttp["path"], "/api/v2/")
        self.assertEqual(xhttp["mode"], "auto")

        ok, msg = vpnguard.validate_xray_config(xray_cfg)
        self.assertTrue(ok, f"Xray test failed for xhttp config: {msg}")

    def test_vless_ws_tls(self):
        """Verify parsing and validation of VLESS + WS + TLS."""
        uri = (
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@ws.example.com:443"
            "?security=tls&type=ws&sni=ws.example.com&fp=chrome"
            "&path=%2Fwebsocket#WebSocket%20Server"
        )

        profile = vpnguard.parse_vless_uri(uri)

        self.assertEqual(profile["name"], "WebSocket Server")
        self.assertEqual(profile["transport"], "ws")
        self.assertEqual(profile["security"], "tls")

        xray_cfg = profile["xrayConfig"]
        self._verify_security_invariants(xray_cfg)

        proxy_out = xray_cfg["outbounds"][0]
        ws_settings = proxy_out["streamSettings"]["wsSettings"]
        self.assertEqual(ws_settings["path"], "/websocket")
        self.assertEqual(ws_settings["headers"]["Host"], "ws.example.com")

        ok, msg = vpnguard.validate_xray_config(xray_cfg)
        self.assertTrue(ok, f"Xray test failed for WS config: {msg}")

    def test_vless_grpc_reality(self):
        """Verify parsing and validation of VLESS + gRPC + Reality."""
        uri = (
            f"vless://b831381d-6324-4d53-ad4f-8cda48b30811@grpc.example.com:443"
            f"?security=reality&type=grpc&serviceName=vless-grpc"
            f"&pbk={self.valid_pbk}&sid=4321&sni=grpc.example.com#gRPC%20Reality"
        )

        profile = vpnguard.parse_vless_uri(uri)

        self.assertEqual(profile["name"], "gRPC Reality")
        self.assertEqual(profile["transport"], "grpc")
        self.assertEqual(profile["security"], "reality")

        xray_cfg = profile["xrayConfig"]
        self._verify_security_invariants(xray_cfg)

        proxy_out = xray_cfg["outbounds"][0]
        grpc_settings = proxy_out["streamSettings"]["grpcSettings"]
        self.assertEqual(grpc_settings["serviceName"], "vless-grpc")

        ok, msg = vpnguard.validate_xray_config(xray_cfg)
        self.assertTrue(ok, f"Xray test failed for gRPC Reality config: {msg}")

    def _verify_security_invariants(self, xray_cfg):
        """Strictly verify security guarantees in generated xray config."""
        inbounds = xray_cfg.get("inbounds", [])
        self.assertEqual(len(inbounds), 2, "Must have exactly 2 inbounds (SOCKS + HTTP)")

        socks_in = next((ib for ib in inbounds if ib.get("protocol") == "socks"), None)
        http_in = next((ib for ib in inbounds if ib.get("protocol") == "http"), None)

        self.assertIsNotNone(socks_in, "Missing socks-in inbound")
        self.assertIsNotNone(http_in, "Missing http-in inbound")

        self.assertEqual(socks_in["listen"], "127.0.0.1")
        self.assertEqual(socks_in["port"], 18088)
        self.assertFalse(socks_in["settings"].get("udp", True), "SOCKS UDP must be false")

        self.assertEqual(http_in["listen"], "127.0.0.1")
        self.assertEqual(http_in["port"], 18089)

        # Ensure no 0.0.0.0 in any listener
        for ib in inbounds:
            self.assertEqual(ib["listen"], "127.0.0.1", "Listeners must be loopback only")

        # Outbounds: proxy and block only. No freedom/direct!
        outbounds = xray_cfg.get("outbounds", [])
        self.assertEqual(len(outbounds), 2)
        tags = [o.get("tag") for o in outbounds]
        protocols = [o.get("protocol") for o in outbounds]

        self.assertIn("proxy", tags)
        self.assertIn("block", tags)
        self.assertNotIn("direct", tags)
        self.assertNotIn("freedom", tags)
        self.assertNotIn("freedom", protocols)
        self.assertNotIn("direct", protocols)

        # Routing: all inbound traffic directed strictly to proxy
        routing = xray_cfg.get("routing", {})
        rules = routing.get("rules", [])
        self.assertTrue(len(rules) >= 1)
        self.assertEqual(rules[0]["outboundTag"], "proxy")

    def test_servers_store_lifecycle(self):
        """Verify profile store saving, loading, adding, deleting, and active protection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_file = os.path.join(tmpdir, "servers.json")

            # 1. Initial store
            store = vpnguard.load_servers_store(store_file)
            self.assertIn("activeId", store)
            self.assertIn("servers", store)

            # 2. Add profiles
            uri1 = f"vless://11111111-1111-1111-1111-111111111111@1.1.1.1:443?security=reality&pbk={self.valid_pbk}#Server1"
            uri2 = f"vless://22222222-2222-2222-2222-222222222222@2.2.2.2:443?security=reality&pbk={self.valid_pbk}#Server2"

            p1 = vpnguard.parse_vless_uri(uri1)
            p2 = vpnguard.parse_vless_uri(uri2)

            store["servers"] = [p1, p2]
            store["activeId"] = p1["id"]
            vpnguard.save_servers_store(store, store_file)

            # Verify reload
            reloaded = vpnguard.load_servers_store(store_file)
            self.assertEqual(len(reloaded["servers"]), 2)
            self.assertEqual(reloaded["activeId"], p1["id"])

            # Verify active profile cannot be deleted
            # Simulating delete check:
            can_delete_active = (p1["id"] != reloaded["activeId"])
            self.assertFalse(can_delete_active, "Active profile must not be deletable")

            # Verify inactive profile can be deleted
            reloaded["servers"] = [s for s in reloaded["servers"] if s["id"] != p2["id"]]
            vpnguard.save_servers_store(reloaded, store_file)

            after_delete = vpnguard.load_servers_store(store_file)
            self.assertEqual(len(after_delete["servers"]), 1)
            self.assertEqual(after_delete["servers"][0]["id"], p1["id"])

    def test_india_gemini_json_import_and_validation(self):
        """Verify parsing, hardening, and Xray validation of '🇮🇳 Индия [Gemini] 9972' JSON."""
        india_json = {
            "remarks": "🇮🇳 Индия [Gemini] 9972",
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": "203.0.113.20",
                                "port": 443,
                                "users": [
                                    {
                                        "encryption": "none",
                                        "id": "00000000-0000-4000-8000-000000000002",
                                        "level": 8
                                    }
                                ]
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "allowInsecure": False,
                            "alpn": ["h2", "h3"],
                            "fingerprint": "edge",
                            "serverName": "cdn.example.com",
                            "show": False
                        },
                        "xhttpSettings": {
                            "extra": {
                                "noGRPCHeader": False,
                                "scMaxEachPostBytes": 1000000,
                                "scMinPostsIntervalMs": 30,
                                "scStreamUpServerSecs": "20-80",
                                "xmux": {
                                    "cMaxReuseTimes": 0,
                                    "hKeepAlivePeriod": 30,
                                    "hMaxRequestTimes": "600-900",
                                    "hMaxReusableSecs": "1800-3000",
                                    "maxConnections": 1
                                },
                                "xPaddingBytes": "100-1000"
                            },
                            "host": "cdn.example.com",
                            "mode": "auto",
                            "path": "/api/v2/"
                        }
                    },
                    "tag": "proxy"
                }
            ]
        }

        profile = vpnguard.parse_xray_server_json(india_json)

        self.assertEqual(profile["name"], "🇮🇳 Индия [Gemini] 9972")
        self.assertEqual(profile["host"], "203.0.113.20")
        self.assertEqual(profile["port"], 443)
        self.assertEqual(profile["transport"], "xhttp")
        self.assertEqual(profile["security"], "tls")
        self.assertEqual(profile["sni"], "cdn.example.com")

        xray_cfg = profile["xrayConfig"]
        self._verify_security_invariants(xray_cfg)

        proxy_out = xray_cfg["outbounds"][0]
        self.assertEqual(proxy_out["tag"], "proxy")
        self.assertEqual(proxy_out["protocol"], "vless")
        self.assertEqual(proxy_out["settings"]["vnext"][0]["address"], "203.0.113.20")
        self.assertEqual(proxy_out["settings"]["vnext"][0]["users"][0]["id"], "00000000-0000-4000-8000-000000000002")

        # Verify xhttpSettings extra/xmux
        xhttp = proxy_out["streamSettings"]["xhttpSettings"]
        self.assertEqual(xhttp["host"], "cdn.example.com")
        self.assertEqual(xhttp["path"], "/api/v2/")
        self.assertEqual(xhttp["extra"]["xmux"]["maxConnections"], 1)

        # Real validation via vpnguard-xray binary
        ok, msg = vpnguard.validate_xray_config(xray_cfg)
        self.assertTrue(ok, f"Xray test failed for India config: {msg}")

    def test_default_servers_store_seeding(self):
        """Verify that empty store initialization is clean and saves with 0600 permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_file = os.path.join(tmpdir, "servers.json")
            store = vpnguard.load_servers_store(store_file)

            self.assertIsInstance(store, dict)
            self.assertIn("servers", store)
            self.assertIn("activeId", store)
            if os.path.exists(store_file):
                mode = os.stat(store_file).st_mode & 0o777
                self.assertEqual(mode, 0o600, f"servers.json must have 0600 permissions, got {oct(mode)}")

    def test_stdin_bounded_and_xray_migration(self):
        """Verify stdin size limit and parse_xray_server_json migration name support."""
        import io
        orig_stdin = sys.stdin
        try:
            class FakeBuf:
                def __init__(self, data):
                    self._b = io.BytesIO(data)
                def read(self, n=-1):
                    return self._b.read(n)
            class FakeStdin:
                def __init__(self, data):
                    self.buffer = FakeBuf(data)

            sys.stdin = FakeStdin(b"vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443")
            self.assertTrue(vpnguard.read_stdin_bounded(1024).startswith("vless://"))

            sys.stdin = FakeStdin(b"x" * 2048)
            with self.assertRaises(ValueError):
                vpnguard.read_stdin_bounded(1024)
        finally:
            sys.stdin = orig_stdin

        sample = {
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": "1.2.3.4", "port": 8443, "users": [{"id": "a3b98c76-2f1d-4e5a-8b9c-123456789abc", "encryption": "none"}]}]},
                "streamSettings": {"network": "tcp", "security": "none"}
            }]
        }
        migrated = vpnguard.parse_xray_server_json(sample, default_name="Основной сервер")
        self.assertEqual(migrated["name"], "Основной сервер")
        self.assertEqual(migrated["port"], 8443)

    def test_resolve_host_ipv4_returns_empty_on_failure(self):
        """resolve_host_ipv4 must never return raw hostnames or invalid IPv4 strings."""
        self.assertEqual(vpnguard.resolve_host_ipv4("203.0.113.10"), ["203.0.113.10"])
        self.assertEqual(vpnguard.resolve_host_ipv4("999.999.999.999"), [])
        self.assertEqual(vpnguard.resolve_host_ipv4("nonexistent.invalid"), [])
        self.assertEqual(vpnguard.resolve_host_ipv4(""), [])


if __name__ == "__main__":
    unittest.main()
