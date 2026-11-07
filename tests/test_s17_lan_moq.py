"""S17 RFC1918 MoQ LAN opt-in security contract (subprocess mocked).

These tests do not claim actual cross-machine connectivity. Rust CLI tests and
an independent two-machine deployment remain mandatory verification gates.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from music_catalogue.live_conductor import ConductorBridgeError
from music_catalogue.moq_conductor import _bound_local_url
from music_catalogue.moq_repair import repair_missing_ciphertext_over_moq
import test_s9_moq as s9_fixture
import test_s15_selective_moq_repair as s15_fixture


class S17EndpointPolicyTests(unittest.TestCase):
    def test_default_loopback_preserved_and_remote_denied(self):
        self.assertEqual(_bound_local_url("https://127.0.0.1:4567"), "https://127.0.0.1:4567")
        for url in ("https://192.168.1.20:4567", "https://172.20.1.2:4321", "https://10.3.4.5:1000"):
            with self.subTest(url=url), self.assertRaises(ConductorBridgeError):
                _bound_local_url(url)

    def test_explicit_lan_accepts_only_three_rfc1918_ranges(self):
        for host in ("10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.20.21"):
            with self.subTest(host=host):
                url = f"https://{host}:9876"
                self.assertEqual(_bound_local_url(url, allow_lan=True), url)

    def test_public_dns_linklocal_credentials_and_paths_all_rejected(self):
        bad = [
            "https://1.1.1.1:443", "https://8.8.8.8:443", "https://100.64.1.1:443",
            "https://169.254.1.20:443", "https://224.0.0.1:443", "https://0.0.0.0:443",
            "https://router.local:443", "https://private.example.org:443", "https://[::1]:443",
            "http://192.168.1.2:443", "https://user@192.168.1.2:443",
            "https://pass:word@192.168.1.2:443", "https://192.168.1.2:443/path",
            "https://192.168.1.2:443?x=1", "https://192.168.1.2:443#frag",
            "https://192.168.1.2:0", "https://192.168.1.2", "https://192.168.1.2:99999",
            "https://192.168.001.002:443", "https://192.168.1.2:443/",
        ]
        for url in bad:
            with self.subTest(url=url), self.assertRaises(ConductorBridgeError):
                _bound_local_url(url, allow_lan=True)

    def test_nonbool_lan_flag_is_rejected(self):
        for setting in (1, "true", object(), None):
            with self.subTest(setting=setting), self.assertRaises(ConductorBridgeError):
                _bound_local_url("https://192.168.1.2:4443", allow_lan=setting)


class S17TrustedConductorLanTests(unittest.TestCase):
    def setUp(self):
        # Reuse exact S9 signed-manifest, Holochain action/agent and S4 receipt
        # fixture. The mock never changes the trust anchors or certificate pin.
        self.fixture = s9_fixture.S9BridgeContractTests("test_verified_metadata_pins_real_receiver_arguments")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture._original_receipt = self.fixture.receipt
        self.fixture.endpoint.body["url"] = "https://192.168.20.21:4443"
        self.fixture.envelope["moq_endpoint"]["body"]["url"] = "https://192.168.20.21:4443"

    def test_verified_remote_lan_endpoint_pins_receiver_without_readiness_json(self):
        observed = []
        original = self.fixture._run
        def intercept(argv, **kwargs):
            observed.append(list(argv))
            return original(argv, **kwargs)
        self.fixture._run = intercept
        self.fixture.kwargs["allow_lan_moq"] = True
        result = self.fixture.call()
        self.assertTrue(result["verified"])
        self.assertEqual(self.fixture.moq_calls, 1)
        self.assertIn("--allow-lan", observed[-1])
        self.assertEqual(observed[-1][observed[-1].index("--url") + 1], "https://192.168.20.21:4443")
        self.assertEqual(observed[-1][observed[-1].index("--cert-fingerprint-hex") + 1], "5" * 64)

    def test_remote_without_optin_refuses_before_moq_and_before_s4(self):
        with self.assertRaises(ConductorBridgeError):
            self.fixture.call()
        self.assertEqual(self.fixture.moq_calls, 0)
        self.assertEqual(self.fixture.manifest_calls, 0)

    def test_wrong_holochain_endpoint_author_still_refused_in_lan_mode(self):
        self.fixture.kwargs["allow_lan_moq"] = True
        self.fixture.envelope["moq_endpoint"]["author"] = self.fixture.alice
        with self.assertRaises(ConductorBridgeError):
            self.fixture.call()
        self.assertEqual(self.fixture.moq_calls, 0)
        self.assertEqual(self.fixture.manifest_calls, 0)

    def test_public_holochain_endpoint_refused_despite_optin(self):
        self.fixture.kwargs["allow_lan_moq"] = True
        self.fixture.endpoint.body["url"] = "https://8.8.8.8:4443"
        self.fixture.envelope["moq_endpoint"]["body"]["url"] = "https://8.8.8.8:4443"
        with self.assertRaises(ConductorBridgeError):
            self.fixture.call()
        self.assertEqual(self.fixture.moq_calls, 0)


class S17SelectiveRepairLanTests(unittest.TestCase):
    def setUp(self):
        self.fixture = s15_fixture.S15SelectiveMoqRepairTests("test_missing_one_object_is_repaired_only_via_pinned_moq")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_repair_lan_optin_propagates_to_pinned_rust_cli(self):
        original = self.fixture.fake_receiver
        def fake(argv, **kwargs):
            self.assertEqual(argv[-1], "--allow-lan")
            self.assertEqual(argv[argv.index("--url") + 1], "https://10.10.4.5:43213")
            return original(argv[:-1], **kwargs)
        with patch("music_catalogue.moq_repair.subprocess.run", side_effect=fake):
            result = repair_missing_ciphertext_over_moq(
                **{**self.fixture.args(), "moq_url": "https://10.10.4.5:43213", "allow_lan_moq": True})
        self.assertEqual(result["recovered_objects"], 1)

    def test_repair_requires_explicit_lan_optin(self):
        with patch("music_catalogue.moq_repair.subprocess.run") as proc:
            with self.assertRaises(Exception):
                repair_missing_ciphertext_over_moq(
                    **{**self.fixture.args(), "moq_url": "https://10.10.4.5:43213"})
        proc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
