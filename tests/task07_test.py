import importlib.util
import ipaddress
import json
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("task07_helper", ROOT / "scripts/task07/helper.py")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class Task07HelperTests(unittest.TestCase):
    def test_client_network_does_not_overlap_task06_or_ru_wan(self):
        self.assertFalse(helper.NETWORK.overlaps(ipaddress.ip_network("10.203.254.0/30")))
        self.assertFalse(helper.NETWORK.overlaps(ipaddress.ip_network("137.22.146.0/24")))
        self.assertEqual(str(helper.NETWORK), "10.203.253.0/24")

    def test_task08_test_profile_captures_ipv4_ipv6_and_dns(self):
        text = helper.render_profile("SERVER_PUBLIC", "CLIENT_PRIVATE")
        self.assertIn("Address = 10.203.253.2/32", text)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", text)
        self.assertIn("Endpoint = 137.22.146.212:51821", text)
        self.assertIn("Jc = 4\nJmin = 64\nJmax = 256", text)
        self.assertIn("DNS = 10.203.253.1", text)

    def test_interface_identity_requires_nonce_index_and_awg_type(self):
        state = {"iface": helper.IFACE, "nonce": "a" * 32, "ifindex": 9,
                 "phase": "active", "implementation": "userspace"}
        link = {"ifname": helper.IFACE, "ifalias": helper.ALIAS_PREFIX + state["nonce"],
                "ifindex": 9, "flags": ["POINTOPOINT"], "linkinfo": {"info_kind": "tun"}}
        helper.verify_owned(state, link)
        for field, value in (("ifalias", "foreign"), ("ifindex", 10)):
            altered = dict(link)
            altered[field] = value
            with self.assertRaises(helper.Refusal):
                helper.verify_owned(state, altered)
        altered = dict(link)
        altered["linkinfo"] = {"info_kind": "wireguard"}
        with self.assertRaises(helper.Refusal):
            helper.verify_owned(state, altered)

    def test_new_address_conflict_is_detected(self):
        address_json = json.dumps([{"ifname": "eth0", "addr_info": [
            {"local": "10.203.253.77", "prefixlen": 24}]}])
        with patch.object(helper, "run", side_effect=[address_json]):
            with self.assertRaisesRegex(helper.Refusal, "address"):
                helper.check_address_conflicts()

    def test_new_route_conflict_is_detected(self):
        address_json = json.dumps([])
        route_json = json.dumps([{"dst": "10.203.253.0/24", "dev": "eth0"}])
        with patch.object(helper, "run", side_effect=[address_json, route_json]):
            with self.assertRaisesRegex(helper.Refusal, "route"):
                helper.check_address_conflicts()

    def test_occupied_port_is_detected_before_awg_port_query(self):
        address_json = json.dumps([])
        route_json = json.dumps([])
        with patch.object(helper, "run", side_effect=[address_json, route_json, "udp socket"]):
            with self.assertRaisesRegex(helper.Refusal, "port"):
                helper.check_address_conflicts()

    def test_helper_never_invokes_a_shell_or_quick_script(self):
        source = (ROOT / "scripts/task07/helper.py").read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("awg-quick", source)
        self.assertNotIn("wg-quick", source)
        self.assertNotIn("eval(", source)


if __name__ == "__main__":
    unittest.main()
