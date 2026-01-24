#!/usr/bin/env python3
"""
Tests for PCAP-Intel TUI v2.0 Features

Tests:
- Session persistence (save/load)
- Advanced filtering (parse/match)
- Timeline panel (event tracking)
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from tui.session_storage import SessionStorage, create_session_storage
from tui.advanced_filter import AdvancedFilter, FILTER_PRESETS
from tui.timeline_panel import TimelinePanel, ActivityType


class TestSessionStorage(unittest.TestCase):
    """Test session persistence."""

    def setUp(self):
        """Create temp database."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_session.db")
        self.storage = SessionStorage(db_path=self.db_path)

    def tearDown(self):
        """Cleanup."""
        self.storage.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        os.rmdir(self.temp_dir)

    def test_save_and_load_hosts(self):
        """Test host save/load."""
        hosts = {
            "10.0.0.1": {
                "os": "Windows 10",
                "services": {22, 445, 3389},
                "dns": "workstation1.local",
                "first_seen": datetime.now(),
                "creds": [],
                "flows": [],
            },
            "192.168.1.100": {
                "os": "Linux",
                "services": {80, 443},
                "dns": None,
                "first_seen": datetime.now(),
                "creds": [],
                "flows": [],
            }
        }
        compromised = {"10.0.0.1"}

        self.storage.save_hosts(hosts, compromised)
        loaded_hosts, loaded_compromised = self.storage.load_hosts()

        self.assertEqual(len(loaded_hosts), 2)
        self.assertIn("10.0.0.1", loaded_hosts)
        self.assertEqual(loaded_hosts["10.0.0.1"]["os"], "Windows 10")
        self.assertEqual(loaded_hosts["10.0.0.1"]["services"], {22, 445, 3389})
        self.assertIn("10.0.0.1", loaded_compromised)

    def test_save_and_load_flows(self):
        """Test flow save/load."""
        flows = {
            "10.0.0.1:192.168.1.1:443": {
                "src": "10.0.0.1",
                "dst": "192.168.1.1",
                "port": 443,
                "proto": "TCP",
                "count": 42,
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
            }
        }

        self.storage.save_flows(flows)
        loaded = self.storage.load_flows()

        self.assertEqual(len(loaded), 1)
        self.assertIn("10.0.0.1:192.168.1.1:443", loaded)
        self.assertEqual(loaded["10.0.0.1:192.168.1.1:443"]["count"], 42)

    def test_save_and_load_dns(self):
        """Test DNS save/load."""
        dns = {
            "google.com": ["142.250.80.46"],
            "example.org": ["93.184.216.34", "93.184.216.35"]
        }

        self.storage.save_dns(dns)
        loaded = self.storage.load_dns()

        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded["google.com"], ["142.250.80.46"])
        self.assertEqual(len(loaded["example.org"]), 2)

    def test_metadata(self):
        """Test metadata storage."""
        self.storage.set_metadata("test_key", "test_value")
        self.assertEqual(self.storage.get_metadata("test_key"), "test_value")

        self.storage.set_metadata("version", "2.0.0")
        self.assertEqual(self.storage.get_metadata("version"), "2.0.0")


class TestAdvancedFilter(unittest.TestCase):
    """Test advanced filtering."""

    def setUp(self):
        """Create filter instance."""
        self.filter = AdvancedFilter()

    def test_parse_ip_filter(self):
        """Test IP filter parsing."""
        self.assertTrue(self.filter.parse("ip 10.0.0.1"))
        self.assertTrue(self.filter.is_active)

    def test_parse_cidr_filter(self):
        """Test CIDR filter parsing."""
        self.assertTrue(self.filter.parse("ip 10.0.0.0/24"))
        self.assertTrue(self.filter.is_active)

    def test_parse_port_filter(self):
        """Test port filter parsing."""
        self.assertTrue(self.filter.parse("port 445"))
        self.assertTrue(self.filter.is_active)

    def test_parse_multiple_ports(self):
        """Test multiple port filter."""
        self.assertTrue(self.filter.parse("port 22,445,3389"))
        self.assertTrue(self.filter.is_active)

    def test_parse_protocol_filter(self):
        """Test protocol filter."""
        self.assertTrue(self.filter.parse("proto smb"))
        self.assertTrue(self.filter.is_active)

    def test_parse_compound_filter(self):
        """Test compound filter with AND."""
        self.assertTrue(self.filter.parse("ip 10.0.0.0/24 and port 445"))
        self.assertTrue(self.filter.is_active)

    def test_parse_or_filter(self):
        """Test compound filter with OR."""
        self.assertTrue(self.filter.parse("compromised or hvt"))
        self.assertTrue(self.filter.is_active)

    def test_parse_not_filter(self):
        """Test NOT filter."""
        self.assertTrue(self.filter.parse("not port 80"))
        self.assertTrue(self.filter.is_active)

    def test_matches_host_ip(self):
        """Test host IP matching."""
        self.filter.parse("ip 10.0.0.1")

        host_data = {"services": set(), "creds": []}

        self.assertTrue(self.filter.matches_host(
            "10.0.0.1", host_data, set(), {}, None
        ))
        self.assertFalse(self.filter.matches_host(
            "10.0.0.2", host_data, set(), {}, None
        ))

    def test_matches_host_cidr(self):
        """Test host CIDR matching."""
        self.filter.parse("ip 10.0.0.0/24")

        host_data = {"services": set(), "creds": []}

        self.assertTrue(self.filter.matches_host(
            "10.0.0.100", host_data, set(), {}, None
        ))
        self.assertFalse(self.filter.matches_host(
            "10.0.1.1", host_data, set(), {}, None
        ))

    def test_matches_host_port(self):
        """Test host port matching."""
        self.filter.parse("port 445")

        host_with_port = {"services": {445, 80}, "creds": []}
        host_without_port = {"services": {22, 80}, "creds": []}

        self.assertTrue(self.filter.matches_host(
            "10.0.0.1", host_with_port, set(), {}, None
        ))
        self.assertFalse(self.filter.matches_host(
            "10.0.0.2", host_without_port, set(), {}, None
        ))

    def test_matches_compromised(self):
        """Test compromised filter."""
        self.filter.parse("compromised")

        host_data = {"services": set(), "creds": []}
        compromised = {"10.0.0.1"}

        self.assertTrue(self.filter.matches_host(
            "10.0.0.1", host_data, compromised, {}, None
        ))
        self.assertFalse(self.filter.matches_host(
            "10.0.0.2", host_data, compromised, {}, None
        ))

    def test_filter_presets(self):
        """Test filter presets."""
        self.assertIn("compromised", FILTER_PRESETS)
        self.assertIn("hvt", FILTER_PRESETS)
        self.assertIn("lateral", FILTER_PRESETS)

    def test_clear_filter(self):
        """Test filter clearing."""
        self.filter.parse("ip 10.0.0.1")
        self.assertTrue(self.filter.is_active)

        self.filter.clear()
        self.assertFalse(self.filter.is_active)


class TestTimelinePanel(unittest.TestCase):
    """Test behavioral timeline."""

    def setUp(self):
        """Create timeline instance."""
        self.timeline = TimelinePanel()

    def test_add_flow(self):
        """Test adding flow event."""
        self.timeline.add_flow(
            src="10.0.0.1",
            dst="192.168.1.1",
            port=443,
            proto="TCP"
        )

        self.assertEqual(len(self.timeline.events), 1)
        self.assertEqual(self.timeline.events[0].activity_type, ActivityType.FLOW)

    def test_add_credential(self):
        """Test adding credential event."""
        self.timeline.add_credential(
            protocol="NTLM",
            username="admin",
            domain="CORP",
            target_ip="10.0.0.100",
            target_port=445
        )

        self.assertEqual(len(self.timeline.events), 1)
        self.assertEqual(self.timeline.events[0].activity_type, ActivityType.CREDENTIAL)
        self.assertEqual(self.timeline.events[0].severity, "critical")

    def test_add_alert(self):
        """Test adding alert event."""
        self.timeline.add_alert(
            severity="high",
            alert_type="lateral_movement",
            message="Possible lateral movement detected",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2"
        )

        self.assertEqual(len(self.timeline.events), 1)
        self.assertEqual(self.timeline.events[0].activity_type, ActivityType.ALERT)

    def test_lateral_movement_detection(self):
        """Test lateral movement classification."""
        # Internal to internal on RDP port = lateral
        self.timeline.add_flow(
            src="10.0.0.1",
            dst="10.0.0.2",
            port=3389
        )

        self.assertEqual(self.timeline.events[0].activity_type, ActivityType.LATERAL)

    def test_profile_tracking(self):
        """Test host profile tracking."""
        self.timeline.add_flow("10.0.0.1", "192.168.1.1", 443)
        self.timeline.add_flow("10.0.0.1", "192.168.1.2", 80)

        self.assertIn("10.0.0.1", self.timeline.profiles)
        self.assertEqual(self.timeline.profiles["10.0.0.1"].total_activities, 2)

    def test_render(self):
        """Test timeline rendering."""
        self.timeline.add_flow("10.0.0.1", "192.168.1.1", 443)
        self.timeline.add_alert("high", "test", "Test alert")

        rendered = self.timeline.render()
        self.assertIsNotNone(rendered)

    def test_summary(self):
        """Test timeline summary."""
        self.timeline.add_flow("10.0.0.1", "192.168.1.1", 443)
        self.timeline.add_credential("NTLM", "admin", "CORP", "10.0.0.100", 445)

        summary = self.timeline.get_summary()
        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["credential_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
