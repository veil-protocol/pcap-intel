#!/usr/bin/env python3
"""
Comprehensive unit tests for PCAP-Intel V2 extractors.
Tests data classes, analysis logic, and output formatting.
Can run without tshark (mock-based tests).
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict

# Add parent to path for proper imports
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

# ============================================================
# Layer 2/3 Extractor Tests (Phase 1)
# ============================================================

def test_arp_entry():
    """Test ARPEntry data class"""
    from src.extractors.arp import ARPEntry, ARPSpoofingAlert

    entry = ARPEntry(
        ip="192.168.1.10",
        mac="aa:bb:cc:dd:ee:ff",
        opcode=2,  # reply
        is_gratuitous=False,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.1",
        timestamp=datetime.now(),
    )

    assert entry.ip == "192.168.1.10"
    assert entry.mac == "aa:bb:cc:dd:ee:ff"
    assert entry.opcode == 2

    # Test to_dict
    d = entry.to_dict()
    assert d["opcode_name"] == "reply"
    assert d["is_gratuitous"] == False
    print("[PASS] ARPEntry data class")


def test_arp_spoofing_alert():
    """Test ARP spoofing detection data class"""
    from src.extractors.arp import ARPSpoofingAlert

    alert = ARPSpoofingAlert(
        ip="192.168.1.10",
        original_mac="aa:bb:cc:dd:ee:ff",
        new_mac="11:22:33:44:55:66",
        first_seen=datetime.now(),
        conflict_time=datetime.now(),
        alert_type="mac_change",
    )

    assert alert.alert_type == "mac_change"
    assert alert.original_mac != alert.new_mac
    d = alert.to_dict()
    assert d["ip"] == "192.168.1.10"
    print("[PASS] ARPSpoofingAlert data class")


def test_vlan_info():
    """Test VLAN extraction data classes"""
    from src.extractors.vlan import VLANTag, VLANPacket

    # Test VLANTag
    vlan_tag = VLANTag(
        vlan_id=100,
        priority=3,
        cfi=0,
        is_outer=True,
        timestamp=datetime.now(),
    )

    assert vlan_tag.vlan_id == 100
    assert vlan_tag.priority == 3
    d = vlan_tag.to_dict()
    assert "Best Effort" not in d["priority_name"]  # Priority 3 = Excellent Effort
    print("[PASS] VLANTag data class")

    # Test VLANPacket (for QinQ detection)
    vlan_packet = VLANPacket(
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="11:22:33:44:55:66",
        outer_vlan=100,
        outer_priority=3,
        inner_vlan=200,  # QinQ inner tag
        inner_priority=2,
        is_qinq=True,
        timestamp=datetime.now(),
    )

    assert vlan_packet.outer_vlan == 100
    assert vlan_packet.inner_vlan == 200
    assert vlan_packet.is_qinq == True
    print("[PASS] VLANPacket (QinQ) data class")


def test_icmp_events():
    """Test ICMP extraction data classes"""
    from src.extractors.icmp import ICMPEvent, ICMPAlert, ICMPType, UnreachableCode

    event = ICMPEvent(
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        icmp_type=8,  # ECHO_REQUEST
        icmp_code=0,
        timestamp=datetime.now(),
        payload_size=64,
    )

    assert event.icmp_type == 8
    assert event.icmp_code == 0
    assert event.payload_size == 64
    print("[PASS] ICMPEvent data class")

    # Test ICMP alert
    alert = ICMPAlert(
        alert_type="scan_detected",
        severity="medium",
        src_ip="10.0.0.100",
        description="ICMP sweep detected",
        evidence=["Detected 50 echo requests in 10 seconds"],
        timestamp=datetime.now(),
    )

    assert alert.alert_type == "scan_detected"
    assert alert.severity == "medium"
    print("[PASS] ICMPAlert data class")


def test_os_fingerprint():
    """Test OS fingerprinting data classes"""
    from src.extractors.os_fingerprint import OSFingerprint, TCPSignature, OSFamily

    sig = TCPSignature(
        ttl=64,
        window_size=65535,
        mss=1460,
        window_scale=7,
        sack_permitted=True,
        timestamp_present=True,
    )

    assert sig.ttl == 64
    assert sig.mss == 1460
    assert sig.window_scale == 7
    print("[PASS] TCPSignature data class")

    fp = OSFingerprint(
        ip="192.168.1.100",
        os_family=OSFamily.LINUX,
        os_detail="Linux 4.x-5.x",
        confidence=0.85,
        signatures=[sig],
        ttl_observed=[64, 64, 63],
    )

    assert fp.os_family == OSFamily.LINUX
    assert fp.confidence == 0.85
    assert "Linux" in fp.os_detail
    print("[PASS] OSFingerprint data class")


def test_network_discovery():
    """Test network discovery data classes (CDP, LLDP, STP)"""
    from src.extractors.network_discovery import (
        CDPDevice, LLDPDevice, STPBridge, TopologyLink, NetworkVulnerability, DeviceType
    )

    # CDP device
    cdp = CDPDevice(
        device_id="switch01.corp.local",
        platform="Cisco WS-C3750X-48P",
        software_version="15.2(4)E1",
        ip_address="10.0.0.1",
        native_vlan=1,
        port_id="GigabitEthernet1/0/1",
        capabilities={"Switch", "IGMP"},
    )

    assert cdp.device_id == "switch01.corp.local"
    assert "3750" in cdp.platform
    print("[PASS] CDPDevice data class")

    # LLDP device
    lldp = LLDPDevice(
        system_name="router01.corp.local",
        system_description="Juniper MX480",
        chassis_id="00:11:22:33:44:55",
        management_ip="10.0.0.2",
        port_id="xe-0/0/0",
        capabilities={"Router", "Bridge"},
    )

    assert lldp.system_name == "router01.corp.local"
    assert "MX480" in lldp.system_description
    print("[PASS] LLDPDevice data class")

    # STP bridge
    stp = STPBridge(
        bridge_id="8000.001122334455",
        root_id="8000.001122334400",
        port_id="1",
        is_root=False,
        root_cost=100,
    )

    assert not stp.is_root
    assert stp.root_cost == 100
    print("[PASS] STPBridge data class")


# ============================================================
# Application Protocol Tests (Phase 2)
# ============================================================

def test_dns_full():
    """Test full DNS extraction data classes"""
    from src.extractors.dns_full import (
        TunnelingIndicator, ServiceRecord, ADServiceDiscovery, DNSQueryStats
    )

    # Tunneling indicator
    tunnel = TunnelingIndicator(
        indicator_type="high_entropy",
        query="aGVsbG8ud29ybGQ.suspicious.com",
        domain="suspicious.com",
        value=4.2,  # entropy score
        severity="high",
        details="Base64-like subdomain detected",
    )

    assert tunnel.severity == "high"
    assert tunnel.value > 4.0  # High entropy suggests tunneling
    print("[PASS] TunnelingIndicator data class")

    # AD service discovery
    ad_service = ADServiceDiscovery(
        domain="corp.local",
        service_type="dc_locator",
        query="_ldap._tcp.dc._msdcs.corp.local",
        target="dc01.corp.local",
        port=389,
    )

    assert ad_service.service_type == "dc_locator"
    assert ad_service.port == 389
    print("[PASS] ADServiceDiscovery data class")


def test_ldap_extraction():
    """Test LDAP extraction data classes"""
    from src.extractors.ldap import LDAPQuery, LDAPBindEvent, ADQueryCategory

    # LDAP query
    query = LDAPQuery(
        src_ip="192.168.1.100",
        dst_ip="192.168.1.10",
        base_dn="DC=corp,DC=local",
        filter_string="(&(objectClass=user)(adminCount=1))",
        scope=2,  # SUBTREE
        attributes=["cn", "memberOf", "servicePrincipalName"],
        category=ADQueryCategory.ADMIN_COUNT_QUERY,
        timestamp=datetime.now(),
    )

    assert query.category == ADQueryCategory.ADMIN_COUNT_QUERY
    assert "adminCount=1" in query.filter_string
    print("[PASS] LDAPQuery data class")


def test_rdp_extraction():
    """Test RDP extraction data classes"""
    from src.extractors.rdp import (
        RDPClientInfo, RDPSecurityInfo, RDPSession, RDPChannelActivity
    )

    # RDP client info
    client = RDPClientInfo(
        client_name="WORKSTATION01",
        client_build=19041,
        keyboard_layout="0x0409",
        client_ip="192.168.1.100",
        server_ip="192.168.1.50",
    )

    assert client.client_name == "WORKSTATION01"
    print("[PASS] RDPClientInfo data class")

    # RDP channel activity (potential data exfil)
    channel = RDPChannelActivity(
        channel_name="cliprdr",  # Clipboard
        session_ip_pair="192.168.1.100:192.168.1.50",
        packet_count=100,
        data_volume=50000,  # Large clipboard paste
    )

    assert channel.channel_name == "cliprdr"
    assert channel.data_volume == 50000
    print("[PASS] RDPChannelActivity data class")


def test_http_enhanced():
    """Test enhanced HTTP extraction data classes"""
    from src.extractors.http_enhanced import (
        HTTPRequest, HTTPResponse, SensitiveFile, DigestAuth, AuthType,
        SensitiveFileType as HTTPSensitiveFileType
    )

    # HTTP request
    request = HTTPRequest(
        method="POST",
        uri="/api/login",
        host="app.corp.local",
        user_agent="Mozilla/5.0",
        x_forwarded_for="10.0.0.100",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.50",
        timestamp=datetime.now(),
    )

    assert request.method == "POST"
    assert request.x_forwarded_for == "10.0.0.100"
    print("[PASS] HTTPRequest data class")

    # Sensitive file detection
    sensitive = SensitiveFile(
        file_type=HTTPSensitiveFileType.WEB_CONFIG,
        filename="web.config",
        uri="/backup/web.config",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.50",
        detected_via="uri",
    )

    assert sensitive.file_type == HTTPSensitiveFileType.WEB_CONFIG
    print("[PASS] SensitiveFile data class")


# ============================================================
# Database Protocol Tests (Phase 3)
# ============================================================

def test_database_extraction():
    """Test database extraction data classes"""
    from src.extractors.databases import (
        DatabaseServer, DatabaseCredential, DatabaseQuery, DatabaseError
    )

    # Database server
    server = DatabaseServer(
        ip="192.168.1.50",
        port=3306,
        db_type="mysql",
        version="8.0.28",
        hostname="db01.corp.local",
    )

    assert server.db_type == "mysql"
    assert server.port == 3306
    print("[PASS] DatabaseServer data class")

    # Database credential (mysql native password)
    cred = DatabaseCredential(
        db_type="mysql",
        username="dbadmin",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.50",
        dst_port=3306,
        hash_value="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",
        salt="random_salt_bytes",
        hashcat_mode=300,
    )

    assert cred.hashcat_mode == 300
    assert cred.hash_value.startswith("*")
    print("[PASS] DatabaseCredential data class")

    # Suspicious query
    query = DatabaseQuery(
        src_ip="192.168.1.100",
        dst_ip="192.168.1.50",
        db_type="mssql",
        query="SELECT * FROM sys.sql_logins WHERE is_disabled = 0",
        database="master",
        sensitive=True,
        timestamp=datetime.now(),
    )

    assert query.sensitive == True
    assert "sys.sql_logins" in query.query
    print("[PASS] DatabaseQuery data class")


# ============================================================
# VoIP Protocol Tests (Phase 4)
# ============================================================

def test_voip_extraction():
    """Test VoIP extraction data classes"""
    from src.extractors.voip import (
        SIPDigestAuth, SIPEndpoint, VoIPCall, VoIPServer, RTPStream,
        SIPMethod, CallState
    )

    # SIP digest auth (crackable)
    digest = SIPDigestAuth(
        username="1001",
        realm="asterisk",
        nonce="abc123def456",
        method="REGISTER",
        uri="sip:asterisk@10.0.0.1",
        response="d41d8cd98f00b204e9800998ecf8427e",
        algorithm="MD5",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
    )

    # Test hashcat format (mode 11400)
    hashcat = digest.to_hashcat()
    assert "$sip$" in hashcat
    assert "asterisk" in hashcat  # realm
    assert "1001" in hashcat  # username
    print(f"[PASS] SIP Digest hashcat: {hashcat[:50]}...")

    # SIP endpoint
    endpoint = SIPEndpoint(
        address="sip:1001@10.0.0.1",
        display_name="Reception",
        user_agent="Polycom VVX 450",
        ip="192.168.1.100",
    )

    assert "Polycom" in endpoint.user_agent
    print("[PASS] SIPEndpoint data class")

    # VoIP call
    call = VoIPCall(
        call_id="abc123@10.0.0.1",
        from_addr="sip:1001@10.0.0.1",
        to_addr="sip:1002@10.0.0.1",
        state=CallState.CONNECTED,
        start_time=datetime.now(),
    )

    assert call.state == CallState.CONNECTED
    print("[PASS] VoIPCall data class")


def test_sip_digest_to_credential():
    """Test SIP digest auth conversion to standard Credential"""
    from src.extractors.voip import SIPDigestAuth
    from src.models import CredentialType

    digest = SIPDigestAuth(
        username="1001",
        realm="asterisk",
        nonce="abc123",
        method="REGISTER",
        uri="sip:asterisk@pbx.local",
        response="d41d8cd98f00b204e9800998ecf8427e",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
    )

    cred = digest.to_credential()
    assert cred.type == CredentialType.SIP_DIGEST
    assert cred.username == "1001"
    assert cred.domain == "asterisk"  # realm becomes domain
    print("[PASS] SIP to Credential conversion")


# ============================================================
# Network Infrastructure Tests (Phase 5)
# ============================================================

def test_network_infra():
    """Test network infrastructure data classes"""
    from src.extractors.network_infra import (
        Router, VirtualIP, Tunnel, RoutingCredential, AttackOpportunity
    )

    # Router with OSPF
    router = Router(
        router_id="10.0.0.1",
        ip="10.0.0.1",
        protocol="ospf",
        area="0.0.0.0",
        neighbors={"10.0.0.2", "10.0.0.3"},
    )

    assert router.protocol == "ospf"
    assert len(router.neighbors) == 2
    print("[PASS] Router data class")

    # Virtual IP (HSRP/VRRP)
    vip = VirtualIP(
        ip="10.0.0.254",
        protocol="hsrp",
        group=1,
        priority=110,
        state="active",
        active_router="10.0.0.1",
        standby_router="10.0.0.2",
    )

    assert vip.protocol == "hsrp"
    assert vip.active_router == "10.0.0.1"
    print("[PASS] VirtualIP data class")

    # Routing credential (OSPF plain auth)
    routing_cred = RoutingCredential(
        protocol="ospf",
        auth_type="plaintext",
        credential="cisco123",
        src_ip="10.0.0.1",
        is_cleartext=True,
    )

    assert routing_cred.auth_type == "plaintext"
    assert routing_cred.credential == "cisco123"
    print("[PASS] RoutingCredential data class")


# ============================================================
# ICS/OT Protocol Tests (Phase 6)
# ============================================================

def test_ics_ot():
    """Test ICS/OT extraction data classes"""
    from src.extractors.ics_ot import (
        ICSProtocol, PLCDevice, ICSOperation, SecurityFinding
    )

    # PLC device
    plc = PLCDevice(
        ip="192.168.1.100",
        protocol=ICSProtocol.MODBUS,
        unit_id=1,
        vendor="Siemens",
        product="S7-1200",
        revision="4.4.0",
        registers_accessed={0, 1, 2, 100, 101},
    )

    assert plc.protocol == ICSProtocol.MODBUS
    assert plc.vendor == "Siemens"
    print("[PASS] PLCDevice data class")

    # ICS operation (dangerous write)
    operation = ICSOperation(
        protocol=ICSProtocol.MODBUS,
        function_code=6,  # Write Single Register
        function_name="Write Single Register",
        src_ip="192.168.1.50",
        dst_ip="192.168.1.100",
        unit_id=1,
        address=100,
        quantity=1,
        is_write=True,
        timestamp=datetime.now(),
    )

    assert operation.is_write == True
    assert operation.function_code == 6
    print("[PASS] ICSOperation data class")


# ============================================================
# IoT Protocol Tests (Phase 7)
# ============================================================

def test_iot_extraction():
    """Test IoT extraction data classes"""
    from src.extractors.iot import (
        MQTTCredential, MQTTTopic, MQTTMessage, CoAPResource,
        IoTDevice, WirelessNetwork, ZigbeeDevice, ZWaveDevice
    )

    # MQTT credential
    mqtt_cred = MQTTCredential(
        client_id="temp_sensor_001",
        username="sensor01",
        password="iot123",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.10",
        broker_port=1883,
        timestamp=datetime.now(),
    )

    assert mqtt_cred.username == "sensor01"
    assert mqtt_cred.password == "iot123"
    assert mqtt_cred.broker_port == 1883
    print("[PASS] MQTTCredential data class")

    # MQTT topic (sensitive)
    topic = MQTTTopic(
        name="home/livingroom/camera/stream",
        msg_type="subscribe",
        qos=1,
        retain=False,
        message_count=150,
    )

    assert "camera" in topic.name
    print("[PASS] MQTTTopic data class")

    # CoAP resource
    coap = CoAPResource(
        uri_path="/sensors/temperature",
        method="GET",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.50",
        payload='{"temp": 22.5}',
    )

    assert coap.method == "GET"
    assert "temperature" in coap.uri_path
    print("[PASS] CoAPResource data class")

    # IoT device fingerprint
    device = IoTDevice(
        ip="192.168.1.100",
        mac="00:11:22:33:44:55",
        device_type="mqtt_client",
        protocols={"MQTT", "HTTP"},
    )

    assert "MQTT" in device.protocols
    print("[PASS] IoTDevice data class")


# ============================================================
# Advanced Analysis Tests (Phase 8)
# ============================================================

def test_tls_fingerprint():
    """Test TLS fingerprinting data classes"""
    from src.extractors.tls_fingerprint import (
        TLSCertificate, TLSFingerprint, TLSSecurityIssue, TLSIssueType
    )

    # TLS certificate
    cert = TLSCertificate(
        common_name="*.corp.local",
        issuer="Corp CA",
        serial_number="01:02:03:04:05",
        not_before=datetime.now(),
        not_after=datetime.now(),
        subject_alt_names=["*.corp.local", "corp.local"],
        server_ip="192.168.1.50",
    )

    assert cert.common_name == "*.corp.local"
    print("[PASS] TLSCertificate data class")

    # JA3 fingerprint
    fingerprint = TLSFingerprint(
        ip="192.168.1.100",
        fingerprint_type="ja3",
        fingerprint_hash="e7d705a3286e19ea42f587b344ee6865",
        fingerprint_string="771,4866-4867-4865,0-23-65281,29-23-24,0",
        matched_application="Chrome 90+",
        match_confidence=0.95,
        is_malware=False,
    )

    assert len(fingerprint.fingerprint_hash) == 32  # MD5 hash
    assert "Chrome" in fingerprint.matched_application
    print("[PASS] TLSFingerprint data class")

    # Security issue
    issue = TLSSecurityIssue(
        issue_type=TLSIssueType.WEAK_CIPHER,
        severity="medium",
        description="TLS 1.0 with weak cipher suite",
        ip="192.168.1.50",
        details={"cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
    )

    assert issue.issue_type == TLSIssueType.WEAK_CIPHER
    assert "3DES" in issue.details["cipher_suite"]
    print("[PASS] TLSSecurityIssue data class")


def test_file_carver():
    """Test file carver data classes"""
    from src.extractors.file_carver import (
        ExtractedFile, ExtractedCredential, ExtractedAPIKey, SensitiveFileType
    )

    # Extracted file
    extracted = ExtractedFile(
        filename=".env",
        filepath="/tmp/extracted/.env",
        size=256,
        mime_type="text/plain",
        protocol="http",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.50",
        is_sensitive=True,
        sensitive_type=SensitiveFileType.ENV_FILE,
    )

    assert extracted.sensitive_type == SensitiveFileType.ENV_FILE
    assert ".env" in extracted.filename
    print("[PASS] ExtractedFile data class")

    # Extracted credential from file
    cred = ExtractedCredential(
        file_path=".env",
        credential_type="database",
        value="secret123",
        context="DB_PASSWORD=secret123",
        line_number=5,
    )

    assert cred.value == "secret123"
    print("[PASS] ExtractedCredential data class")

    # Extracted API key
    api_key = ExtractedAPIKey(
        file_path="config.json",
        provider="AWS",
        key_type="access_key",
        value="AKIAIOSFODNN7EXAMPLE",
        line_number=10,
    )

    assert api_key.provider == "AWS"
    assert api_key.value.startswith("AKIA")
    print("[PASS] ExtractedAPIKey data class")


# ============================================================
# Integration Tests
# ============================================================

def test_credential_type_coverage():
    """Verify V2 extractors cover expected credential types"""
    from src.models import CredentialType

    # List of credential types that V2 extractors should support
    v2_cred_types = [
        CredentialType.SIP_DIGEST,       # VoIP extractor
        CredentialType.MYSQL,            # Database extractor
        CredentialType.MSSQL,            # Database extractor
        CredentialType.POSTGRESQL,       # Database extractor
        CredentialType.CLEARTEXT_LDAP,   # LDAP extractor
    ]

    # Verify these exist in CredentialType enum
    for ct in v2_cred_types:
        assert ct is not None, f"Missing credential type: {ct}"

    print(f"[PASS] Credential type coverage: {len(v2_cred_types)} V2 types verified")


def test_hashcat_mode_coverage():
    """Test hashcat mode output formatting"""
    from src.extractors.voip import SIPDigestAuth

    # SIP digest should produce mode 11400
    sip = SIPDigestAuth(
        username="1001",
        realm="asterisk",
        nonce="abc123",
        method="REGISTER",
        uri="sip:pbx@10.0.0.1",
        response="d41d8cd98f00b204e9800998ecf8427e",
    )

    hashcat = sip.to_hashcat()
    assert hashcat.startswith("$sip$"), "SIP hash should start with $sip$"
    print(f"[PASS] SIP hashcat mode 11400: {hashcat[:40]}...")


# ============================================================
# Test Runner
# ============================================================

def run_all_tests():
    """Run all V2 extractor tests"""
    print("\n" + "=" * 70)
    print("PCAP-Intel V2 Extractor Unit Tests")
    print("=" * 70 + "\n")

    # Group tests by phase
    tests_phase1 = [
        ("ARP Entry", test_arp_entry),
        ("ARP Spoofing Alert", test_arp_spoofing_alert),
        ("VLAN Info", test_vlan_info),
        ("ICMP Events", test_icmp_events),
        ("OS Fingerprint", test_os_fingerprint),
        ("Network Discovery", test_network_discovery),
    ]

    tests_phase2 = [
        ("DNS Full", test_dns_full),
        ("LDAP Extraction", test_ldap_extraction),
        ("RDP Extraction", test_rdp_extraction),
        ("HTTP Enhanced", test_http_enhanced),
    ]

    tests_phase3 = [
        ("Database Extraction", test_database_extraction),
    ]

    tests_phase4 = [
        ("VoIP Extraction", test_voip_extraction),
        ("SIP to Credential", test_sip_digest_to_credential),
    ]

    tests_phase5 = [
        ("Network Infrastructure", test_network_infra),
    ]

    tests_phase6 = [
        ("ICS/OT", test_ics_ot),
    ]

    tests_phase7 = [
        ("IoT Extraction", test_iot_extraction),
    ]

    tests_phase8 = [
        ("TLS Fingerprint", test_tls_fingerprint),
        ("File Carver", test_file_carver),
    ]

    tests_integration = [
        ("Credential Type Coverage", test_credential_type_coverage),
        ("Hashcat Mode Coverage", test_hashcat_mode_coverage),
    ]

    all_phases = [
        ("Phase 1: Layer 2/3 Infrastructure", tests_phase1),
        ("Phase 2: Application Protocols", tests_phase2),
        ("Phase 3: Database Protocols", tests_phase3),
        ("Phase 4: VoIP/Telephony", tests_phase4),
        ("Phase 5: Network Infrastructure", tests_phase5),
        ("Phase 6: ICS/OT Protocols", tests_phase6),
        ("Phase 7: IoT Protocols", tests_phase7),
        ("Phase 8: Advanced Analysis", tests_phase8),
        ("Integration Tests", tests_integration),
    ]

    total_passed = 0
    total_failed = 0
    failed_tests = []

    for phase_name, tests in all_phases:
        print(f"\n--- {phase_name} ---\n")
        for test_name, test_func in tests:
            try:
                test_func()
                total_passed += 1
            except AssertionError as e:
                print(f"[FAIL] {test_name}: {e}")
                total_failed += 1
                failed_tests.append((test_name, str(e)))
            except ImportError as e:
                print(f"[SKIP] {test_name}: Import error - {e}")
                total_failed += 1
                failed_tests.append((test_name, f"Import: {e}"))
            except Exception as e:
                print(f"[ERROR] {test_name}: {e}")
                total_failed += 1
                failed_tests.append((test_name, str(e)))

    print("\n" + "=" * 70)
    print(f"Results: {total_passed} passed, {total_failed} failed")
    print("=" * 70)

    if failed_tests:
        print("\nFailed tests:")
        for name, error in failed_tests:
            print(f"  - {name}: {error}")

    return total_failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
