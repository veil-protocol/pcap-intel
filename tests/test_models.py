#!/usr/bin/env python3
"""
Unit tests for PCAP-Intel models and correlation.
Can run without tshark.
"""

import sys
from pathlib import Path
from datetime import datetime

# Add parent to path for proper imports
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

from src.models import (
    Credential, CredentialType, Host, HostRole,
    AuthEvent, IntelReport, DNSRecord, Share
)
from src.correlators.credential_correlator import CredentialCorrelator
from src.correlators.attack_path import AttackPathAnalyzer


def test_credential_ntlmv2():
    """Test NTLMv2 credential creation and hashcat format"""
    cred = Credential(
        type=CredentialType.NTLMV2,
        username="admin",
        domain="CORP",
        challenge="1122334455667788",
        response="aabbccdd:eeffgghhiijjkkll",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.10",
    )

    assert cred.username == "admin"
    assert cred.domain == "CORP"
    assert cred.is_crackable == True
    assert cred.is_cleartext == False

    hashcat = cred.to_hashcat()
    assert hashcat is not None
    assert "admin" in hashcat
    assert "CORP" in hashcat
    print(f"[PASS] NTLMv2 credential: {hashcat}")


def test_credential_cleartext():
    """Test cleartext credential"""
    cred = Credential(
        type=CredentialType.CLEARTEXT_FTP,
        username="ftpuser",
        password="Secret123!",
        dst_ip="192.168.1.50",
    )

    assert cred.is_cleartext == True
    assert cred.is_crackable == False
    assert cred.password == "Secret123!"
    print(f"[PASS] Cleartext FTP: {cred.username}:{cred.password}")


def test_credential_kerberos():
    """Test Kerberos TGS credential"""
    cred = Credential(
        type=CredentialType.KERBEROS_TGS,
        username="svc_sql",
        domain="CORP.LOCAL",
        spn="MSSQLSvc/sqlserver.corp.local:1433",
        etype=23,  # RC4
        ticket="$krb5tgs$23$*svc_sql$CORP.LOCAL$...",
    )

    assert cred.spn == "MSSQLSvc/sqlserver.corp.local:1433"
    assert cred.is_crackable == True
    assert cred.etype == 23
    print(f"[PASS] Kerberos TGS: {cred.spn}")


def test_host_roles():
    """Test host role identification"""
    host = Host(
        ip="192.168.1.10",
        hostname="dc01",
        open_ports={88, 389, 636, 445, 3268},
    )
    host.roles = {HostRole.DOMAIN_CONTROLLER}

    assert host.is_dc == True
    assert HostRole.DOMAIN_CONTROLLER in host.roles
    print(f"[PASS] DC identification: {host.hostname}")


def test_credential_correlator():
    """Test credential correlation"""
    correlator = CredentialCorrelator()

    # Create test credentials
    creds = [
        Credential(
            type=CredentialType.NTLMV2,
            username="admin",
            domain="CORP",
            src_ip="192.168.1.100",
            dst_ip="192.168.1.10",
        ),
        Credential(
            type=CredentialType.NTLMV2,
            username="admin",
            domain="CORP",
            src_ip="192.168.1.100",
            dst_ip="192.168.1.20",  # Different target
        ),
        Credential(
            type=CredentialType.CLEARTEXT_FTP,
            username="ftpuser",
            password="pass123",
            dst_ip="192.168.1.50",
        ),
    ]

    # Create test hosts
    hosts = {
        "192.168.1.10": Host(ip="192.168.1.10", roles={HostRole.DOMAIN_CONTROLLER}),
        "192.168.1.20": Host(ip="192.168.1.20", roles={HostRole.FILE_SERVER}),
        "192.168.1.50": Host(ip="192.168.1.50", roles={HostRole.WEB_SERVER}),
    }

    result = correlator.process(
        credentials=creds,
        auth_events=[],
        hosts=hosts,
    )

    # Check credential reuse detection
    assert "credential_reuse" in result
    assert "credential_profiles" in result

    # admin@CORP should have reuse score > 1 (accessed multiple systems)
    admin_profile = result["credential_profiles"].get("corp\\admin")
    if admin_profile:
        assert admin_profile["reuse_score"] >= 2
        print(f"[PASS] Credential reuse detected: {admin_profile['reuse_score']} systems")

    print(f"[PASS] Correlation: {result['statistics']}")


def test_attack_path_analyzer():
    """Test attack path generation"""
    analyzer = AttackPathAnalyzer()

    # Create test data
    creds = [
        Credential(
            type=CredentialType.KERBEROS_TGS,
            username="svc_sql",
            domain="CORP",
            spn="MSSQLSvc/sql.corp.local:1433",
            etype=23,  # RC4 - crackable
            ticket="$krb5tgs$23$*...",
        ),
        Credential(
            type=CredentialType.CLEARTEXT_FTP,
            username="backup",
            password="Backup2024!",
        ),
    ]

    hosts = {
        "192.168.1.10": Host(ip="192.168.1.10", roles={HostRole.DOMAIN_CONTROLLER}),
    }

    paths = analyzer.analyze(
        credential_profiles={},
        system_profiles={},
        hosts=hosts,
        credentials=creds,
    )

    assert len(paths) > 0

    # Should find Kerberoast path
    kerb_paths = [p for p in paths if "Kerberoast" in p.name]
    assert len(kerb_paths) > 0
    print(f"[PASS] Kerberoast path found")

    # Should find cleartext path
    clear_paths = [p for p in paths if "Cleartext" in p.name]
    assert len(clear_paths) > 0
    print(f"[PASS] Cleartext path found")

    print(f"[PASS] Attack paths: {len(paths)} identified")


def test_intel_report():
    """Test IntelReport JSON export"""
    report = IntelReport(
        pcap_file="test.pcap",
        analysis_time=datetime.now(),
        duration_seconds=1.5,
    )

    report.hosts["192.168.1.10"] = Host(ip="192.168.1.10", hostname="dc01")
    report.credentials.append(
        Credential(type=CredentialType.NTLMV2, username="admin", domain="CORP")
    )
    report.domain_controllers = ["192.168.1.10"]

    # Test JSON export
    json_output = report.to_json()
    assert "192.168.1.10" in json_output
    assert "admin" in json_output
    assert "domain_controllers" in json_output

    print(f"[PASS] IntelReport JSON export works")


def run_all_tests():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("PCAP-Intel Unit Tests")
    print("=" * 60 + "\n")

    tests = [
        test_credential_ntlmv2,
        test_credential_cleartext,
        test_credential_kerberos,
        test_host_roles,
        test_credential_correlator,
        test_attack_path_analyzer,
        test_intel_report,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
