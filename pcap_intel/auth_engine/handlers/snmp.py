#!/usr/bin/env python3
"""
AUTH ENGINE - SNMP Credential Handler

Extracts SNMP community strings and SNMPv3 credentials.

SNMPv1/v2c: Community strings (plaintext)
SNMPv3: Username + auth/privacy parameters (USM)

Hashcat: Mode 25000 for SNMPv3
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class SNMPAuthHandler(AuthProtocolHandler):
    """
    Handler for SNMP authentication.

    Supports:
        - SNMPv1/v2c community strings
        - SNMPv3 USM (User Security Model)
    """

    @property
    def protocol_name(self) -> str:
        return "snmp"

    @property
    def tshark_filter(self) -> str:
        return "snmp"

    @property
    def correlation_field(self) -> str:
        return "udp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # v1/v2c
            "snmp.community",
            "snmp.version",
            # v3 USM
            "snmp.msgUserName",
            "snmp.msgAuthoritativeEngineID",
            "snmp.msgAuthoritativeEngineBoots",
            "snmp.msgAuthoritativeEngineTime",
            "snmp.msgAuthenticationParameters",
            "snmp.msgPrivacyParameters",
            "snmp.msgSecurityModel",
            # Request type
            "snmp.request_id",
            "snmp.pdu_type",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify SNMP message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("udp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("udp.dstport", 0)) or 0)
        correlation_key = f"{src_ip}:{dst_ip}"  # SNMP is stateless

        community = self._get_first(fields.get("snmp.community", ""))
        username = self._get_first(fields.get("snmp.msgUserName", ""))

        if not community and not username:
            return None

        # SNMP is essentially single-message auth
        phase = AuthPhase.RESPONSE

        return AuthMessage(
            phase=phase,
            correlation_key=correlation_key,
            timestamp=timestamp,
            frame_number=frame_num,
            source_ip=src_ip,
            source_port=src_port,
            dest_ip=dst_ip,
            dest_port=dst_port,
            protocol=self.protocol_name,
            raw_data=fields
        )

    def build_credential(self, messages: List[AuthMessage]) -> Optional[ExtractedCredential]:
        """Build SNMP credential from messages."""
        # Take first message with credential data
        for msg in sorted(messages, key=lambda m: m.timestamp):
            community = self._get_first(msg.raw_data.get("snmp.community", ""))
            version = self._get_first(msg.raw_data.get("snmp.version", ""))
            username = self._get_first(msg.raw_data.get("snmp.msgUserName", ""))
            engine_id = self._get_first(msg.raw_data.get("snmp.msgAuthoritativeEngineID", ""))
            auth_params = self._get_first(msg.raw_data.get("snmp.msgAuthenticationParameters", ""))

            if community:
                # SNMPv1/v2c
                return self._build_v1v2_credential(msg, community, version)
            elif username:
                # SNMPv3
                return self._build_v3_credential(msg, username, engine_id, auth_params)

        return None

    def _build_v1v2_credential(
        self,
        msg: AuthMessage,
        community: str,
        version: str
    ) -> ExtractedCredential:
        """Build SNMPv1/v2c credential."""
        metadata = ProtocolMetadata(
            raw_fields={
                "snmp_version": version,
                "note": "Community string (plaintext)",
            }
        )

        return ExtractedCredential(
            protocol="snmp_v1v2",
            username=community,  # Community string as "username"
            domain=msg.dest_ip,
            credential_data={
                "community": community,  # PLAINTEXT
                "version": version,
            },
            hashcat_format=None,
            hashcat_mode=None,
            source_ip=msg.source_ip,
            source_port=msg.source_port,
            target_ip=msg.dest_ip,
            target_port=msg.dest_port or 161,
            target_service="snmp",
            timestamp=msg.timestamp,
            metadata=metadata,
        )

    def _build_v3_credential(
        self,
        msg: AuthMessage,
        username: str,
        engine_id: str,
        auth_params: str
    ) -> ExtractedCredential:
        """Build SNMPv3 USM credential."""
        engine_boots = self._get_first(msg.raw_data.get("snmp.msgAuthoritativeEngineBoots", ""))
        engine_time = self._get_first(msg.raw_data.get("snmp.msgAuthoritativeEngineTime", ""))

        metadata = ProtocolMetadata(
            raw_fields={
                "snmp_version": "3",
                "engine_id": engine_id,
                "engine_boots": engine_boots,
                "engine_time": engine_time,
            }
        )

        hashcat_format = None
        hashcat_mode = None

        # SNMPv3 hash can be cracked with mode 25000
        if auth_params and engine_id:
            hashcat_mode = 25000
            # Format: $snmp$0$<engineID>$<username>$<authParams>
            hashcat_format = f"$snmp$0${engine_id}${username}${auth_params}"

        return ExtractedCredential(
            protocol="snmp_v3",
            username=username,
            domain=msg.dest_ip,
            credential_data={
                "engine_id": engine_id,
                "auth_params": auth_params,
                "engine_boots": engine_boots,
                "engine_time": engine_time,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=msg.source_ip,
            source_port=msg.source_port,
            target_ip=msg.dest_ip,
            target_port=msg.dest_port or 161,
            target_service="snmp",
            timestamp=msg.timestamp,
            metadata=metadata,
        )

    def _get_first(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def validate_credential(self, cred: ExtractedCredential) -> bool:
        """Validate SNMP credential."""
        # Skip common default/useless community strings
        if cred.protocol == "snmp_v1v2":
            community = cred.credential_data.get("community", "")
            if community.lower() in ["", "public"]:
                return False  # Too common, not interesting
        return super().validate_credential(cred)

    def get_hashcat_mode(self) -> Optional[int]:
        return 25000  # SNMPv3
