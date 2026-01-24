#!/usr/bin/env python3
"""
AUTH ENGINE - EAP Credential Handler

Extracts EAP (Extensible Authentication Protocol) credentials.

EAP Types:
    - EAP-MD5 (Type 4): Challenge/response, crackable
    - EAP-TLS (Type 13): Certificate-based
    - EAP-TTLS (Type 21): Tunneled TLS
    - EAP-PEAP (Type 25): Protected EAP
    - EAP-MSCHAPv2 (Type 26): MS-CHAP in EAP
    - EAP-LEAP (Type 17): Cisco LEAP, weak
    - EAP-FAST (Type 43): Cisco FAST

Hashcat Modes:
    - 4800: iSCSI CHAP / EAP-MD5
    - 5500: MS-CHAPv2 (for EAP-MSCHAPv2)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class EAPAuthHandler(AuthProtocolHandler):
    """
    Handler for EAP authentication.

    Extracts credentials from various EAP methods.
    """

    @property
    def protocol_name(self) -> str:
        return "eap"

    @property
    def tshark_filter(self) -> str:
        return "eap"

    @property
    def correlation_field(self) -> str:
        return "eap.identifier"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "eap.code",
            "eap.identifier",
            "eap.type",
            "eap.identity",
            "eap.len",
            # EAP-MD5
            "eap.md5.value_size",
            "eap.md5.value",
            "eap.md5.extra_data",
            # EAP-TLS
            "eap.tls.flags",
            "eap.tls.fragment",
            # EAP-LEAP (Cisco)
            "eap.leap.version",
            "eap.leap.count",
            "eap.leap.peer_challenge",
            "eap.leap.peer_response",
            "eap.leap.ap_challenge",
            "eap.leap.ap_response",
            "eap.leap.name",
            # EAP-MSCHAPv2
            "eap.mschapv2.op_code",
            "eap.mschapv2.peer_challenge",
            "eap.mschapv2.nt_response",
            "eap.mschapv2.name",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify EAP message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_mac = self._get_first(fields.get("eth.src", ""))
        dst_mac = self._get_first(fields.get("eth.dst", ""))

        # EAP over 802.1X or RADIUS
        src_port = int(self._get_first(fields.get("udp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("udp.dstport", 0)) or 0)

        eap_id = self._get_first(fields.get("eap.identifier", ""))
        eap_code = self._get_first(fields.get("eap.code", ""))
        eap_type = self._get_first(fields.get("eap.type", ""))

        if not eap_id and not eap_code:
            return None

        correlation_key = eap_id or f"{src_mac or src_ip}:{dst_mac or dst_ip}"

        # EAP codes: 1=Request, 2=Response, 3=Success, 4=Failure
        if eap_code == "1":
            phase = AuthPhase.CHALLENGE
        elif eap_code == "2":
            phase = AuthPhase.RESPONSE
        elif eap_code == "3":
            phase = AuthPhase.RESULT  # Success
        elif eap_code == "4":
            phase = AuthPhase.RESULT  # Failure
        else:
            phase = AuthPhase.RESPONSE

        return AuthMessage(
            phase=phase,
            correlation_key=correlation_key,
            timestamp=timestamp,
            frame_number=frame_num,
            source_ip=src_ip or src_mac or "",
            source_port=src_port,
            dest_ip=dst_ip or dst_mac or "",
            dest_port=dst_port,
            protocol=self.protocol_name,
            raw_data=fields
        )

    def build_credential(self, messages: List[AuthMessage]) -> Optional[ExtractedCredential]:
        """Build EAP credential from exchange."""
        username = None
        eap_type = None
        eap_type_name = None
        md5_challenge = None
        md5_response = None
        leap_challenge = None
        leap_response = None
        leap_name = None
        mschapv2_challenge = None
        mschapv2_response = None
        mschapv2_name = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        eap_type_names = {
            "1": "Identity",
            "4": "MD5-Challenge",
            "13": "TLS",
            "17": "LEAP",
            "21": "TTLS",
            "25": "PEAP",
            "26": "MSCHAPv2",
            "43": "FAST",
        }

        for msg in sorted(messages, key=lambda m: m.timestamp):
            eap_code = self._get_first(msg.raw_data.get("eap.code", ""))
            etype = self._get_first(msg.raw_data.get("eap.type", ""))

            if etype and etype != "1":  # Not Identity
                eap_type = etype
                eap_type_name = eap_type_names.get(etype, f"Type-{etype}")

            identity = self._get_first(msg.raw_data.get("eap.identity", ""))
            if identity:
                username = identity

            # EAP-MD5
            md5_val = self._get_first(msg.raw_data.get("eap.md5.value", ""))
            if md5_val:
                if eap_code == "1":  # Challenge from server
                    md5_challenge = md5_val.replace(":", "")
                    server_ip = msg.source_ip
                    client_ip = msg.dest_ip
                elif eap_code == "2":  # Response from client
                    md5_response = md5_val.replace(":", "")
                    client_ip = msg.source_ip
                    server_ip = msg.dest_ip
                    timestamp = msg.timestamp

            # EAP-LEAP
            leap_peer_chal = self._get_first(msg.raw_data.get("eap.leap.peer_challenge", ""))
            if leap_peer_chal:
                leap_challenge = leap_peer_chal.replace(":", "")

            leap_peer_resp = self._get_first(msg.raw_data.get("eap.leap.peer_response", ""))
            if leap_peer_resp:
                leap_response = leap_peer_resp.replace(":", "")
                timestamp = msg.timestamp

            leap_n = self._get_first(msg.raw_data.get("eap.leap.name", ""))
            if leap_n:
                leap_name = leap_n
                if not username:
                    username = leap_n

            # EAP-MSCHAPv2
            mschap_chal = self._get_first(msg.raw_data.get("eap.mschapv2.peer_challenge", ""))
            if mschap_chal:
                mschapv2_challenge = mschap_chal.replace(":", "")

            mschap_resp = self._get_first(msg.raw_data.get("eap.mschapv2.nt_response", ""))
            if mschap_resp:
                mschapv2_response = mschap_resp.replace(":", "")
                timestamp = msg.timestamp

            mschap_n = self._get_first(msg.raw_data.get("eap.mschapv2.name", ""))
            if mschap_n:
                mschapv2_name = mschap_n
                if not username:
                    username = mschap_n

            # Result
            if eap_code == "3":
                auth_success = True
            elif eap_code == "4":
                auth_success = False

        if not username:
            return None

        # Determine hashcat format based on EAP type
        hashcat_format = None
        hashcat_mode = None

        if eap_type == "4" and md5_challenge and md5_response:
            # EAP-MD5: hashcat mode 4800
            # Format: challenge:response:id
            hashcat_mode = 4800
            hashcat_format = f"{md5_challenge}:{md5_response}"

        elif eap_type == "17" and leap_challenge and leap_response:
            # LEAP: similar to MS-CHAPv1
            hashcat_mode = 5500
            hashcat_format = f"{username}::::{leap_response}:{leap_challenge}"

        elif eap_type == "26" and mschapv2_challenge and mschapv2_response:
            # EAP-MSCHAPv2: hashcat mode 5500
            hashcat_mode = 5500
            hashcat_format = f"{username}::::{mschapv2_response}:{mschapv2_challenge}"

        metadata = ProtocolMetadata(
            raw_fields={
                "eap_type": eap_type,
                "eap_type_name": eap_type_name,
                "leap_name": leap_name,
                "mschapv2_name": mschapv2_name,
            }
        )

        return ExtractedCredential(
            protocol="eap",
            username=username,
            domain=server_ip,
            credential_data={
                "eap_type": eap_type,
                "eap_type_name": eap_type_name,
                "md5_challenge": md5_challenge,
                "md5_response": md5_response,
                "leap_challenge": leap_challenge,
                "leap_response": leap_response,
                "mschapv2_challenge": mschapv2_challenge,
                "mschapv2_response": mschapv2_response,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=0,
            target_service="eap",
            timestamp=timestamp,
            metadata=metadata,
            auth_success=auth_success,
        )

    def _get_first(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def get_hashcat_mode(self) -> Optional[int]:
        return 4800  # EAP-MD5 default
