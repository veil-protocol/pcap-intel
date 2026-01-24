#!/usr/bin/env python3
"""
AUTH ENGINE - MS-CHAPv2 Credential Handler

Extracts MS-CHAPv2 authentication from various protocols.

MS-CHAPv2 is used in:
    - PPTP VPN
    - EAP-MSCHAPv2 (802.1X)
    - RADIUS with MS-CHAP attributes
    - PEAP-MSCHAPv2

Hashcat Mode: 5500 (NetNTLMv1 / MS-CHAPv2)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class MSCHAPv2AuthHandler(AuthProtocolHandler):
    """
    Handler for MS-CHAPv2 authentication.

    Extracts challenge/response pairs for offline cracking.
    """

    @property
    def protocol_name(self) -> str:
        return "mschapv2"

    @property
    def tshark_filter(self) -> str:
        # MS-CHAPv2 in PPP, EAP, or standalone
        return "ppp.protocol == 0xc223 or eap.type == 26"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # PPP CHAP fields
            "ppp.protocol",
            "chap.code",
            "chap.identifier",
            "chap.value_size",
            "chap.value",
            "chap.name",
            "chap.message",
            # MS-CHAPv2 specific (in CHAP value)
            # These may need custom dissection
            "mschapv2.op_code",
            "mschapv2.peer_challenge",
            "mschapv2.nt_response",
            "mschapv2.auth_response",
            # EAP-MSCHAPv2
            "eap.type",
            "eap.identity",
            "eap.mschapv2.op_code",
            "eap.mschapv2.peer_challenge",
            "eap.mschapv2.nt_response",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify MS-CHAPv2 message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            # Try PPP identifier
            correlation_key = self._get_first(fields.get("chap.identifier", ""))
            if not correlation_key:
                return None

        chap_code = self._get_first(fields.get("chap.code", ""))
        eap_type = self._get_first(fields.get("eap.type", ""))
        mschapv2_op = self._get_first(fields.get("mschapv2.op_code", "")) or \
                      self._get_first(fields.get("eap.mschapv2.op_code", ""))

        # CHAP codes: 1=Challenge, 2=Response, 3=Success, 4=Failure
        # MS-CHAPv2 op codes: 1=Challenge, 2=Response, 3=Success, 4=Failure, 7=Change-Password
        if chap_code == "1" or mschapv2_op == "1":
            phase = AuthPhase.CHALLENGE
        elif chap_code == "2" or mschapv2_op == "2":
            phase = AuthPhase.RESPONSE
        elif chap_code == "3" or mschapv2_op == "3":
            phase = AuthPhase.RESULT  # Success
        elif chap_code == "4" or mschapv2_op == "4":
            phase = AuthPhase.RESULT  # Failure
        elif eap_type == "26":  # EAP-MSCHAPv2
            phase = AuthPhase.RESPONSE
        else:
            return None

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
        """Build MS-CHAPv2 credential from exchange."""
        username = None
        authenticator_challenge = None
        peer_challenge = None
        nt_response = None
        auth_response = None
        chap_identifier = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            chap_code = self._get_first(msg.raw_data.get("chap.code", ""))
            mschapv2_op = self._get_first(msg.raw_data.get("mschapv2.op_code", ""))

            name = self._get_first(msg.raw_data.get("chap.name", ""))
            if name:
                username = name

            identity = self._get_first(msg.raw_data.get("eap.identity", ""))
            if identity:
                username = identity

            chap_id = self._get_first(msg.raw_data.get("chap.identifier", ""))
            if chap_id:
                chap_identifier = chap_id

            # Challenge from server (authenticator challenge)
            if chap_code == "1" or mschapv2_op == "1":
                chap_value = self._get_first(msg.raw_data.get("chap.value", ""))
                if chap_value:
                    authenticator_challenge = chap_value.replace(":", "")
                server_ip = msg.source_ip
                client_ip = msg.dest_ip

            # Response from client
            if chap_code == "2" or mschapv2_op == "2":
                # MS-CHAPv2 response structure:
                # 16 bytes peer challenge + 8 bytes reserved + 24 bytes NT response + 1 byte flags
                chap_value = self._get_first(msg.raw_data.get("chap.value", ""))
                if chap_value:
                    value_hex = chap_value.replace(":", "")
                    if len(value_hex) >= 98:  # 49 bytes * 2
                        peer_challenge = value_hex[0:32]  # First 16 bytes
                        nt_response = value_hex[48:96]  # 24 bytes after reserved

                # Or from specific fields
                pc = self._get_first(msg.raw_data.get("mschapv2.peer_challenge", "")) or \
                     self._get_first(msg.raw_data.get("eap.mschapv2.peer_challenge", ""))
                if pc:
                    peer_challenge = pc.replace(":", "")

                nt = self._get_first(msg.raw_data.get("mschapv2.nt_response", "")) or \
                     self._get_first(msg.raw_data.get("eap.mschapv2.nt_response", ""))
                if nt:
                    nt_response = nt.replace(":", "")

                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp

            # Result
            if chap_code == "3" or mschapv2_op == "3":
                auth_success = True
                ar = self._get_first(msg.raw_data.get("mschapv2.auth_response", ""))
                if ar:
                    auth_response = ar.replace(":", "")
            elif chap_code == "4" or mschapv2_op == "4":
                auth_success = False

        if not nt_response:
            return None

        # Hashcat format for MS-CHAPv2 (mode 5500):
        # user::::nt_response:authenticator_challenge
        # Or with peer challenge:
        # user::::peer_challenge+nt_response:authenticator_challenge
        hashcat_format = None
        if username and authenticator_challenge:
            if peer_challenge:
                hashcat_format = f"{username}::::{peer_challenge}{nt_response}:{authenticator_challenge}"
            else:
                hashcat_format = f"{username}::::{nt_response}:{authenticator_challenge}"

        metadata = ProtocolMetadata(
            raw_fields={
                "chap_identifier": chap_identifier,
                "auth_response": auth_response,
                "note": "MS-CHAPv2 challenge/response",
            }
        )

        return ExtractedCredential(
            protocol="mschapv2",
            username=username or "unknown",
            domain=server_ip,
            credential_data={
                "authenticator_challenge": authenticator_challenge,
                "peer_challenge": peer_challenge,
                "nt_response": nt_response,
                "auth_response": auth_response,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=5500,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=0,
            target_service="mschapv2",
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
        return 5500
