#!/usr/bin/env python3
"""
AUTH ENGINE - VNC Credential Handler

Extracts VNC authentication challenges for cracking.

VNC Auth Protocol:
    1. Server sends 16-byte challenge
    2. Client encrypts challenge with DES(password) and sends response
    3. Server verifies

VNC passwords are max 8 characters, making them trivially crackable.

Hashcat Mode: 14000 (3DES challenge/response)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class VNCAuthHandler(AuthProtocolHandler):
    """
    Handler for VNC authentication.

    Extracts challenge/response for offline cracking.
    VNC passwords are limited to 8 characters.
    """

    @property
    def protocol_name(self) -> str:
        return "vnc"

    @property
    def tshark_filter(self) -> str:
        return "vnc"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "vnc.server_security_type",
            "vnc.auth_challenge",
            "vnc.auth_response",
            "vnc.auth_result",
            "vnc.server_proto_ver",
            "vnc.client_proto_ver",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify VNC auth message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        challenge = self._get_first(fields.get("vnc.auth_challenge", ""))
        response = self._get_first(fields.get("vnc.auth_response", ""))
        result = self._get_first(fields.get("vnc.auth_result", ""))
        security_type = self._get_first(fields.get("vnc.server_security_type", ""))

        if challenge:
            phase = AuthPhase.CHALLENGE
        elif response:
            phase = AuthPhase.RESPONSE
        elif result:
            phase = AuthPhase.RESULT
        elif security_type:
            phase = AuthPhase.INITIATION
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
        """Build VNC credential from challenge/response."""
        challenge = None
        response = None
        server_ip = None
        server_port = None
        client_ip = None
        auth_success = None
        server_version = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            c = self._get_first(msg.raw_data.get("vnc.auth_challenge", ""))
            r = self._get_first(msg.raw_data.get("vnc.auth_response", ""))
            result = self._get_first(msg.raw_data.get("vnc.auth_result", ""))
            ver = self._get_first(msg.raw_data.get("vnc.server_proto_ver", ""))

            if c:
                challenge = c.replace(":", "").replace(" ", "")
                server_ip = msg.source_ip
                server_port = msg.source_port
                client_ip = msg.dest_ip
            if r:
                response = r.replace(":", "").replace(" ", "")
                timestamp = msg.timestamp
            if result == "0":
                auth_success = True
            elif result and result != "0":
                auth_success = False
            if ver:
                server_version = ver

        if not challenge or not response:
            return None

        # Hashcat format: $vnc$*CHALLENGE*RESPONSE
        hashcat_format = f"$vnc$*{challenge}*{response}"

        metadata = ProtocolMetadata(
            server_version=server_version,
            raw_fields={
                "challenge": challenge,
                "note": "VNC passwords max 8 chars",
            }
        )

        return ExtractedCredential(
            protocol="vnc",
            username="vnc_user",  # VNC doesn't have usernames
            domain=server_ip,
            credential_data={
                "challenge": challenge,
                "response": response,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=14000,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 5900,
            target_service="vnc",
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
        return 14000
