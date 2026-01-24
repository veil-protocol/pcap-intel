#!/usr/bin/env python3
"""
AUTH ENGINE - NNTP Credential Handler

Extracts NNTP (Network News Transfer Protocol) credentials.

NNTP Auth (RFC 4643):
    - AUTHINFO USER/PASS: Plaintext
    - AUTHINFO GENERIC: SASL-based
    - AUTHINFO SASL: Modern SASL

Hashcat Mode: N/A (plaintext)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class NNTPAuthHandler(AuthProtocolHandler):
    """
    Handler for NNTP authentication.

    Extracts AUTHINFO credentials from news server connections.
    """

    @property
    def protocol_name(self) -> str:
        return "nntp"

    @property
    def tshark_filter(self) -> str:
        return "nntp"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "nntp.command",
            "nntp.response",
            "nntp.response_code",
            "nntp.authinfo_command",
            "nntp.authinfo_data",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify NNTP message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        command = self._get_first(fields.get("nntp.command", "")).upper()
        response_code = self._get_first(fields.get("nntp.response_code", ""))
        authinfo_cmd = self._get_first(fields.get("nntp.authinfo_command", "")).upper()

        if "AUTHINFO" in command or authinfo_cmd:
            phase = AuthPhase.RESPONSE  # Client sending credentials
        elif response_code:
            code = int(response_code) if response_code.isdigit() else 0
            if code == 281:  # Authentication accepted
                phase = AuthPhase.RESULT
            elif code == 381:  # Password required
                phase = AuthPhase.CHALLENGE
            elif code in [481, 482, 502]:  # Auth failed/required
                phase = AuthPhase.RESULT
            else:
                return None
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
        """Build NNTP credential from AUTHINFO exchange."""
        username = None
        password = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            command = self._get_first(msg.raw_data.get("nntp.command", "")).upper()
            authinfo = self._get_first(msg.raw_data.get("nntp.authinfo_command", "")).upper()
            auth_data = self._get_first(msg.raw_data.get("nntp.authinfo_data", ""))
            response_code = self._get_first(msg.raw_data.get("nntp.response_code", ""))

            # Parse AUTHINFO commands
            if "AUTHINFO USER" in command or authinfo == "USER":
                # Extract username
                if auth_data:
                    username = auth_data
                else:
                    parts = command.split()
                    if len(parts) >= 3:
                        username = parts[2]
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp

            elif "AUTHINFO PASS" in command or authinfo == "PASS":
                # Extract password
                if auth_data:
                    password = auth_data
                else:
                    parts = command.split()
                    if len(parts) >= 3:
                        password = parts[2]

            # Check response codes
            if response_code:
                code = int(response_code) if response_code.isdigit() else 0
                if code == 281:
                    auth_success = True
                elif code in [481, 482, 502]:
                    auth_success = False

        if not username:
            return None

        metadata = ProtocolMetadata(
            raw_fields={
                "note": "NNTP AUTHINFO credentials in plaintext",
            }
        )

        return ExtractedCredential(
            protocol="nntp",
            username=username,
            domain=server_ip,
            credential_data={
                "password": password,  # PLAINTEXT
            },
            hashcat_format=None,  # Plaintext
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=119,
            target_service="nntp",
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
        return None  # Plaintext
