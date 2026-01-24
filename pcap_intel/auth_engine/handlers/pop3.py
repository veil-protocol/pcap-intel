#!/usr/bin/env python3
"""
AUTH ENGINE - POP3 Credential Handler

Extracts POP3 credentials from USER/PASS commands.

POP3 Authentication:
    Client: USER <username>
    Server: +OK
    Client: PASS <password>
    Server: +OK / -ERR

Also handles APOP (challenge-response) authentication.

Hashcat: N/A for plaintext, mode 10900 for APOP
"""

from typing import Dict, List, Optional, Any
import hashlib
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class POP3AuthHandler(AuthProtocolHandler):
    """
    Handler for POP3 authentication.

    Supports:
        - USER/PASS (plaintext)
        - APOP (MD5 challenge-response)
    """

    @property
    def protocol_name(self) -> str:
        return "pop3"

    @property
    def tshark_filter(self) -> str:
        return "pop.request or pop.response"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "pop.request.command",
            "pop.request.parameter",
            "pop.response.indicator",
            "pop.response.description",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify POP3 auth message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        command = self._get_first(fields.get("pop.request.command", "")).upper()
        response = self._get_first(fields.get("pop.response.indicator", ""))

        if command == "USER":
            phase = AuthPhase.INITIATION
        elif command == "PASS":
            phase = AuthPhase.RESPONSE
        elif command == "APOP":
            phase = AuthPhase.RESPONSE
        elif response in ["+OK", "-ERR"]:
            phase = AuthPhase.RESULT
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
        """Build POP3 credential from auth exchange."""
        username = None
        password = None
        apop_digest = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            command = self._get_first(msg.raw_data.get("pop.request.command", "")).upper()
            param = self._get_first(msg.raw_data.get("pop.request.parameter", ""))
            response = self._get_first(msg.raw_data.get("pop.response.indicator", ""))

            if command == "USER":
                username = param
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp
            elif command == "PASS":
                password = param
            elif command == "APOP":
                # APOP <username> <digest>
                parts = param.split(None, 1)
                if len(parts) >= 2:
                    username = parts[0]
                    apop_digest = parts[1]
                elif len(parts) == 1:
                    apop_digest = parts[0]
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp
            elif response == "+OK":
                auth_success = True
            elif response == "-ERR":
                auth_success = False

        if not username:
            return None

        cred_data = {}
        hashcat_format = None
        hashcat_mode = None

        if password:
            cred_data["password"] = password  # PLAINTEXT
        elif apop_digest:
            cred_data["apop_digest"] = apop_digest
            # APOP uses MD5(timestamp + password)
            # Format: username:$apop$timestamp$digest
            hashcat_mode = 10900

        metadata = ProtocolMetadata(
            raw_fields={
                "auth_success": auth_success,
                "auth_type": "APOP" if apop_digest else "USER/PASS",
            }
        )

        return ExtractedCredential(
            protocol="pop3",
            username=username,
            domain=server_ip,
            credential_data=cred_data,
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 110,
            target_service="pop3",
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
        return 10900  # APOP
