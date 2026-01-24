#!/usr/bin/env python3
"""
AUTH ENGINE - FTP Credential Handler

Extracts FTP credentials from plaintext USER/PASS commands.

FTP Authentication:
    Client: USER <username>
    Server: 331 Password required
    Client: PASS <password>
    Server: 230 Login successful / 530 Login incorrect

Hashcat: N/A (plaintext passwords)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class FTPAuthHandler(AuthProtocolHandler):
    """
    Handler for FTP authentication.

    FTP sends credentials in plaintext - no hashing involved.
    Extracts USER and PASS commands from FTP control channel.
    """

    @property
    def protocol_name(self) -> str:
        return "ftp"

    @property
    def tshark_filter(self) -> str:
        return "ftp.request.command == USER or ftp.request.command == PASS or ftp.response.code"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "ftp.request.command",
            "ftp.request.arg",
            "ftp.response.code",
            "ftp.response.arg",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify FTP auth message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        command = self._get_first(fields.get("ftp.request.command", "")).upper()
        response_code = self._get_first(fields.get("ftp.response.code", ""))

        if command == "USER":
            phase = AuthPhase.INITIATION
        elif command == "PASS":
            phase = AuthPhase.RESPONSE
        elif response_code:
            code = int(response_code) if response_code.isdigit() else 0
            if code in [230, 530, 331, 332]:
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
        """Build FTP credential from USER/PASS exchange."""
        username = None
        password = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            command = self._get_first(msg.raw_data.get("ftp.request.command", "")).upper()
            arg = self._get_first(msg.raw_data.get("ftp.request.arg", ""))
            response_code = self._get_first(msg.raw_data.get("ftp.response.code", ""))

            if command == "USER":
                username = arg
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp
            elif command == "PASS":
                password = arg
            elif response_code:
                code = int(response_code) if response_code.isdigit() else 0
                if code == 230:
                    auth_success = True
                elif code == 530:
                    auth_success = False

        if not username:
            return None

        metadata = ProtocolMetadata(
            raw_fields={
                "auth_success": auth_success,
            }
        )

        return ExtractedCredential(
            protocol="ftp",
            username=username,
            domain=server_ip,
            credential_data={
                "password": password,  # PLAINTEXT
            },
            hashcat_format=None,
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 21,
            target_service="ftp",
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
