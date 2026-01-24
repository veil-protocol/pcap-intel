#!/usr/bin/env python3
"""
AUTH ENGINE - Telnet Credential Handler

Extracts Telnet credentials from interactive sessions.

Telnet sends credentials in plaintext over TCP.
Tshark can extract the data stream.

Hashcat: N/A (plaintext)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class TelnetAuthHandler(AuthProtocolHandler):
    """
    Handler for Telnet authentication.

    Extracts username and password from Telnet streams.
    """

    @property
    def protocol_name(self) -> str:
        return "telnet"

    @property
    def tshark_filter(self) -> str:
        return "telnet.data"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "telnet.data",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify Telnet data as potential auth."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        data = self._get_first(fields.get("telnet.data", ""))
        if not data:
            return None

        # Telnet data is either server prompt or client response
        data_lower = data.lower()

        if any(prompt in data_lower for prompt in ["login:", "username:", "user:"]):
            phase = AuthPhase.CHALLENGE
        elif "password:" in data_lower:
            phase = AuthPhase.CHALLENGE
        elif dst_port == 23:  # Client sending to server
            phase = AuthPhase.RESPONSE
        elif src_port == 23:  # Server sending to client
            phase = AuthPhase.CHALLENGE
        else:
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
        """Build Telnet credential from data stream."""
        username = None
        password = None
        client_ip = None
        server_ip = None
        server_port = None
        timestamp = 0.0

        awaiting_username = False
        awaiting_password = False

        for msg in sorted(messages, key=lambda m: m.timestamp):
            data = self._get_first(msg.raw_data.get("telnet.data", ""))
            if not data:
                continue

            data_clean = data.strip()
            data_lower = data_clean.lower()

            # Detect prompts (from server)
            if msg.source_port == 23:  # Server
                if any(p in data_lower for p in ["login:", "username:", "user:"]):
                    awaiting_username = True
                    awaiting_password = False
                    server_ip = msg.source_ip
                    client_ip = msg.dest_ip
                elif "password:" in data_lower:
                    awaiting_password = True
                    awaiting_username = False

            # Detect responses (from client)
            elif msg.dest_port == 23:  # Client
                if awaiting_username and data_clean:
                    # Filter out control chars
                    username = ''.join(c for c in data_clean if c.isprintable())
                    awaiting_username = False
                    timestamp = msg.timestamp
                elif awaiting_password and data_clean:
                    password = ''.join(c for c in data_clean if c.isprintable())
                    awaiting_password = False

        if not username:
            return None

        metadata = ProtocolMetadata(
            raw_fields={
                "note": "Telnet plaintext capture",
            }
        )

        return ExtractedCredential(
            protocol="telnet",
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
            target_port=server_port or 23,
            target_service="telnet",
            timestamp=timestamp,
            metadata=metadata,
        )

    def _get_first(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def get_hashcat_mode(self) -> Optional[int]:
        return None  # Plaintext
