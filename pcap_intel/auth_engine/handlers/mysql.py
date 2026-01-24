#!/usr/bin/env python3
"""
AUTH ENGINE - MySQL Credential Handler

Extracts MySQL authentication credentials.

MySQL Auth Protocol:
    1. Server sends greeting with auth plugin and scramble
    2. Client sends username + scrambled password
    3. Server confirms (OK/ERR)

Hashcat Modes:
    - 200: MySQL323 (old)
    - 300: MySQL4.1/MySQL5
    - 11200: MySQL $A$ (sha256)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class MySQLAuthHandler(AuthProtocolHandler):
    """
    Handler for MySQL authentication.

    Extracts challenge-response from MySQL auth handshake.
    """

    @property
    def protocol_name(self) -> str:
        return "mysql"

    @property
    def tshark_filter(self) -> str:
        return "mysql"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # Server greeting
            "mysql.version",
            "mysql.server_greeting",
            "mysql.salt",
            "mysql.salt2",
            "mysql.caps.server",
            "mysql.auth_plugin",
            # Client auth
            "mysql.user",
            "mysql.passwd",
            "mysql.schema",
            "mysql.caps.client",
            "mysql.client_auth_plugin",
            # Response
            "mysql.response_code",
            "mysql.error_code",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify MySQL auth message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        # Determine message type
        version = self._get_first(fields.get("mysql.version", ""))
        salt = self._get_first(fields.get("mysql.salt", ""))
        user = self._get_first(fields.get("mysql.user", ""))
        passwd = self._get_first(fields.get("mysql.passwd", ""))
        response_code = self._get_first(fields.get("mysql.response_code", ""))

        if version or salt:
            phase = AuthPhase.CHALLENGE  # Server greeting
        elif user or passwd:
            phase = AuthPhase.RESPONSE  # Client auth
        elif response_code:
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
        """Build MySQL credential from auth exchange."""
        username = None
        passwd_hash = None
        salt1 = None
        salt2 = None
        version = None
        auth_plugin = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            # Server greeting
            v = self._get_first(msg.raw_data.get("mysql.version", ""))
            s1 = self._get_first(msg.raw_data.get("mysql.salt", ""))
            s2 = self._get_first(msg.raw_data.get("mysql.salt2", ""))
            plugin = self._get_first(msg.raw_data.get("mysql.auth_plugin", ""))

            if v:
                version = v
                server_ip = msg.source_ip
                server_port = msg.source_port
            if s1:
                salt1 = s1
            if s2:
                salt2 = s2
            if plugin:
                auth_plugin = plugin

            # Client auth
            user = self._get_first(msg.raw_data.get("mysql.user", ""))
            passwd = self._get_first(msg.raw_data.get("mysql.passwd", ""))

            if user:
                username = user
                client_ip = msg.source_ip
                timestamp = msg.timestamp
            if passwd:
                passwd_hash = passwd

            # Result
            response = self._get_first(msg.raw_data.get("mysql.response_code", ""))
            error = self._get_first(msg.raw_data.get("mysql.error_code", ""))

            if response == "0":  # OK
                auth_success = True
            elif error:
                auth_success = False

        if not username:
            return None

        # Build hashcat format
        hashcat_format = None
        hashcat_mode = None

        if salt1 and passwd_hash:
            # Full salt is salt1 + salt2
            full_salt = salt1 + (salt2 or "")
            # MySQL hash format: username:$mysql$salt$response
            # Mode 300 for MySQL4.1/5
            hashcat_mode = 300
            if passwd_hash.startswith("*"):
                # Already in MySQL format
                hashcat_format = f"{username}:{passwd_hash}"
            else:
                hashcat_format = f"{username}:$mysql${full_salt}${passwd_hash}"

        metadata = ProtocolMetadata(
            server_version=version,
            raw_fields={
                "auth_plugin": auth_plugin,
                "salt1": salt1,
                "salt2": salt2,
            }
        )

        return ExtractedCredential(
            protocol="mysql",
            username=username,
            domain=server_ip,
            credential_data={
                "passwd_hash": passwd_hash,
                "salt": (salt1 or "") + (salt2 or ""),
                "auth_plugin": auth_plugin,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 3306,
            target_service="mysql",
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
        return 300  # MySQL4.1/5
