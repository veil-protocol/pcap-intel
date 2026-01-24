#!/usr/bin/env python3
"""
AUTH ENGINE - PostgreSQL Credential Handler

Extracts PostgreSQL authentication credentials.

PostgreSQL Auth Methods:
    - md5: MD5(MD5(password + username) + salt)
    - scram-sha-256: SCRAM-SHA-256 (PostgreSQL 10+)
    - password: Plaintext (deprecated)

Hashcat Modes:
    - 12000: PostgreSQL md5
    - 28600: PostgreSQL SCRAM-SHA-256
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class PostgreSQLAuthHandler(AuthProtocolHandler):
    """
    Handler for PostgreSQL authentication.

    Extracts md5 and SCRAM-SHA-256 credentials.
    """

    @property
    def protocol_name(self) -> str:
        return "postgresql"

    @property
    def tshark_filter(self) -> str:
        return "pgsql"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "pgsql.type",
            "pgsql.format",
            "pgsql.val.name",
            "pgsql.val.value",
            "pgsql.parameter_name",
            "pgsql.parameter_value",
            "pgsql.authtype",
            "pgsql.salt",
            "pgsql.password",
            "pgsql.error.message",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify PostgreSQL auth message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        msg_type = self._get_first(fields.get("pgsql.type", ""))
        authtype = self._get_first(fields.get("pgsql.authtype", ""))
        password = self._get_first(fields.get("pgsql.password", ""))
        salt = self._get_first(fields.get("pgsql.salt", ""))
        error = self._get_first(fields.get("pgsql.error.message", ""))

        # Startup message or auth request
        if authtype or salt:
            phase = AuthPhase.CHALLENGE
        elif password:
            phase = AuthPhase.RESPONSE
        elif msg_type == "R" and not authtype:
            # AuthenticationOk
            phase = AuthPhase.RESULT
        elif error:
            phase = AuthPhase.RESULT
        elif msg_type == "p":  # Password message
            phase = AuthPhase.RESPONSE
        else:
            # Check for startup message with user
            param_name = self._get_first(fields.get("pgsql.parameter_name", ""))
            if param_name == "user":
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
        """Build PostgreSQL credential from auth exchange."""
        username = None
        database = None
        password = None
        salt = None
        authtype = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            # Check for startup parameters
            param_names = msg.raw_data.get("pgsql.parameter_name", [])
            param_values = msg.raw_data.get("pgsql.parameter_value", [])

            if isinstance(param_names, list) and isinstance(param_values, list):
                for name, value in zip(param_names, param_values):
                    if name == "user":
                        username = value
                        client_ip = msg.source_ip
                        server_ip = msg.dest_ip
                        server_port = msg.dest_port
                        timestamp = msg.timestamp
                    elif name == "database":
                        database = value
            elif param_names == "user":
                username = self._get_first(param_values)
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp

            # Server auth request
            at = self._get_first(msg.raw_data.get("pgsql.authtype", ""))
            s = self._get_first(msg.raw_data.get("pgsql.salt", ""))

            if at:
                authtype = at
            if s:
                salt = s
                server_ip = msg.source_ip

            # Client password
            pw = self._get_first(msg.raw_data.get("pgsql.password", ""))
            if pw:
                password = pw

            # Result
            msg_type = self._get_first(msg.raw_data.get("pgsql.type", ""))
            error = self._get_first(msg.raw_data.get("pgsql.error.message", ""))

            if msg_type == "R" and not self._get_first(msg.raw_data.get("pgsql.authtype", "")):
                auth_success = True
            elif error:
                auth_success = False

        if not username:
            return None

        hashcat_format = None
        hashcat_mode = None

        # Determine hash format based on auth type
        if authtype == "5" and password and salt:
            # MD5: md5 + MD5(MD5(password + user) + salt)
            # Format: $postgres$user*salt*hash
            hashcat_mode = 12000
            if password.startswith("md5"):
                hashcat_format = f"$postgres${username}*{salt}*{password[3:]}"

        metadata = ProtocolMetadata(
            raw_fields={
                "authtype": authtype,
                "database": database,
                "salt": salt,
            }
        )

        return ExtractedCredential(
            protocol="postgresql",
            username=username,
            domain=database or server_ip,
            credential_data={
                "password_hash": password,
                "salt": salt,
                "authtype": authtype,
                "database": database,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 5432,
            target_service="postgresql",
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
        return 12000  # PostgreSQL md5
