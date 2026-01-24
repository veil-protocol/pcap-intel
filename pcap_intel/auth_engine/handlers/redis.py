#!/usr/bin/env python3
"""
AUTH ENGINE - Redis Credential Handler

Extracts Redis authentication credentials.

Redis Auth:
    - AUTH <password> (Redis < 6.0)
    - AUTH <username> <password> (Redis 6.0+ ACL)
    - Sent in plaintext

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


class RedisAuthHandler(AuthProtocolHandler):
    """
    Handler for Redis authentication.

    Extracts AUTH commands from Redis protocol.
    Credentials are plaintext.
    """

    @property
    def protocol_name(self) -> str:
        return "redis"

    @property
    def tshark_filter(self) -> str:
        return "redis"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "redis.command",
            "redis.argument",
            "redis.response",
            "redis.string",
            "redis.bulk.string",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify Redis message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        command = self._get_first(fields.get("redis.command", "")).upper()
        response = self._get_first(fields.get("redis.response", ""))
        bulk_string = self._get_first(fields.get("redis.bulk.string", "")).upper()

        # Check for AUTH command
        if command == "AUTH" or bulk_string == "AUTH":
            phase = AuthPhase.RESPONSE
        elif response:
            resp_upper = response.upper()
            if "+OK" in resp_upper:
                phase = AuthPhase.RESULT
            elif "-ERR" in resp_upper or "NOAUTH" in resp_upper or "invalid" in response.lower():
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
        """Build Redis credential from AUTH command."""
        username = None
        password = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            command = self._get_first(msg.raw_data.get("redis.command", "")).upper()
            args = msg.raw_data.get("redis.argument", [])
            if isinstance(args, str):
                args = [args]
            response = self._get_first(msg.raw_data.get("redis.response", ""))
            bulk = self._get_first(msg.raw_data.get("redis.bulk.string", "")).upper()

            if command == "AUTH" or bulk == "AUTH":
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp

                if args:
                    if len(args) >= 2:
                        # Redis 6.0+ ACL: AUTH <username> <password>
                        username = args[0]
                        password = args[1]
                    elif len(args) == 1:
                        # Redis < 6.0: AUTH <password>
                        username = "default"
                        password = args[0]

            if response:
                resp_upper = response.upper()
                if "+OK" in resp_upper:
                    auth_success = True
                elif "-ERR" in resp_upper or "NOAUTH" in resp_upper:
                    auth_success = False

        if not password:
            return None

        metadata = ProtocolMetadata(
            raw_fields={
                "note": "Redis AUTH in plaintext",
            }
        )

        return ExtractedCredential(
            protocol="redis",
            username=username or "default",
            domain=server_ip,
            credential_data={
                "password": password,  # PLAINTEXT
            },
            hashcat_format=None,
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 6379,
            target_service="redis",
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
