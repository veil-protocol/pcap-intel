#!/usr/bin/env python3
"""
AUTH ENGINE - SOCKS Credential Handler

Extracts SOCKS proxy authentication credentials.

SOCKS Protocol:
    - SOCKS4: No authentication or IDENT
    - SOCKS4a: With domain name support
    - SOCKS5: Username/password auth (RFC 1929)

SOCKS5 auth is sent in plaintext unless wrapped in TLS.

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


class SOCKSAuthHandler(AuthProtocolHandler):
    """
    Handler for SOCKS proxy authentication.

    Extracts plaintext username/password from SOCKS5.
    """

    @property
    def protocol_name(self) -> str:
        return "socks"

    @property
    def tshark_filter(self) -> str:
        return "socks"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "socks.version",
            "socks.nmethods",
            "socks.method",
            "socks.results",
            "socks.cmd",
            "socks.reserved",
            "socks.atyp",
            "socks.dst.port",
            "socks.dst",
            # SOCKS5 auth
            "socks.authmethod.version",
            "socks.authmethod.username.length",
            "socks.authmethod.username",
            "socks.authmethod.password.length",
            "socks.authmethod.password",
            "socks.authmethod.status",
            # SOCKS4
            "socks.userid",
            "socks.dstip",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify SOCKS message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        version = self._get_first(fields.get("socks.version", ""))
        method = self._get_first(fields.get("socks.method", ""))
        username = self._get_first(fields.get("socks.authmethod.username", ""))
        password = self._get_first(fields.get("socks.authmethod.password", ""))
        status = self._get_first(fields.get("socks.authmethod.status", ""))
        userid = self._get_first(fields.get("socks.userid", ""))

        if username or password:
            phase = AuthPhase.RESPONSE  # Client sending credentials
        elif status:
            phase = AuthPhase.RESULT  # Server auth response
        elif method == "2":  # Username/password method selected
            phase = AuthPhase.CHALLENGE
        elif userid:  # SOCKS4 userid
            phase = AuthPhase.RESPONSE
        elif version:
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
        """Build SOCKS credential from auth exchange."""
        username = None
        password = None
        userid = None
        version = None
        dest_addr = None
        dest_port = None
        auth_method = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            ver = self._get_first(msg.raw_data.get("socks.version", ""))
            if ver:
                version = ver

            user = self._get_first(msg.raw_data.get("socks.authmethod.username", ""))
            if user:
                username = user
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp

            pwd = self._get_first(msg.raw_data.get("socks.authmethod.password", ""))
            if pwd:
                password = pwd

            uid = self._get_first(msg.raw_data.get("socks.userid", ""))
            if uid:
                userid = uid
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp

            dst = self._get_first(msg.raw_data.get("socks.dst", ""))
            if dst:
                dest_addr = dst

            dp = self._get_first(msg.raw_data.get("socks.dst.port", ""))
            if dp:
                dest_port = dp

            method = self._get_first(msg.raw_data.get("socks.method", ""))
            if method:
                auth_method = method

            status = self._get_first(msg.raw_data.get("socks.authmethod.status", ""))
            if status:
                auth_success = (status == "0")  # 0 = success

            results = self._get_first(msg.raw_data.get("socks.results", ""))
            if results:
                auth_success = (results == "0")  # 0 = request granted

        if not username and not userid:
            return None

        version_name = {
            "4": "SOCKS4",
            "5": "SOCKS5",
        }.get(version, f"SOCKS{version}")

        metadata = ProtocolMetadata(
            raw_fields={
                "version": version,
                "version_name": version_name,
                "auth_method": auth_method,
                "dest_addr": dest_addr,
                "dest_port": dest_port,
                "note": "SOCKS credentials in plaintext",
            }
        )

        return ExtractedCredential(
            protocol="socks",
            username=username or userid or "unknown",
            domain=server_ip,
            credential_data={
                "password": password,  # PLAINTEXT
                "userid": userid,  # SOCKS4
                "version": version,
            },
            hashcat_format=None,  # Plaintext
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 1080,
            target_service="socks",
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
