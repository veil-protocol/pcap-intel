#!/usr/bin/env python3
"""
AUTH ENGINE - IMAP Credential Handler

Extracts IMAP authentication credentials.

IMAP AUTH Methods:
    - LOGIN: IMAP LOGIN username password (plaintext)
    - AUTHENTICATE PLAIN: Base64(null + username + null + password)
    - AUTHENTICATE LOGIN: Base64 username, then Base64 password
    - AUTHENTICATE CRAM-MD5: Challenge-response

Hashcat: Mode 16400 for CRAM-MD5
"""

import base64
from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class IMAPAuthHandler(AuthProtocolHandler):
    """
    Handler for IMAP authentication.

    Supports LOGIN, AUTHENTICATE PLAIN, LOGIN, CRAM-MD5.
    """

    @property
    def protocol_name(self) -> str:
        return "imap"

    @property
    def tshark_filter(self) -> str:
        return "imap.request or imap.response"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "imap.request",
            "imap.request.command",
            "imap.request.tag",
            "imap.response",
            "imap.response.tag",
            "imap.response.status",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify IMAP auth message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        request = self._get_first(fields.get("imap.request", "")).upper()
        command = self._get_first(fields.get("imap.request.command", "")).upper()
        response = self._get_first(fields.get("imap.response", ""))
        status = self._get_first(fields.get("imap.response.status", "")).upper()

        if command == "LOGIN" or "LOGIN" in request:
            phase = AuthPhase.RESPONSE
        elif command == "AUTHENTICATE" or "AUTHENTICATE" in request:
            phase = AuthPhase.INITIATION
        elif status == "OK":
            phase = AuthPhase.RESULT
        elif status == "NO" or status == "BAD":
            phase = AuthPhase.RESULT
        elif "+" in response:  # Server continuation
            phase = AuthPhase.CHALLENGE
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
        """Build IMAP credential from auth exchange."""
        auth_type = None
        username = None
        password = None
        challenge = None
        response_hash = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0

        continuation_data = []

        for msg in sorted(messages, key=lambda m: m.timestamp):
            request = self._get_first(msg.raw_data.get("imap.request", ""))
            status = self._get_first(msg.raw_data.get("imap.response.status", "")).upper()
            response = self._get_first(msg.raw_data.get("imap.response", ""))

            request_upper = request.upper()

            # Parse LOGIN command: tag LOGIN username password
            if "LOGIN" in request_upper and "AUTHENTICATE" not in request_upper:
                parts = request.split()
                if len(parts) >= 4:
                    # tag LOGIN user pass
                    username = parts[2].strip('"')
                    password = parts[3].strip('"')
                    auth_type = "LOGIN"
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp

            # Parse AUTHENTICATE command
            elif "AUTHENTICATE" in request_upper:
                parts = request.split()
                if len(parts) >= 3:
                    auth_type = parts[2].upper()
                    if len(parts) > 3:
                        continuation_data.append(parts[3])
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp

            # Server challenge
            elif response.startswith("+"):
                challenge = response[1:].strip()

            # Client continuation response
            elif request and not any(cmd in request_upper for cmd in ["LOGIN", "AUTHENTICATE", "CAPABILITY", "NOOP"]):
                continuation_data.append(request.strip())

            # Result
            elif status == "OK":
                auth_success = True
            elif status in ["NO", "BAD"]:
                auth_success = False

        # Parse continuation data based on auth type
        if auth_type == "PLAIN" and continuation_data:
            try:
                decoded = base64.b64decode(continuation_data[0]).decode("utf-8", errors="replace")
                parts = decoded.split("\x00")
                if len(parts) >= 3:
                    username = parts[1] or parts[0]
                    password = parts[2]
                elif len(parts) == 2:
                    username = parts[0]
                    password = parts[1]
            except Exception:
                pass

        elif auth_type == "CRAM-MD5" and continuation_data and challenge:
            try:
                decoded_response = base64.b64decode(continuation_data[0]).decode("utf-8", errors="replace")
                parts = decoded_response.rsplit(" ", 1)
                if len(parts) == 2:
                    username = parts[0]
                    response_hash = parts[1]
            except Exception:
                pass

        if not username:
            return None

        cred_data = {"auth_type": auth_type or "LOGIN"}
        hashcat_format = None
        hashcat_mode = None

        if password:
            cred_data["password"] = password  # PLAINTEXT
        elif auth_type == "CRAM-MD5" and challenge and response_hash:
            cred_data["challenge"] = challenge
            cred_data["response"] = response_hash
            hashcat_mode = 16400

        metadata = ProtocolMetadata(
            raw_fields={
                "auth_type": auth_type or "LOGIN",
                "auth_success": auth_success,
            }
        )

        return ExtractedCredential(
            protocol="imap",
            username=username,
            domain=server_ip,
            credential_data=cred_data,
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 143,
            target_service="imap",
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
        return 16400  # CRAM-MD5
