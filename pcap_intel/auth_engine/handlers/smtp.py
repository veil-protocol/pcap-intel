#!/usr/bin/env python3
"""
AUTH ENGINE - SMTP Credential Handler

Extracts SMTP authentication credentials.

SMTP AUTH Mechanisms:
    - PLAIN: Base64(null + username + null + password)
    - LOGIN: Base64 username, then Base64 password
    - CRAM-MD5: Challenge-response

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


class SMTPAuthHandler(AuthProtocolHandler):
    """
    Handler for SMTP authentication.

    Supports AUTH PLAIN, AUTH LOGIN, and AUTH CRAM-MD5.
    """

    @property
    def protocol_name(self) -> str:
        return "smtp"

    @property
    def tshark_filter(self) -> str:
        return "smtp.req.command or smtp.response.code"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "smtp.req.command",
            "smtp.req.parameter",
            "smtp.response.code",
            "smtp.auth.username",
            "smtp.auth.password",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify SMTP auth message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        command = self._get_first(fields.get("smtp.req.command", "")).upper()
        param = self._get_first(fields.get("smtp.req.parameter", ""))
        response_code = self._get_first(fields.get("smtp.response.code", ""))

        if command == "AUTH":
            phase = AuthPhase.INITIATION
        elif command == "EHLO" or command == "HELO":
            return None  # Not auth
        elif response_code:
            code = int(response_code) if response_code.isdigit() else 0
            if code == 334:  # Continue
                phase = AuthPhase.CHALLENGE
            elif code == 235:  # Auth success
                phase = AuthPhase.RESULT
            elif code == 535:  # Auth failed
                phase = AuthPhase.RESULT
            else:
                return None
        elif param and not command:
            # Continuation data (base64 encoded)
            phase = AuthPhase.RESPONSE
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
        """Build SMTP credential from auth exchange."""
        auth_type = None
        username = None
        password = None
        challenge = None
        response = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0

        continuation_data = []

        for msg in sorted(messages, key=lambda m: m.timestamp):
            command = self._get_first(msg.raw_data.get("smtp.req.command", "")).upper()
            param = self._get_first(msg.raw_data.get("smtp.req.parameter", ""))
            response_code = self._get_first(msg.raw_data.get("smtp.response.code", ""))

            # Check for tshark-decoded username/password
            tshark_user = self._get_first(msg.raw_data.get("smtp.auth.username", ""))
            tshark_pass = self._get_first(msg.raw_data.get("smtp.auth.password", ""))
            if tshark_user:
                username = tshark_user
            if tshark_pass:
                password = tshark_pass

            if command == "AUTH":
                parts = param.split(None, 1)
                if parts:
                    auth_type = parts[0].upper()
                    if len(parts) > 1:
                        # Initial data provided with AUTH command
                        continuation_data.append(parts[1])
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp
            elif response_code == "334":
                # Challenge from server (base64 encoded)
                challenge = param
            elif response_code == "235":
                auth_success = True
            elif response_code == "535":
                auth_success = False
            elif param and not command:
                # Client continuation data
                continuation_data.append(param)

        # Parse based on auth type
        if auth_type == "PLAIN" and continuation_data:
            # PLAIN: base64(null + username + null + password)
            try:
                decoded = base64.b64decode(continuation_data[0]).decode("utf-8", errors="replace")
                parts = decoded.split("\x00")
                if len(parts) >= 3:
                    # Format: authzid\0authcid\0password
                    username = parts[1] or parts[0]
                    password = parts[2]
                elif len(parts) == 2:
                    username = parts[0]
                    password = parts[1]
            except Exception:
                pass

        elif auth_type == "LOGIN" and len(continuation_data) >= 2:
            # LOGIN: base64(username), then base64(password)
            try:
                username = base64.b64decode(continuation_data[0]).decode("utf-8", errors="replace")
                password = base64.b64decode(continuation_data[1]).decode("utf-8", errors="replace")
            except Exception:
                pass

        elif auth_type == "CRAM-MD5" and continuation_data and challenge:
            # CRAM-MD5: challenge-response
            try:
                decoded_response = base64.b64decode(continuation_data[0]).decode("utf-8", errors="replace")
                # Format: username digest
                parts = decoded_response.rsplit(" ", 1)
                if len(parts) == 2:
                    username = parts[0]
                    response = parts[1]
            except Exception:
                pass

        if not username:
            return None

        cred_data = {"auth_type": auth_type}
        hashcat_format = None
        hashcat_mode = None

        if password:
            cred_data["password"] = password  # PLAINTEXT
        elif auth_type == "CRAM-MD5" and challenge and response:
            cred_data["challenge"] = challenge
            cred_data["response"] = response
            hashcat_mode = 16400  # CRAM-MD5

        metadata = ProtocolMetadata(
            raw_fields={
                "auth_type": auth_type,
                "auth_success": auth_success,
            }
        )

        return ExtractedCredential(
            protocol="smtp",
            username=username,
            domain=server_ip,
            credential_data=cred_data,
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 25,
            target_service="smtp",
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
