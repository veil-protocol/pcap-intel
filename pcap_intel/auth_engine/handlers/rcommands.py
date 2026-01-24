#!/usr/bin/env python3
"""
AUTH ENGINE - Berkeley r-commands Credential Handler

Extracts credentials from legacy Berkeley r-commands.

r-commands (RFC 1282):
    - rsh (remote shell) - port 514
    - rlogin (remote login) - port 513
    - rexec (remote exec) - port 512

These are trust-based (no password for rsh/rlogin with .rhosts)
but rexec sends plaintext username/password.

Hashcat Mode: N/A (plaintext or trust-based)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class RCommandsAuthHandler(AuthProtocolHandler):
    """
    Handler for Berkeley r-commands (rsh, rlogin, rexec).

    Extracts plaintext credentials and trust relationships.
    """

    @property
    def protocol_name(self) -> str:
        return "rcommands"

    @property
    def tshark_filter(self) -> str:
        # r-commands on their respective ports
        return "tcp.port == 512 or tcp.port == 513 or tcp.port == 514"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # Need to parse TCP payload for r-commands
            # These protocols send null-terminated strings
            "tcp.payload",
            "data.data",
            "data.text",
            # Basic TCP info
            "tcp.srcport",
            "tcp.dstport",
            "tcp.flags.syn",
            "tcp.flags.fin",
            "tcp.len",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify r-command message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        # Check for r-command ports
        if dst_port not in [512, 513, 514] and src_port not in [512, 513, 514]:
            return None

        payload = self._get_first(fields.get("tcp.payload", "")) or \
                  self._get_first(fields.get("data.data", ""))
        tcp_len = int(self._get_first(fields.get("tcp.len", 0)) or 0)
        syn = self._get_first(fields.get("tcp.flags.syn", ""))

        if syn == "1":
            phase = AuthPhase.INITIATION
        elif payload and tcp_len > 0:
            # Data being sent - credentials or commands
            if dst_port in [512, 513, 514]:
                phase = AuthPhase.RESPONSE  # Client sending creds
            else:
                phase = AuthPhase.RESULT  # Server response
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
        """Build r-command credential from captured data."""
        local_user = None
        remote_user = None
        password = None  # Only for rexec
        command = None
        service = None
        client_ip = None
        server_ip = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            dst_port = msg.dest_port
            src_port = msg.source_port

            # Determine service
            if dst_port == 512 or src_port == 512:
                service = "rexec"
            elif dst_port == 513 or src_port == 513:
                service = "rlogin"
            elif dst_port == 514 or src_port == 514:
                service = "rsh"

            if dst_port in [512, 513, 514]:
                client_ip = msg.source_ip
                server_ip = msg.dest_ip

            # Try to parse payload
            payload_hex = self._get_first(msg.raw_data.get("tcp.payload", "")) or \
                          self._get_first(msg.raw_data.get("data.data", ""))

            if payload_hex:
                try:
                    # Convert hex to bytes
                    payload_bytes = bytes.fromhex(payload_hex.replace(":", ""))
                    # Split on null bytes
                    parts = payload_bytes.split(b'\x00')
                    parts = [p.decode('utf-8', errors='ignore').strip() for p in parts if p]

                    if service == "rexec" and len(parts) >= 3:
                        # rexec format: port\0username\0password\0command\0
                        if parts[0].isdigit():
                            parts = parts[1:]  # Skip stderr port
                        if len(parts) >= 3:
                            remote_user = parts[0]
                            password = parts[1]
                            command = parts[2] if len(parts) > 2 else None
                            timestamp = msg.timestamp

                    elif service == "rsh" and len(parts) >= 2:
                        # rsh format: port\0local_user\0remote_user\0command\0
                        if parts[0].isdigit():
                            parts = parts[1:]
                        if len(parts) >= 2:
                            local_user = parts[0]
                            remote_user = parts[1]
                            command = parts[2] if len(parts) > 2 else None
                            timestamp = msg.timestamp

                    elif service == "rlogin" and len(parts) >= 2:
                        # rlogin format: \0local_user\0remote_user\0terminal/speed\0
                        if parts[0] == '':
                            parts = parts[1:]
                        if len(parts) >= 2:
                            local_user = parts[0]
                            remote_user = parts[1]
                            timestamp = msg.timestamp

                except Exception:
                    pass

        if not remote_user and not local_user:
            return None

        username = remote_user or local_user

        metadata = ProtocolMetadata(
            raw_fields={
                "service": service,
                "local_user": local_user,
                "remote_user": remote_user,
                "command": command,
                "note": f"{service} - {'password auth' if password else 'trust-based (.rhosts)'}",
            }
        )

        return ExtractedCredential(
            protocol="rcommands",
            username=username,
            domain=server_ip,
            credential_data={
                "password": password,  # Only for rexec, PLAINTEXT
                "local_user": local_user,
                "remote_user": remote_user,
                "command": command,
                "service": service,
            },
            hashcat_format=None,  # Plaintext or trust-based
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port={"rexec": 512, "rlogin": 513, "rsh": 514}.get(service, 514),
            target_service=service or "rsh",
            timestamp=timestamp,
            metadata=metadata,
            auth_success=None,  # Can't determine
        )

    def _get_first(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def get_hashcat_mode(self) -> Optional[int]:
        return None  # Plaintext or trust-based
