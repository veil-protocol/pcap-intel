#!/usr/bin/env python3
"""
AUTH ENGINE - TACACS+ Credential Handler

Extracts TACACS+ authentication credentials.

TACACS+ Auth (RFC 8907):
    - Terminal Access Controller Access-Control System Plus
    - Used primarily in Cisco environments
    - Supports ASCII, PAP, CHAP authentication
    - Encrypted with shared secret (MD5-based)

Hashcat Mode: 16100 (TACACS+)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class TACACSAuthHandler(AuthProtocolHandler):
    """
    Handler for TACACS+ authentication.

    Extracts encrypted credentials for offline cracking.
    """

    @property
    def protocol_name(self) -> str:
        return "tacacs"

    @property
    def tshark_filter(self) -> str:
        return "tacplus"

    @property
    def correlation_field(self) -> str:
        return "tacplus.session_id"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "tacplus.type",
            "tacplus.session_id",
            "tacplus.seq_no",
            "tacplus.flags",
            "tacplus.length",
            "tacplus.encrypted_flag",
            "tacplus.body",
            # Authentication fields
            "tacplus.authen.action",
            "tacplus.authen.priv_lvl",
            "tacplus.authen.authen_type",
            "tacplus.authen.service",
            "tacplus.authen.user_len",
            "tacplus.authen.user",
            "tacplus.authen.port_len",
            "tacplus.authen.port",
            "tacplus.authen.rem_addr_len",
            "tacplus.authen.rem_addr",
            "tacplus.authen.data_len",
            "tacplus.authen.data",
            "tacplus.authen.status",
            "tacplus.authen.server_msg",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify TACACS+ message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)

        session_id = self._get_first(fields.get("tacplus.session_id", ""))
        msg_type = self._get_first(fields.get("tacplus.type", ""))
        seq_no = self._get_first(fields.get("tacplus.seq_no", ""))

        if not session_id:
            return None

        # Type 1 = Authentication, 2 = Authorization, 3 = Accounting
        # Seq 1 = START, even = REPLY, odd = CONTINUE
        if msg_type == "1":  # Authentication
            seq = int(seq_no) if seq_no else 0
            if seq == 1:
                phase = AuthPhase.INITIATION
            elif seq % 2 == 0:
                phase = AuthPhase.CHALLENGE  # Server reply
            else:
                phase = AuthPhase.RESPONSE  # Client continue
        else:
            return None

        return AuthMessage(
            phase=phase,
            correlation_key=session_id,
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
        """Build TACACS+ credential from exchange."""
        username = None
        password_data = None
        session_id = None
        authen_type = None
        service = None
        port = None
        rem_addr = None
        status = None
        encrypted_body = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            sid = self._get_first(msg.raw_data.get("tacplus.session_id", ""))
            if sid:
                session_id = sid

            user = self._get_first(msg.raw_data.get("tacplus.authen.user", ""))
            if user:
                username = user
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp

            data = self._get_first(msg.raw_data.get("tacplus.authen.data", ""))
            if data:
                password_data = data.replace(":", "")

            body = self._get_first(msg.raw_data.get("tacplus.body", ""))
            if body:
                encrypted_body = body.replace(":", "")

            atype = self._get_first(msg.raw_data.get("tacplus.authen.authen_type", ""))
            if atype:
                authen_type = atype

            svc = self._get_first(msg.raw_data.get("tacplus.authen.service", ""))
            if svc:
                service = svc

            p = self._get_first(msg.raw_data.get("tacplus.authen.port", ""))
            if p:
                port = p

            addr = self._get_first(msg.raw_data.get("tacplus.authen.rem_addr", ""))
            if addr:
                rem_addr = addr

            s = self._get_first(msg.raw_data.get("tacplus.authen.status", ""))
            if s:
                status = s
                if s == "1":  # PASS
                    auth_success = True
                elif s in ["2", "3", "4", "5"]:  # FAIL, GETDATA, GETUSER, GETPASS
                    if s == "2":
                        auth_success = False

        if not session_id:
            return None

        # TACACS+ hashcat format (mode 16100):
        # session_id:encrypted_body
        hashcat_format = None
        if session_id and encrypted_body:
            hashcat_format = f"$tacacs-plus${session_id}${encrypted_body}"

        metadata = ProtocolMetadata(
            raw_fields={
                "session_id": session_id,
                "authen_type": authen_type,
                "service": service,
                "port": port,
                "rem_addr": rem_addr,
                "status": status,
            }
        )

        return ExtractedCredential(
            protocol="tacacs",
            username=username or "unknown",
            domain=server_ip,
            credential_data={
                "session_id": session_id,
                "password_data": password_data,
                "encrypted_body": encrypted_body,
                "authen_type": authen_type,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=16100,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=49,
            target_service="tacacs",
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
        return 16100
