#!/usr/bin/env python3
"""
AUTH ENGINE - AFP Credential Handler

Extracts AFP (Apple Filing Protocol) authentication credentials.

AFP Auth Methods:
    - Cleartext: Plaintext password (AFP 2.x)
    - Randnum: Random number exchange
    - 2-Way Randnum: Mutual auth
    - DHCAST128: Diffie-Hellman + CAST-128
    - DHX: Diffie-Hellman Exchange
    - DHX2: Enhanced DH (AFP 3.1+)
    - Kerberos: For AD environments
    - Reconnect: Session resume

Hashcat Mode: N/A (encrypted key exchange)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class AFPAuthHandler(AuthProtocolHandler):
    """
    Handler for AFP (Apple Filing Protocol) authentication.

    Extracts authentication attempts from AFP sessions.
    """

    @property
    def protocol_name(self) -> str:
        return "afp"

    @property
    def tshark_filter(self) -> str:
        return "afp"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "afp.command",
            "afp.AFPVersion",
            "afp.UAM",
            "afp.user",
            "afp.passwd",
            "afp.random",
            "afp.server_name",
            "afp.machine_type",
            "afp.vol_name",
            "afp.result_code",
            "afp.login.flags",
            "afp.path_type",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify AFP message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        command = self._get_first(fields.get("afp.command", ""))
        result = self._get_first(fields.get("afp.result_code", ""))
        user = self._get_first(fields.get("afp.user", ""))
        uam = self._get_first(fields.get("afp.UAM", ""))

        # AFP commands:
        # 18 = FPLogin
        # 19 = FPLoginCont
        # 20 = FPLogout
        # 24 = FPGetSrvrInfo
        # 63 = FPLoginExt

        if command in ["18", "63"]:  # FPLogin, FPLoginExt
            phase = AuthPhase.INITIATION
        elif command == "19":  # FPLoginCont
            phase = AuthPhase.RESPONSE
        elif result:
            phase = AuthPhase.RESULT
        elif user or uam:
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
        """Build AFP credential from login exchange."""
        username = None
        password = None
        uam = None
        afp_version = None
        server_name = None
        machine_type = None
        random_data = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            user = self._get_first(msg.raw_data.get("afp.user", ""))
            if user:
                username = user
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp

            pwd = self._get_first(msg.raw_data.get("afp.passwd", ""))
            if pwd:
                password = pwd

            u = self._get_first(msg.raw_data.get("afp.UAM", ""))
            if u:
                uam = u

            ver = self._get_first(msg.raw_data.get("afp.AFPVersion", ""))
            if ver:
                afp_version = ver

            srv = self._get_first(msg.raw_data.get("afp.server_name", ""))
            if srv:
                server_name = srv

            mtype = self._get_first(msg.raw_data.get("afp.machine_type", ""))
            if mtype:
                machine_type = mtype

            rand = self._get_first(msg.raw_data.get("afp.random", ""))
            if rand:
                random_data = rand.replace(":", "")

            result = self._get_first(msg.raw_data.get("afp.result_code", ""))
            if result:
                if result == "0":
                    auth_success = True
                else:
                    auth_success = False

        if not username:
            return None

        # UAM types
        uam_types = {
            "No User Authent": "none",
            "Cleartxt Passwrd": "cleartext",
            "Randnum Exchange": "randnum",
            "2-Way Randnum": "randnum2way",
            "DHCAST128": "dhcast128",
            "DHX": "dhx",
            "DHX2": "dhx2",
            "Client Krb v2": "kerberos",
            "Recon1": "reconnect",
        }
        uam_name = uam_types.get(uam, uam)

        metadata = ProtocolMetadata(
            server_version=afp_version,
            target_hostname=server_name,
            raw_fields={
                "uam": uam,
                "uam_name": uam_name,
                "machine_type": machine_type,
                "random_data": random_data,
            }
        )

        return ExtractedCredential(
            protocol="afp",
            username=username,
            domain=server_name,
            credential_data={
                "password": password,  # Only for Cleartext UAM
                "uam": uam,
                "random_data": random_data,
            },
            hashcat_format=None,  # DH-based, not crackable offline
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=548,
            target_service="afp",
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
        return None  # DH-based exchange
