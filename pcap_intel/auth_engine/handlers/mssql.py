#!/usr/bin/env python3
"""
AUTH ENGINE - MSSQL (SQL Server) Credential Handler

Extracts MSSQL authentication credentials.

MSSQL Auth:
    - SQL Authentication: Username + password (TDS protocol)
    - Windows Authentication: NTLM/Kerberos (handled by other handlers)

TDS Protocol (Tabular Data Stream) carries auth in LOGIN7 packet.

Hashcat Modes:
    - 1731: MSSQL (2012, 2014)
    - 131: MSSQL (2000)
    - 132: MSSQL (2005)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class MSSQLAuthHandler(AuthProtocolHandler):
    """
    Handler for MSSQL SQL Server authentication.

    Extracts credentials from TDS LOGIN7 packets.
    """

    @property
    def protocol_name(self) -> str:
        return "mssql"

    @property
    def tshark_filter(self) -> str:
        return "tds"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "tds.type",
            "tds.login.username",
            "tds.login.password",
            "tds.login.servername",
            "tds.login.appname",
            "tds.login.hostname",
            "tds.login.database",
            "tds.login.interface.version",
            "tds.error.message",
            "tds.token.done.status",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify MSSQL auth message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        tds_type = self._get_first(fields.get("tds.type", ""))
        username = self._get_first(fields.get("tds.login.username", ""))
        password = self._get_first(fields.get("tds.login.password", ""))
        error = self._get_first(fields.get("tds.error.message", ""))
        done_status = self._get_first(fields.get("tds.token.done.status", ""))

        if username or password:
            phase = AuthPhase.RESPONSE  # Login packet
        elif tds_type == "16":  # TDS7 Login
            phase = AuthPhase.RESPONSE
        elif error:
            phase = AuthPhase.RESULT
        elif done_status:
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
        """Build MSSQL credential from TDS login."""
        username = None
        password = None
        servername = None
        database = None
        appname = None
        hostname = None
        version = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            user = self._get_first(msg.raw_data.get("tds.login.username", ""))
            passwd = self._get_first(msg.raw_data.get("tds.login.password", ""))
            server = self._get_first(msg.raw_data.get("tds.login.servername", ""))
            db = self._get_first(msg.raw_data.get("tds.login.database", ""))
            app = self._get_first(msg.raw_data.get("tds.login.appname", ""))
            host = self._get_first(msg.raw_data.get("tds.login.hostname", ""))
            ver = self._get_first(msg.raw_data.get("tds.login.interface.version", ""))
            error = self._get_first(msg.raw_data.get("tds.error.message", ""))
            done = self._get_first(msg.raw_data.get("tds.token.done.status", ""))

            if user:
                username = user
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp
            if passwd:
                password = passwd
            if server:
                servername = server
            if db:
                database = db
            if app:
                appname = app
            if host:
                hostname = host
            if ver:
                version = ver
            if error:
                auth_success = False
            elif done == "0x0000":  # DONE_FINAL
                auth_success = True

        if not username:
            return None

        # TDS password is XOR-encoded, tshark may decode it
        # If password captured, it's likely plaintext or decoded
        hashcat_format = None
        hashcat_mode = None

        metadata = ProtocolMetadata(
            server_version=version,
            raw_fields={
                "servername": servername,
                "database": database,
                "appname": appname,
                "hostname": hostname,
            }
        )

        return ExtractedCredential(
            protocol="mssql",
            username=username,
            domain=servername or server_ip,
            credential_data={
                "password": password,  # May be XOR-decoded
                "servername": servername,
                "database": database,
                "appname": appname,
                "hostname": hostname,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 1433,
            target_service="mssql",
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
        return 1731  # MSSQL 2012+
