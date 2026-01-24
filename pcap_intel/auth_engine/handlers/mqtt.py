#!/usr/bin/env python3
"""
AUTH ENGINE - MQTT Credential Handler

Extracts MQTT authentication credentials.

MQTT Auth (v3.1/v3.1.1/v5):
    - Username/password in CONNECT packet
    - Sent in plaintext unless TLS used
    - Common in IoT deployments

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


class MQTTAuthHandler(AuthProtocolHandler):
    """
    Handler for MQTT authentication.

    Extracts username/password from CONNECT packets.
    Credentials are plaintext unless TLS is used.
    """

    @property
    def protocol_name(self) -> str:
        return "mqtt"

    @property
    def tshark_filter(self) -> str:
        return "mqtt.conflag.uname == 1 or mqtt.conflag.passwd == 1"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "mqtt.msgtype",
            "mqtt.username",
            "mqtt.passwd",
            "mqtt.clientid",
            "mqtt.proto_name",
            "mqtt.proto_ver",
            "mqtt.conflag.uname",
            "mqtt.conflag.passwd",
            "mqtt.conack.val",
            "mqtt.willmsg",
            "mqtt.willtopic",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify MQTT message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        msg_type = self._get_first(fields.get("mqtt.msgtype", ""))
        username = self._get_first(fields.get("mqtt.username", ""))
        password = self._get_first(fields.get("mqtt.passwd", ""))
        conack = self._get_first(fields.get("mqtt.conack.val", ""))

        # MQTT message types: 1=CONNECT, 2=CONNACK
        if msg_type == "1" or username or password:
            phase = AuthPhase.RESPONSE
        elif msg_type == "2" or conack:
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
        """Build MQTT credential from CONNECT packet."""
        username = None
        password = None
        client_id = None
        proto_name = None
        proto_ver = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            user = self._get_first(msg.raw_data.get("mqtt.username", ""))
            passwd = self._get_first(msg.raw_data.get("mqtt.passwd", ""))
            cid = self._get_first(msg.raw_data.get("mqtt.clientid", ""))
            proto = self._get_first(msg.raw_data.get("mqtt.proto_name", ""))
            ver = self._get_first(msg.raw_data.get("mqtt.proto_ver", ""))
            conack = self._get_first(msg.raw_data.get("mqtt.conack.val", ""))

            if user:
                username = user
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp
            if passwd:
                password = passwd
            if cid:
                client_id = cid
            if proto:
                proto_name = proto
            if ver:
                proto_ver = ver
            if conack == "0":
                auth_success = True
            elif conack:
                auth_success = False

        if not username:
            return None

        metadata = ProtocolMetadata(
            client_version=proto_ver,
            raw_fields={
                "client_id": client_id,
                "proto_name": proto_name,
                "note": "MQTT credentials in plaintext",
            }
        )

        return ExtractedCredential(
            protocol="mqtt",
            username=username,
            domain=server_ip,
            credential_data={
                "password": password,  # PLAINTEXT
                "client_id": client_id,
            },
            hashcat_format=None,
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 1883,
            target_service="mqtt",
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
