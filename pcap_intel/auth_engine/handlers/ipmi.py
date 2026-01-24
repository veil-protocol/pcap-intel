#!/usr/bin/env python3
"""
AUTH ENGINE - IPMI Credential Handler

Extracts IPMI 2.0 RAKP authentication hashes.

IPMI RAKP (Remote Authenticated Key-Exchange Protocol):
    - Used for remote BMC management
    - RAKP Message 2 contains salted HMAC that can be cracked
    - Common vulnerability in datacenter environments

Hashcat Mode: 7300 (IPMI2 RAKP HMAC-SHA1)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class IPMIAuthHandler(AuthProtocolHandler):
    """
    Handler for IPMI 2.0 RAKP authentication.

    Extracts HMAC-SHA1 hash for offline cracking.
    """

    @property
    def protocol_name(self) -> str:
        return "ipmi"

    @property
    def tshark_filter(self) -> str:
        return "ipmi.session.authtype == 0x06"  # RMCP+ / IPMI 2.0

    @property
    def correlation_field(self) -> str:
        return "ipmi.session.id"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "ipmi.session.id",
            "ipmi.session.authtype",
            "ipmi.session.payloadtype",
            "rmcp.class",
            # RAKP fields
            "ipmi.rakp.message",
            "ipmi.rakp.console.sessionid",
            "ipmi.rakp.bmc.sessionid",
            "ipmi.rakp.console.random",
            "ipmi.rakp.bmc.random",
            "ipmi.rakp.bmc.guid",
            "ipmi.rakp.auth.code",
            "ipmi.rakp.username",
            "ipmi.rakp.role",
            "ipmi.rakp.status",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify IPMI RAKP message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("udp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("udp.dstport", 0)) or 0)

        session_id = self._get_first(fields.get("ipmi.session.id", ""))
        rakp_msg = self._get_first(fields.get("ipmi.rakp.message", ""))

        if not session_id and not rakp_msg:
            return None

        correlation_key = session_id or f"{src_ip}:{dst_ip}"

        # RAKP message types
        if rakp_msg == "1":
            phase = AuthPhase.INITIATION
        elif rakp_msg == "2":
            phase = AuthPhase.CHALLENGE  # Contains the crackable hash
        elif rakp_msg == "3":
            phase = AuthPhase.RESPONSE
        elif rakp_msg == "4":
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
        """Build IPMI credential from RAKP exchange."""
        username = None
        console_session_id = None
        bmc_session_id = None
        console_random = None
        bmc_random = None
        bmc_guid = None
        auth_code = None  # The HMAC we want
        role = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            rakp_msg = self._get_first(msg.raw_data.get("ipmi.rakp.message", ""))

            user = self._get_first(msg.raw_data.get("ipmi.rakp.username", ""))
            if user:
                username = user

            c_sid = self._get_first(msg.raw_data.get("ipmi.rakp.console.sessionid", ""))
            if c_sid:
                console_session_id = c_sid.replace(":", "")

            b_sid = self._get_first(msg.raw_data.get("ipmi.rakp.bmc.sessionid", ""))
            if b_sid:
                bmc_session_id = b_sid.replace(":", "")

            c_rand = self._get_first(msg.raw_data.get("ipmi.rakp.console.random", ""))
            if c_rand:
                console_random = c_rand.replace(":", "")

            b_rand = self._get_first(msg.raw_data.get("ipmi.rakp.bmc.random", ""))
            if b_rand:
                bmc_random = b_rand.replace(":", "")

            guid = self._get_first(msg.raw_data.get("ipmi.rakp.bmc.guid", ""))
            if guid:
                bmc_guid = guid.replace(":", "")

            code = self._get_first(msg.raw_data.get("ipmi.rakp.auth.code", ""))
            if code and rakp_msg == "2":
                auth_code = code.replace(":", "")
                server_ip = msg.source_ip
                client_ip = msg.dest_ip
                timestamp = msg.timestamp

            r = self._get_first(msg.raw_data.get("ipmi.rakp.role", ""))
            if r:
                role = r

            status = self._get_first(msg.raw_data.get("ipmi.rakp.status", ""))
            if status == "0":
                auth_success = True
            elif status:
                auth_success = False

        if not auth_code:
            return None

        # Hashcat format for IPMI2 RAKP (mode 7300):
        # console_session_id:bmc_session_id:console_random:bmc_random:bmc_guid:auth_code:username
        # All values hex-encoded
        hashcat_parts = [
            console_session_id or "",
            bmc_session_id or "",
            console_random or "",
            bmc_random or "",
            bmc_guid or "",
            auth_code,
        ]
        hashcat_format = ":".join(hashcat_parts)
        if username:
            hashcat_format += f":{username.encode().hex()}"

        metadata = ProtocolMetadata(
            raw_fields={
                "role": role,
                "bmc_guid": bmc_guid,
                "note": "IPMI RAKP HMAC-SHA1",
            }
        )

        return ExtractedCredential(
            protocol="ipmi",
            username=username or "admin",
            domain=server_ip,
            credential_data={
                "auth_code": auth_code,
                "console_session_id": console_session_id,
                "bmc_session_id": bmc_session_id,
                "console_random": console_random,
                "bmc_random": bmc_random,
                "bmc_guid": bmc_guid,
                "role": role,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=7300,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=623,
            target_service="ipmi",
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
        return 7300
