#!/usr/bin/env python3
"""
AUTH ENGINE - Diameter Credential Handler

Extracts Diameter protocol authentication credentials.

Diameter (RFC 6733):
    - Successor to RADIUS for AAA
    - Used in 3GPP/LTE networks
    - Supports EAP, CHAP, and other auth methods
    - Application IDs: 0=Base, 1=NASREQ, 4=Credit-Control, 16777216+=3GPP

Hashcat Mode: Depends on encapsulated auth method
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class DiameterAuthHandler(AuthProtocolHandler):
    """
    Handler for Diameter protocol authentication.

    Extracts credentials from AAA exchanges.
    """

    @property
    def protocol_name(self) -> str:
        return "diameter"

    @property
    def tshark_filter(self) -> str:
        return "diameter"

    @property
    def correlation_field(self) -> str:
        return "diameter.Session-Id"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "diameter.cmd.code",
            "diameter.flags.request",
            "diameter.applicationId",
            "diameter.Session-Id",
            "diameter.Origin-Host",
            "diameter.Origin-Realm",
            "diameter.Destination-Host",
            "diameter.Destination-Realm",
            "diameter.User-Name",
            "diameter.Auth-Application-Id",
            "diameter.Result-Code",
            # Authentication AVPs
            "diameter.EAP-Payload",
            "diameter.CHAP-Auth",
            "diameter.CHAP-Challenge",
            "diameter.SIP-Auth-Data-Item",
            "diameter.SIP-Authorization",
            "diameter.SIP-Authenticate",
            # 3GPP specific
            "diameter.3GPP-IMSI",
            "diameter.3GPP-Charging-Id",
            "diameter.3GPP-User-Location-Info",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify Diameter message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)

        session_id = self._get_first(fields.get("diameter.Session-Id", ""))
        cmd_code = self._get_first(fields.get("diameter.cmd.code", ""))
        is_request = self._get_first(fields.get("diameter.flags.request", ""))

        if not session_id and not cmd_code:
            return None

        correlation_key = session_id or f"{src_ip}:{dst_ip}:{cmd_code}"

        # Relevant command codes:
        # 265 = AA-Request/Answer (Authentication-Authorization)
        # 258 = Re-Auth-Request/Answer
        # 274 = Abort-Session-Request/Answer
        # 275 = Session-Termination-Request/Answer
        # 268 = Diameter-EAP-Request/Answer
        # 303 = User-Authorization-Request/Answer (SIP)
        # 300 = Multimedia-Auth-Request/Answer (SIP)

        auth_commands = ["265", "258", "268", "300", "303", "272"]  # Include Credit-Control
        if cmd_code not in auth_commands:
            return None

        if is_request == "1":
            phase = AuthPhase.RESPONSE  # Client sending auth
        else:
            phase = AuthPhase.RESULT  # Server response

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
        """Build Diameter credential from exchange."""
        username = None
        session_id = None
        origin_host = None
        origin_realm = None
        dest_host = None
        dest_realm = None
        eap_payload = None
        chap_auth = None
        chap_challenge = None
        sip_auth = None
        imsi = None
        result_code = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            is_request = self._get_first(msg.raw_data.get("diameter.flags.request", ""))

            user = self._get_first(msg.raw_data.get("diameter.User-Name", ""))
            if user:
                username = user
                if is_request == "1":
                    client_ip = msg.source_ip
                    server_ip = msg.dest_ip
                    timestamp = msg.timestamp

            sid = self._get_first(msg.raw_data.get("diameter.Session-Id", ""))
            if sid:
                session_id = sid

            oh = self._get_first(msg.raw_data.get("diameter.Origin-Host", ""))
            if oh:
                origin_host = oh

            oreal = self._get_first(msg.raw_data.get("diameter.Origin-Realm", ""))
            if oreal:
                origin_realm = oreal

            dh = self._get_first(msg.raw_data.get("diameter.Destination-Host", ""))
            if dh:
                dest_host = dh

            dr = self._get_first(msg.raw_data.get("diameter.Destination-Realm", ""))
            if dr:
                dest_realm = dr

            eap = self._get_first(msg.raw_data.get("diameter.EAP-Payload", ""))
            if eap:
                eap_payload = eap.replace(":", "")

            chap = self._get_first(msg.raw_data.get("diameter.CHAP-Auth", ""))
            if chap:
                chap_auth = chap.replace(":", "")

            chap_chal = self._get_first(msg.raw_data.get("diameter.CHAP-Challenge", ""))
            if chap_chal:
                chap_challenge = chap_chal.replace(":", "")

            sip = self._get_first(msg.raw_data.get("diameter.SIP-Authorization", ""))
            if sip:
                sip_auth = sip

            imsi_val = self._get_first(msg.raw_data.get("diameter.3GPP-IMSI", ""))
            if imsi_val:
                imsi = imsi_val

            rc = self._get_first(msg.raw_data.get("diameter.Result-Code", ""))
            if rc:
                result_code = rc
                if rc == "2001":  # DIAMETER_SUCCESS
                    auth_success = True
                elif rc.startswith("3") or rc.startswith("4") or rc.startswith("5"):
                    auth_success = False

        if not username and not imsi:
            return None

        metadata = ProtocolMetadata(
            target_realm=origin_realm,
            raw_fields={
                "session_id": session_id,
                "origin_host": origin_host,
                "origin_realm": origin_realm,
                "dest_host": dest_host,
                "dest_realm": dest_realm,
                "result_code": result_code,
                "imsi": imsi,
            }
        )

        return ExtractedCredential(
            protocol="diameter",
            username=username or imsi or "unknown",
            domain=origin_realm,
            credential_data={
                "session_id": session_id,
                "eap_payload": eap_payload,
                "chap_auth": chap_auth,
                "chap_challenge": chap_challenge,
                "sip_auth": sip_auth,
                "imsi": imsi,
            },
            hashcat_format=None,  # Depends on encapsulated auth
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=3868,
            target_service="diameter",
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
        return None  # Varies by encapsulated method
