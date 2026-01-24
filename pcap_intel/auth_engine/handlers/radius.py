#!/usr/bin/env python3
"""
AUTH ENGINE - RADIUS Credential Handler

Extracts RADIUS authentication credentials.

RADIUS Auth (RFC 2865):
    - User-Password: XOR encrypted with shared secret
    - CHAP-Password: CHAP challenge/response
    - EAP-Message: Encapsulated EAP
    - MS-CHAP/MS-CHAPv2: Microsoft extensions

Hashcat Modes:
    - 16000: RADIUS (User-Password with known secret)
    - 16100: TACACS+ (similar format)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class RADIUSAuthHandler(AuthProtocolHandler):
    """
    Handler for RADIUS authentication.

    Extracts User-Password, CHAP, and MS-CHAP credentials.
    """

    @property
    def protocol_name(self) -> str:
        return "radius"

    @property
    def tshark_filter(self) -> str:
        return "radius"

    @property
    def correlation_field(self) -> str:
        return "radius.id"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "radius.code",
            "radius.id",
            "radius.authenticator",
            "radius.User_Name",
            "radius.User_Password",
            "radius.CHAP_Password",
            "radius.CHAP_Challenge",
            "radius.NAS_IP_Address",
            "radius.NAS_Port",
            "radius.Service_Type",
            "radius.Framed_Protocol",
            "radius.Called_Station_Id",
            "radius.Calling_Station_Id",
            # MS-CHAP attributes
            "radius.MS_CHAP_Challenge",
            "radius.MS_CHAP_Response",
            "radius.MS_CHAP2_Response",
            # EAP
            "radius.EAP_Message",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify RADIUS message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("udp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("udp.dstport", 0)) or 0)

        radius_id = self._get_first(fields.get("radius.id", ""))
        radius_code = self._get_first(fields.get("radius.code", ""))

        if not radius_id:
            return None

        # RADIUS codes: 1=Access-Request, 2=Access-Accept, 3=Access-Reject, 11=Access-Challenge
        if radius_code == "1":
            phase = AuthPhase.RESPONSE  # Client sending credentials
        elif radius_code == "2":
            phase = AuthPhase.RESULT  # Accept
        elif radius_code == "3":
            phase = AuthPhase.RESULT  # Reject
        elif radius_code == "11":
            phase = AuthPhase.CHALLENGE
        else:
            return None

        return AuthMessage(
            phase=phase,
            correlation_key=radius_id,
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
        """Build RADIUS credential from exchange."""
        username = None
        user_password = None
        chap_password = None
        chap_challenge = None
        mschap_challenge = None
        mschap_response = None
        mschap2_response = None
        authenticator = None
        nas_ip = None
        called_station = None
        calling_station = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            code = self._get_first(msg.raw_data.get("radius.code", ""))

            user = self._get_first(msg.raw_data.get("radius.User_Name", ""))
            if user:
                username = user
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp

            auth = self._get_first(msg.raw_data.get("radius.authenticator", ""))
            if auth:
                authenticator = auth.replace(":", "")

            pwd = self._get_first(msg.raw_data.get("radius.User_Password", ""))
            if pwd:
                user_password = pwd.replace(":", "")

            chap_pwd = self._get_first(msg.raw_data.get("radius.CHAP_Password", ""))
            if chap_pwd:
                chap_password = chap_pwd.replace(":", "")

            chap_chal = self._get_first(msg.raw_data.get("radius.CHAP_Challenge", ""))
            if chap_chal:
                chap_challenge = chap_chal.replace(":", "")

            ms_chal = self._get_first(msg.raw_data.get("radius.MS_CHAP_Challenge", ""))
            if ms_chal:
                mschap_challenge = ms_chal.replace(":", "")

            ms_resp = self._get_first(msg.raw_data.get("radius.MS_CHAP_Response", ""))
            if ms_resp:
                mschap_response = ms_resp.replace(":", "")

            ms2_resp = self._get_first(msg.raw_data.get("radius.MS_CHAP2_Response", ""))
            if ms2_resp:
                mschap2_response = ms2_resp.replace(":", "")

            nas = self._get_first(msg.raw_data.get("radius.NAS_IP_Address", ""))
            if nas:
                nas_ip = nas

            called = self._get_first(msg.raw_data.get("radius.Called_Station_Id", ""))
            if called:
                called_station = called

            calling = self._get_first(msg.raw_data.get("radius.Calling_Station_Id", ""))
            if calling:
                calling_station = calling

            if code == "2":
                auth_success = True
            elif code == "3":
                auth_success = False

        if not username:
            return None

        # Determine credential type and hashcat format
        hashcat_mode = None
        hashcat_format = None
        cred_type = "unknown"

        if mschap2_response and mschap_challenge:
            # MS-CHAPv2 format for hashcat mode 5500
            # Format: user::::mschap2_response:mschap_challenge
            cred_type = "mschapv2"
            hashcat_mode = 5500
            hashcat_format = f"{username}::::{mschap2_response}:{mschap_challenge}"
        elif mschap_response and mschap_challenge:
            # MS-CHAP format
            cred_type = "mschap"
            hashcat_mode = 5500
            hashcat_format = f"{username}::::{mschap_response}:{mschap_challenge}"
        elif chap_password and chap_challenge:
            cred_type = "chap"
            # CHAP not directly crackable without more context
        elif user_password and authenticator:
            # RADIUS User-Password (XOR with MD5(secret + authenticator))
            cred_type = "user_password"
            hashcat_mode = 16000
            hashcat_format = f"{authenticator}:{user_password}"

        metadata = ProtocolMetadata(
            raw_fields={
                "nas_ip": nas_ip,
                "called_station": called_station,
                "calling_station": calling_station,
                "credential_type": cred_type,
            }
        )

        return ExtractedCredential(
            protocol="radius",
            username=username,
            domain=server_ip,
            credential_data={
                "user_password": user_password,
                "chap_password": chap_password,
                "chap_challenge": chap_challenge,
                "mschap_challenge": mschap_challenge,
                "mschap_response": mschap_response,
                "mschap2_response": mschap2_response,
                "authenticator": authenticator,
                "credential_type": cred_type,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=1812,
            target_service="radius",
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
        return 16000
