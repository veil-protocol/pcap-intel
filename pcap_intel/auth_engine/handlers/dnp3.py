#!/usr/bin/env python3
"""
AUTH ENGINE - DNP3 Credential Handler

Extracts DNP3 (Distributed Network Protocol) authentication.

DNP3 Security (IEEE 1815-2012):
    - Secure Authentication v5 (SA5)
    - HMAC-SHA-256 challenge/response
    - User numbers and key wrapping

DNP3 SA5 provides actual authentication unlike basic Modbus.

Hashcat Mode: N/A (HMAC-based, requires key material)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class DNP3AuthHandler(AuthProtocolHandler):
    """
    Handler for DNP3 Secure Authentication.

    Extracts SA5 authentication exchanges.
    """

    @property
    def protocol_name(self) -> str:
        return "dnp3"

    @property
    def tshark_filter(self) -> str:
        return "dnp3"

    @property
    def correlation_field(self) -> str:
        return "dnp3.al.seq"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # DNP3 Link Layer
            "dnp3.src",
            "dnp3.dst",
            "dnp3.ctl.dir",
            "dnp3.ctl.prm",
            # DNP3 Application Layer
            "dnp3.al.func",
            "dnp3.al.seq",
            "dnp3.al.iin",
            # Secure Authentication
            "dnp3.al.obj.sa.csq",
            "dnp3.al.obj.sa.usr",
            "dnp3.al.obj.sa.mac",
            "dnp3.al.obj.sa.chal",
            "dnp3.al.obj.sa.kw",
            "dnp3.al.obj.sa.ks",
            "dnp3.al.obj.sa.err",
            # Object headers
            "dnp3.al.obj.group",
            "dnp3.al.obj.var",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify DNP3 message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0) or \
                   int(self._get_first(fields.get("udp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0) or \
                   int(self._get_first(fields.get("udp.dstport", 0)) or 0)

        dnp3_src = self._get_first(fields.get("dnp3.src", ""))
        dnp3_dst = self._get_first(fields.get("dnp3.dst", ""))
        al_func = self._get_first(fields.get("dnp3.al.func", ""))
        al_seq = self._get_first(fields.get("dnp3.al.seq", ""))

        # SA5 fields
        sa_usr = self._get_first(fields.get("dnp3.al.obj.sa.usr", ""))
        sa_chal = self._get_first(fields.get("dnp3.al.obj.sa.chal", ""))
        sa_mac = self._get_first(fields.get("dnp3.al.obj.sa.mac", ""))
        sa_err = self._get_first(fields.get("dnp3.al.obj.sa.err", ""))

        if not dnp3_src and not al_func:
            return None

        correlation_key = f"{dnp3_src}:{dnp3_dst}:{al_seq}" if al_seq else f"{src_ip}:{dst_ip}"

        # Application function codes related to auth:
        # 32 (0x20) = Authentication Request
        # 33 (0x21) = Authentication Response
        # 131-134 = SA-specific

        if sa_chal and not sa_mac:
            phase = AuthPhase.CHALLENGE
        elif sa_mac:
            phase = AuthPhase.RESPONSE
        elif sa_err:
            phase = AuthPhase.RESULT
        elif al_func == "32":
            phase = AuthPhase.INITIATION
        elif al_func == "33":
            phase = AuthPhase.RESULT
        elif sa_usr:
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
        """Build DNP3 credential from SA5 exchange."""
        user_number = None
        challenge = None
        mac_value = None
        key_status = None
        challenge_seq = None
        error_code = None
        dnp3_src = None
        dnp3_dst = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            usr = self._get_first(msg.raw_data.get("dnp3.al.obj.sa.usr", ""))
            if usr:
                user_number = usr

            chal = self._get_first(msg.raw_data.get("dnp3.al.obj.sa.chal", ""))
            if chal:
                challenge = chal.replace(":", "")
                server_ip = msg.source_ip
                client_ip = msg.dest_ip

            mac = self._get_first(msg.raw_data.get("dnp3.al.obj.sa.mac", ""))
            if mac:
                mac_value = mac.replace(":", "")
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp

            csq = self._get_first(msg.raw_data.get("dnp3.al.obj.sa.csq", ""))
            if csq:
                challenge_seq = csq

            ks = self._get_first(msg.raw_data.get("dnp3.al.obj.sa.ks", ""))
            if ks:
                key_status = ks

            err = self._get_first(msg.raw_data.get("dnp3.al.obj.sa.err", ""))
            if err:
                error_code = err
                auth_success = False

            src = self._get_first(msg.raw_data.get("dnp3.src", ""))
            if src:
                dnp3_src = src

            dst = self._get_first(msg.raw_data.get("dnp3.dst", ""))
            if dst:
                dnp3_dst = dst

            # Check IIN bits for auth status
            iin = self._get_first(msg.raw_data.get("dnp3.al.iin", ""))
            if iin and not error_code:
                auth_success = True

        if not user_number and not challenge:
            return None

        username = f"user:{user_number}" if user_number else "dnp3_client"

        metadata = ProtocolMetadata(
            raw_fields={
                "dnp3_src": dnp3_src,
                "dnp3_dst": dnp3_dst,
                "challenge_seq": challenge_seq,
                "key_status": key_status,
                "error_code": error_code,
                "note": "DNP3 SA5 uses HMAC-SHA-256",
            }
        )

        return ExtractedCredential(
            protocol="dnp3",
            username=username,
            domain=server_ip,
            credential_data={
                "user_number": user_number,
                "challenge": challenge,
                "mac_value": mac_value,
                "challenge_seq": challenge_seq,
                "key_status": key_status,
            },
            hashcat_format=None,  # HMAC-based, needs key material
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=20000,
            target_service="dnp3",
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
        return None  # HMAC-based
