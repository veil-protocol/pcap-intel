#!/usr/bin/env python3
"""
AUTH ENGINE - DCE/RPC Credential Handler

Extracts DCE/RPC (MS-RPC) authentication credentials.

DCE/RPC Auth:
    - NTLMSSP: Most common in Windows environments
    - Kerberos: For AD-joined systems
    - SPNEGO: Negotiate between NTLM/Kerberos

Used by many Windows services: SMB, DCOM, WMI, etc.

Hashcat Mode: 5600 (NetNTLMv2)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class DCERPCAuthHandler(AuthProtocolHandler):
    """
    Handler for DCE/RPC authentication.

    Extracts NTLM credentials from RPC auth.
    """

    @property
    def protocol_name(self) -> str:
        return "dcerpc"

    @property
    def tshark_filter(self) -> str:
        return "dcerpc.auth_type or (dcerpc and ntlmssp)"

    @property
    def correlation_field(self) -> str:
        return "dcerpc.cn_call_id"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # DCE/RPC fields
            "dcerpc.cn_call_id",
            "dcerpc.pkt_type",
            "dcerpc.cn_ctx_id",
            "dcerpc.auth_type",
            "dcerpc.auth_level",
            "dcerpc.cn_ack_result",
            "dcerpc.if_uuid",
            "dcerpc.ver",
            # NTLMSSP fields (embedded)
            "ntlmssp.messagetype",
            "ntlmssp.ntlmv2_response.ntproofstr",
            "ntlmssp.ntlmclientchallenge",
            "ntlmssp.ntlmserverchallenge",
            "ntlmssp.auth.username",
            "ntlmssp.auth.domain",
            "ntlmssp.auth.hostname",
            "ntlmssp.auth.ntresponse",
            "ntlmssp.challenge.target_name",
            "ntlmssp.version.major",
            "ntlmssp.version.minor",
            "ntlmssp.version.build",
            # SPNEGO
            "spnego.negResult",
            "spnego.mechType",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify DCE/RPC message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)

        call_id = self._get_first(fields.get("dcerpc.cn_call_id", ""))
        pkt_type = self._get_first(fields.get("dcerpc.pkt_type", ""))
        auth_type = self._get_first(fields.get("dcerpc.auth_type", ""))
        ntlm_type = self._get_first(fields.get("ntlmssp.messagetype", ""))

        if not call_id and not ntlm_type:
            return None

        correlation_key = call_id or f"{src_ip}:{dst_ip}"

        # DCE/RPC packet types:
        # 0=REQUEST, 2=RESPONSE, 11=BIND, 12=BIND_ACK, 13=BIND_NAK
        # 14=ALTER_CONTEXT, 15=ALTER_CONTEXT_RESP, 16=AUTH3

        if ntlm_type == "1":
            phase = AuthPhase.INITIATION  # NTLM Type 1
        elif ntlm_type == "2":
            phase = AuthPhase.CHALLENGE  # NTLM Type 2
        elif ntlm_type == "3":
            phase = AuthPhase.RESPONSE  # NTLM Type 3
        elif pkt_type in ["11", "14"]:  # BIND, ALTER_CONTEXT
            phase = AuthPhase.INITIATION
        elif pkt_type in ["12", "15"]:  # BIND_ACK, ALTER_CONTEXT_RESP
            phase = AuthPhase.CHALLENGE
        elif pkt_type == "16":  # AUTH3
            phase = AuthPhase.RESPONSE
        elif auth_type:
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
        """Build DCE/RPC credential from NTLM exchange."""
        username = None
        domain = None
        hostname = None
        server_challenge = None
        nt_response = None
        nt_proof = None
        client_challenge = None
        target_name = None
        auth_type = None
        interface_uuid = None
        os_version = None
        client_ip = None
        server_ip = None
        timestamp = 0.0

        auth_types = {
            "9": "SPNEGO",
            "10": "NTLMSSP",
            "16": "Kerberos",
        }

        for msg in sorted(messages, key=lambda m: m.timestamp):
            atype = self._get_first(msg.raw_data.get("dcerpc.auth_type", ""))
            if atype:
                auth_type = auth_types.get(atype, f"Type_{atype}")

            uuid = self._get_first(msg.raw_data.get("dcerpc.if_uuid", ""))
            if uuid:
                interface_uuid = uuid

            # NTLM components
            user = self._get_first(msg.raw_data.get("ntlmssp.auth.username", ""))
            if user:
                username = user
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp

            dom = self._get_first(msg.raw_data.get("ntlmssp.auth.domain", ""))
            if dom:
                domain = dom

            host = self._get_first(msg.raw_data.get("ntlmssp.auth.hostname", ""))
            if host:
                hostname = host

            s_chal = self._get_first(msg.raw_data.get("ntlmssp.ntlmserverchallenge", ""))
            if s_chal:
                server_challenge = s_chal.replace(":", "")

            c_chal = self._get_first(msg.raw_data.get("ntlmssp.ntlmclientchallenge", ""))
            if c_chal:
                client_challenge = c_chal.replace(":", "")

            nt_resp = self._get_first(msg.raw_data.get("ntlmssp.auth.ntresponse", ""))
            if nt_resp:
                nt_response = nt_resp.replace(":", "")

            proof = self._get_first(msg.raw_data.get("ntlmssp.ntlmv2_response.ntproofstr", ""))
            if proof:
                nt_proof = proof.replace(":", "")

            target = self._get_first(msg.raw_data.get("ntlmssp.challenge.target_name", ""))
            if target:
                target_name = target

            # OS version
            major = self._get_first(msg.raw_data.get("ntlmssp.version.major", ""))
            minor = self._get_first(msg.raw_data.get("ntlmssp.version.minor", ""))
            build = self._get_first(msg.raw_data.get("ntlmssp.version.build", ""))
            if major and minor:
                os_version = f"{major}.{minor}.{build}"

        if not username or not server_challenge:
            return None

        # Build hashcat format for NTLMv2 (mode 5600)
        hashcat_format = None
        if nt_proof and nt_response and len(nt_response) > 32:
            blob = nt_response[32:]
            hashcat_format = f"{username}::{domain or ''}:{server_challenge}:{nt_proof}:{blob}"

        metadata = ProtocolMetadata(
            os_info=os_version,
            target_hostname=hostname,
            target_realm=target_name,
            raw_fields={
                "auth_type": auth_type,
                "interface_uuid": interface_uuid,
                "client_challenge": client_challenge,
            }
        )

        return ExtractedCredential(
            protocol="dcerpc",
            username=username,
            domain=domain,
            credential_data={
                "server_challenge": server_challenge,
                "client_challenge": client_challenge,
                "nt_response": nt_response,
                "nt_proof": nt_proof,
                "hostname": hostname,
                "auth_type": auth_type,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=5600,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=135,  # Default RPC endpoint mapper
            target_service="dcerpc",
            timestamp=timestamp,
            metadata=metadata,
            auth_success=None,
        )

    def _get_first(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def get_hashcat_mode(self) -> Optional[int]:
        return 5600  # NetNTLMv2
