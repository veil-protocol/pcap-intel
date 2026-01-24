#!/usr/bin/env python3
"""
AUTH ENGINE - RDP/NLA Credential Handler

Extracts RDP Network Level Authentication credentials.

RDP NLA uses CredSSP which wraps:
    - NTLM authentication (most common)
    - Kerberos authentication
    - TLS-based authentication

The NTLM exchange within RDP can be extracted for offline cracking.

Hashcat Mode: 5600 (NetNTLMv2) - same as NTLM
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class RDPAuthHandler(AuthProtocolHandler):
    """
    Handler for RDP Network Level Authentication.

    Extracts NTLM credentials from CredSSP/NLA exchange.
    """

    @property
    def protocol_name(self) -> str:
        return "rdp"

    @property
    def tshark_filter(self) -> str:
        # RDP uses NTLM within CredSSP, look for both
        return "rdp or credssp or (ntlmssp and tcp.port == 3389)"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # RDP fields
            "rdp.rt_cookie",
            "rdp.clientName",
            "rdp.clientBuild",
            "rdp.clientProductId",
            # CredSSP fields
            "credssp.negTokenInit",
            "credssp.negTokenTarg",
            "credssp.pubKeyAuth",
            # NTLMSSP fields (embedded in CredSSP)
            "ntlmssp.messagetype",
            "ntlmssp.ntlmv2_response.ntproofstr",
            "ntlmssp.ntlmclientchallenge",
            "ntlmssp.ntlmserverchallenge",
            "ntlmssp.auth.username",
            "ntlmssp.auth.domain",
            "ntlmssp.auth.hostname",
            "ntlmssp.auth.lmresponse",
            "ntlmssp.auth.ntresponse",
            "ntlmssp.challenge.target_name",
            "ntlmssp.version.major",
            "ntlmssp.version.minor",
            "ntlmssp.version.build",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify RDP/NLA message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        # Check for RDP-related traffic
        ntlm_type = self._get_first(fields.get("ntlmssp.messagetype", ""))
        client_name = self._get_first(fields.get("rdp.clientName", ""))
        credssp = self._get_first(fields.get("credssp.negTokenInit", "")) or \
                  self._get_first(fields.get("credssp.negTokenTarg", ""))

        if ntlm_type == "1":
            phase = AuthPhase.INITIATION  # NTLM Type 1 (Negotiate)
        elif ntlm_type == "2":
            phase = AuthPhase.CHALLENGE  # NTLM Type 2 (Challenge)
        elif ntlm_type == "3":
            phase = AuthPhase.RESPONSE  # NTLM Type 3 (Authenticate)
        elif client_name or credssp:
            phase = AuthPhase.INITIATION
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
        """Build RDP credential from NLA/NTLM exchange."""
        username = None
        domain = None
        hostname = None
        server_challenge = None
        nt_response = None
        nt_proof = None
        client_challenge = None
        client_name = None
        client_build = None
        target_name = None
        client_ip = None
        server_ip = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            # Extract NTLM components
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

            # RDP-specific fields
            c_name = self._get_first(msg.raw_data.get("rdp.clientName", ""))
            if c_name:
                client_name = c_name

            c_build = self._get_first(msg.raw_data.get("rdp.clientBuild", ""))
            if c_build:
                client_build = c_build

        if not username or not server_challenge:
            return None

        # Build hashcat format for NTLMv2 (mode 5600)
        # Format: username::domain:server_challenge:nt_proof:nt_response_without_proof
        hashcat_format = None
        if nt_proof and nt_response:
            # NTLMv2 response = NTProofStr (16 bytes) + blob
            # Remove the NTProofStr from the response to get the blob
            if len(nt_response) > 32:
                blob = nt_response[32:]  # Skip first 16 bytes (32 hex chars)
                hashcat_format = f"{username}::{domain or ''}:{server_challenge}:{nt_proof}:{blob}"

        metadata = ProtocolMetadata(
            target_hostname=hostname,
            target_realm=target_name,
            raw_fields={
                "client_name": client_name,
                "client_build": client_build,
                "client_challenge": client_challenge,
                "note": "RDP NLA (CredSSP) NTLM capture",
            }
        )

        return ExtractedCredential(
            protocol="rdp",
            username=username,
            domain=domain,
            credential_data={
                "server_challenge": server_challenge,
                "client_challenge": client_challenge,
                "nt_response": nt_response,
                "nt_proof": nt_proof,
                "hostname": hostname,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=5600,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=3389,
            target_service="rdp",
            timestamp=timestamp,
            metadata=metadata,
            auth_success=None,  # Can't determine from NTLM alone
        )

    def _get_first(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def get_hashcat_mode(self) -> Optional[int]:
        return 5600  # NetNTLMv2
