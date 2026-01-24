#!/usr/bin/env python3
"""
AUTH ENGINE - LLMNR/NBT-NS/mDNS Credential Handler

Extracts credentials from name resolution poisoning attacks.

These protocols are used for local name resolution:
    - LLMNR (Link-Local Multicast Name Resolution) - UDP 5355
    - NBT-NS (NetBIOS Name Service) - UDP 137
    - mDNS (Multicast DNS) - UDP 5353

When poisoned (Responder, mitm6), victims send NTLM auth.
This handler captures those NTLM exchanges.

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


class LLMNRAuthHandler(AuthProtocolHandler):
    """
    Handler for LLMNR/NBT-NS/mDNS name resolution.

    Captures NTLM credentials from poisoning attacks.
    """

    @property
    def protocol_name(self) -> str:
        return "llmnr"

    @property
    def tshark_filter(self) -> str:
        # LLMNR, NBT-NS, mDNS queries and NTLM responses
        return "llmnr or nbns or mdns or (ntlmssp and (udp.port == 5355 or udp.port == 137 or udp.port == 5353))"

    @property
    def correlation_field(self) -> str:
        return "ip.src"  # Correlate by victim IP

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # LLMNR fields
            "llmnr.query.name",
            "llmnr.query.type",
            "llmnr.response",
            "llmnr.answer.addr",
            # NBT-NS fields
            "nbns.name",
            "nbns.type",
            "nbns.addr",
            "nbns.flags.response",
            # mDNS fields
            "mdns.query.name",
            "mdns.resp.name",
            "mdns.a",
            # NTLM fields (from subsequent auth)
            "ntlmssp.messagetype",
            "ntlmssp.ntlmv2_response.ntproofstr",
            "ntlmssp.ntlmclientchallenge",
            "ntlmssp.ntlmserverchallenge",
            "ntlmssp.auth.username",
            "ntlmssp.auth.domain",
            "ntlmssp.auth.hostname",
            "ntlmssp.auth.ntresponse",
            "ntlmssp.challenge.target_name",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify LLMNR/NBT-NS/mDNS message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("udp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("udp.dstport", 0)) or 0)

        # Determine message type
        llmnr_query = self._get_first(fields.get("llmnr.query.name", ""))
        nbns_name = self._get_first(fields.get("nbns.name", ""))
        mdns_query = self._get_first(fields.get("mdns.query.name", ""))
        ntlm_type = self._get_first(fields.get("ntlmssp.messagetype", ""))

        correlation_key = src_ip

        if llmnr_query:
            phase = AuthPhase.INITIATION
            correlation_key = f"{src_ip}:llmnr:{llmnr_query}"
        elif nbns_name:
            phase = AuthPhase.INITIATION
            correlation_key = f"{src_ip}:nbns:{nbns_name}"
        elif mdns_query:
            phase = AuthPhase.INITIATION
            correlation_key = f"{src_ip}:mdns:{mdns_query}"
        elif ntlm_type == "1":
            phase = AuthPhase.INITIATION
        elif ntlm_type == "2":
            phase = AuthPhase.CHALLENGE
        elif ntlm_type == "3":
            phase = AuthPhase.RESPONSE
        else:
            # Check for responses
            llmnr_resp = self._get_first(fields.get("llmnr.response", ""))
            nbns_resp = self._get_first(fields.get("nbns.flags.response", ""))
            if llmnr_resp or nbns_resp:
                phase = AuthPhase.CHALLENGE
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
        """Build LLMNR credential from captured NTLM exchange."""
        username = None
        domain = None
        hostname = None
        server_challenge = None
        nt_response = None
        nt_proof = None
        client_challenge = None
        queried_name = None
        resolution_type = None
        poisoned_ip = None
        victim_ip = None
        attacker_ip = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            # Capture name queries
            llmnr_q = self._get_first(msg.raw_data.get("llmnr.query.name", ""))
            if llmnr_q:
                queried_name = llmnr_q
                resolution_type = "llmnr"
                victim_ip = msg.source_ip

            nbns_n = self._get_first(msg.raw_data.get("nbns.name", ""))
            if nbns_n:
                queried_name = nbns_n
                resolution_type = "nbns"
                victim_ip = msg.source_ip

            mdns_q = self._get_first(msg.raw_data.get("mdns.query.name", ""))
            if mdns_q:
                queried_name = mdns_q
                resolution_type = "mdns"
                victim_ip = msg.source_ip

            # Capture poisoned responses
            llmnr_ans = self._get_first(msg.raw_data.get("llmnr.answer.addr", ""))
            if llmnr_ans:
                poisoned_ip = llmnr_ans
                attacker_ip = msg.source_ip

            nbns_addr = self._get_first(msg.raw_data.get("nbns.addr", ""))
            if nbns_addr:
                poisoned_ip = nbns_addr
                attacker_ip = msg.source_ip

            # Capture NTLM authentication
            user = self._get_first(msg.raw_data.get("ntlmssp.auth.username", ""))
            if user:
                username = user
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

        if not username or not server_challenge:
            return None

        # Build hashcat format for NTLMv2 (mode 5600)
        hashcat_format = None
        if nt_proof and nt_response and len(nt_response) > 32:
            blob = nt_response[32:]
            hashcat_format = f"{username}::{domain or ''}:{server_challenge}:{nt_proof}:{blob}"

        metadata = ProtocolMetadata(
            target_hostname=hostname,
            raw_fields={
                "queried_name": queried_name,
                "resolution_type": resolution_type,
                "poisoned_ip": poisoned_ip,
                "attacker_ip": attacker_ip,
                "note": f"NTLM captured via {resolution_type} poisoning",
            }
        )

        return ExtractedCredential(
            protocol="llmnr",
            username=username,
            domain=domain,
            credential_data={
                "server_challenge": server_challenge,
                "client_challenge": client_challenge,
                "nt_response": nt_response,
                "nt_proof": nt_proof,
                "queried_name": queried_name,
                "resolution_type": resolution_type,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=5600,
            source_ip=victim_ip or "",
            source_port=0,
            target_ip=attacker_ip or "",
            target_port=0,
            target_service=resolution_type or "llmnr",
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
