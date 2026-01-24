#!/usr/bin/env python3
"""
AUTH ENGINE - WPA/WPA2 Credential Handler

Extracts WPA/WPA2 4-way handshake for PSK cracking.

WPA/WPA2 Handshake:
    - Message 1: AP → Client (ANonce)
    - Message 2: Client → AP (SNonce + MIC)
    - Message 3: AP → Client (GTK + MIC)
    - Message 4: Client → AP (ACK)

For PSK cracking, need: ANonce, SNonce, AP MAC, Client MAC, MIC

Hashcat Modes:
    - 2500: WPA/WPA2 (PBKDF2-HMAC-SHA1)
    - 22000: WPA-PBKDF2-PMKID+EAPOL (modern format)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class WPAAuthHandler(AuthProtocolHandler):
    """
    Handler for WPA/WPA2 4-way handshake.

    Extracts handshake components for offline PSK cracking.
    """

    @property
    def protocol_name(self) -> str:
        return "wpa"

    @property
    def tshark_filter(self) -> str:
        return "eapol"

    @property
    def correlation_field(self) -> str:
        # Correlate by AP MAC + Client MAC pair
        return "wlan.bssid"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # WLAN fields
            "wlan.bssid",
            "wlan.sa",
            "wlan.da",
            "wlan.ta",
            "wlan.ra",
            "wlan_mgt.ssid",
            # EAPOL fields
            "eapol.type",
            "eapol.keydes.type",
            "eapol.keydes.key_info",
            "eapol.keydes.key_len",
            "eapol.keydes.replay_counter",
            "eapol.keydes.nonce",
            "eapol.keydes.key_iv",
            "eapol.keydes.rsc",
            "eapol.keydes.mic",
            "eapol.keydes.data_len",
            "eapol.keydes.data",
            # Key info bits
            "eapol.keydes.key_info.key_type",
            "eapol.keydes.key_info.key_index",
            "eapol.keydes.key_info.install",
            "eapol.keydes.key_info.key_ack",
            "eapol.keydes.key_info.key_mic",
            "eapol.keydes.key_info.secure",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify WPA handshake message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_mac = self._get_first(fields.get("wlan.sa", "")) or self._get_first(fields.get("wlan.ta", ""))
        dst_mac = self._get_first(fields.get("wlan.da", "")) or self._get_first(fields.get("wlan.ra", ""))
        bssid = self._get_first(fields.get("wlan.bssid", ""))

        if not bssid:
            return None

        # Check for EAPOL Key
        eapol_type = self._get_first(fields.get("eapol.type", ""))
        if eapol_type != "3":  # 3 = EAPOL-Key
            return None

        # Determine message number from key info flags
        key_ack = self._get_first(fields.get("eapol.keydes.key_info.key_ack", ""))
        key_mic = self._get_first(fields.get("eapol.keydes.key_info.key_mic", ""))
        install = self._get_first(fields.get("eapol.keydes.key_info.install", ""))
        secure = self._get_first(fields.get("eapol.keydes.key_info.secure", ""))

        # Message 1: ACK=1, MIC=0, Install=0, Secure=0
        # Message 2: ACK=0, MIC=1, Install=0, Secure=0
        # Message 3: ACK=1, MIC=1, Install=1, Secure=1
        # Message 4: ACK=0, MIC=1, Install=0, Secure=1

        if key_ack == "1" and key_mic != "1":
            phase = AuthPhase.CHALLENGE  # Message 1 (ANonce)
        elif key_ack != "1" and key_mic == "1" and secure != "1":
            phase = AuthPhase.RESPONSE  # Message 2 (SNonce + MIC)
        elif key_ack == "1" and key_mic == "1" and install == "1":
            phase = AuthPhase.RESULT  # Message 3
        elif key_ack != "1" and key_mic == "1" and secure == "1":
            phase = AuthPhase.RESULT  # Message 4
        else:
            phase = AuthPhase.RESPONSE  # Unknown, treat as response

        # Correlation key = BSSID + client MAC
        client_mac = dst_mac if key_ack == "1" else src_mac
        correlation_key = f"{bssid}:{client_mac}"

        return AuthMessage(
            phase=phase,
            correlation_key=correlation_key,
            timestamp=timestamp,
            frame_number=frame_num,
            source_ip=src_mac,  # Using MAC instead of IP
            source_port=0,
            dest_ip=dst_mac,
            dest_port=0,
            protocol=self.protocol_name,
            raw_data=fields
        )

    def build_credential(self, messages: List[AuthMessage]) -> Optional[ExtractedCredential]:
        """Build WPA credential from 4-way handshake."""
        ap_mac = None
        client_mac = None
        ssid = None
        anonce = None
        snonce = None
        mic = None
        eapol_frame = None
        replay_counter = None
        key_data = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            bssid = self._get_first(msg.raw_data.get("wlan.bssid", ""))
            if bssid:
                ap_mac = bssid.replace(":", "").lower()

            ssid_val = self._get_first(msg.raw_data.get("wlan_mgt.ssid", ""))
            if ssid_val:
                ssid = ssid_val

            nonce = self._get_first(msg.raw_data.get("eapol.keydes.nonce", ""))
            key_ack = self._get_first(msg.raw_data.get("eapol.keydes.key_info.key_ack", ""))
            key_mic = self._get_first(msg.raw_data.get("eapol.keydes.key_info.key_mic", ""))

            if nonce and nonce != "00" * 32:
                if key_ack == "1" and key_mic != "1":
                    # Message 1: ANonce from AP
                    anonce = nonce.replace(":", "")
                elif key_ack != "1" and key_mic == "1":
                    # Message 2: SNonce from client
                    snonce = nonce.replace(":", "")
                    # Get client MAC
                    src = self._get_first(msg.raw_data.get("wlan.sa", ""))
                    if src:
                        client_mac = src.replace(":", "").lower()
                    timestamp = msg.timestamp

            mic_val = self._get_first(msg.raw_data.get("eapol.keydes.mic", ""))
            if mic_val and mic_val != "00" * 16:
                mic = mic_val.replace(":", "")

            rc = self._get_first(msg.raw_data.get("eapol.keydes.replay_counter", ""))
            if rc:
                replay_counter = rc

            kd = self._get_first(msg.raw_data.get("eapol.keydes.data", ""))
            if kd:
                key_data = kd.replace(":", "")

        if not anonce or not snonce or not mic:
            return None

        # Build hashcat 22000 format (modern WPA format)
        # WPA*TYPE*PMKID_OR_MIC*MAC_AP*MAC_CLIENT*ESSID_HEX*ANONCE*EAPOL*MESSAGEPAIR
        # For EAPOL capture (type 02):
        ssid_hex = ssid.encode().hex() if ssid else ""

        # Simplified format - full EAPOL frame capture would be more complex
        # hashcat -m 22000 expects: WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*ANONCE*EAPOL*MP
        hashcat_format = None
        if ap_mac and client_mac and ssid_hex:
            # Note: Full implementation would need to capture entire EAPOL frame
            # This is a simplified representation
            hashcat_format = f"WPA*02*{mic}*{ap_mac}*{client_mac}*{ssid_hex}*{anonce}*{snonce}*00"

        metadata = ProtocolMetadata(
            raw_fields={
                "ssid": ssid,
                "ap_mac": ap_mac,
                "client_mac": client_mac,
                "replay_counter": replay_counter,
                "note": "WPA/WPA2 4-way handshake",
            }
        )

        return ExtractedCredential(
            protocol="wpa",
            username=ssid or "unknown_ssid",
            domain=ap_mac,
            credential_data={
                "anonce": anonce,
                "snonce": snonce,
                "mic": mic,
                "ap_mac": ap_mac,
                "client_mac": client_mac,
                "ssid": ssid,
                "key_data": key_data,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=22000,
            source_ip=client_mac or "",
            source_port=0,
            target_ip=ap_mac or "",
            target_port=0,
            target_service="wpa",
            timestamp=timestamp,
            metadata=metadata,
            auth_success=None,  # Determined by Message 3/4 presence
        )

    def _get_first(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def get_hashcat_mode(self) -> Optional[int]:
        return 22000  # Modern WPA format
