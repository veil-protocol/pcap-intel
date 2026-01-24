#!/usr/bin/env python3
"""
AUTH ENGINE - Modbus Credential Handler

Extracts Modbus protocol authentication (limited).

Modbus Protocol:
    - Modbus TCP (port 502): No built-in authentication
    - Modbus RTU/ASCII: Serial protocols
    - Modbus/TCP Security (TLS): With authentication

Most Modbus is unauthenticated, but we can capture:
    - Unit IDs being accessed
    - Function codes
    - Read/Write operations
    - Device identification

Hashcat Mode: N/A (no password-based auth in standard Modbus)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class ModbusAuthHandler(AuthProtocolHandler):
    """
    Handler for Modbus protocol.

    Captures device access patterns (no real auth in standard Modbus).
    """

    @property
    def protocol_name(self) -> str:
        return "modbus"

    @property
    def tshark_filter(self) -> str:
        return "modbus"

    @property
    def correlation_field(self) -> str:
        return "modbus.trans_id"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "modbus.trans_id",
            "modbus.unit_id",
            "modbus.func_code",
            "modbus.reference_num",
            "modbus.word_cnt",
            "modbus.byte_cnt",
            "modbus.data",
            "modbus.exception_code",
            # MEI (Device Identification)
            "modbus.mei.device_id",
            "modbus.mei.object_id",
            "modbus.mei.object_value",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify Modbus message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)

        trans_id = self._get_first(fields.get("modbus.trans_id", ""))
        func_code = self._get_first(fields.get("modbus.func_code", ""))
        unit_id = self._get_first(fields.get("modbus.unit_id", ""))
        exception = self._get_first(fields.get("modbus.exception_code", ""))

        if not func_code and not unit_id:
            return None

        correlation_key = trans_id or f"{src_ip}:{dst_ip}"

        # Function codes of interest:
        # 43 (0x2B) = Read Device Identification (MEI)
        # 17 (0x11) = Report Server ID
        # Write functions may indicate privileged access

        if exception:
            phase = AuthPhase.RESULT  # Error response
        elif func_code in ["43", "17"]:
            if src_port == 502:
                phase = AuthPhase.RESULT  # Server response
            else:
                phase = AuthPhase.INITIATION  # Client request
        elif dst_port == 502:
            phase = AuthPhase.INITIATION  # Request
        else:
            phase = AuthPhase.RESULT  # Response

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
        """Build Modbus 'credential' (device access info)."""
        unit_ids = set()
        func_codes = set()
        device_id = None
        vendor = None
        product = None
        version = None
        client_ip = None
        server_ip = None
        access_granted = True
        timestamp = 0.0

        func_names = {
            "1": "Read Coils",
            "2": "Read Discrete Inputs",
            "3": "Read Holding Registers",
            "4": "Read Input Registers",
            "5": "Write Single Coil",
            "6": "Write Single Register",
            "15": "Write Multiple Coils",
            "16": "Write Multiple Registers",
            "17": "Report Server ID",
            "43": "Read Device Identification",
        }

        for msg in sorted(messages, key=lambda m: m.timestamp):
            uid = self._get_first(msg.raw_data.get("modbus.unit_id", ""))
            if uid:
                unit_ids.add(uid)

            func = self._get_first(msg.raw_data.get("modbus.func_code", ""))
            if func:
                func_codes.add(func_names.get(func, f"FC_{func}"))

            # Device identification
            dev_id = self._get_first(msg.raw_data.get("modbus.mei.device_id", ""))
            if dev_id:
                device_id = dev_id

            obj_id = self._get_first(msg.raw_data.get("modbus.mei.object_id", ""))
            obj_val = self._get_first(msg.raw_data.get("modbus.mei.object_value", ""))
            if obj_id and obj_val:
                if obj_id == "0":
                    vendor = obj_val
                elif obj_id == "1":
                    product = obj_val
                elif obj_id == "2":
                    version = obj_val

            exception = self._get_first(msg.raw_data.get("modbus.exception_code", ""))
            if exception:
                access_granted = False

            # Track client/server
            if msg.dest_port == 502:
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp
            elif msg.source_port == 502:
                server_ip = msg.source_ip
                client_ip = msg.dest_ip

        if not unit_ids and not device_id:
            return None

        # Create a "credential" representing device access
        username = f"unit_ids:{','.join(sorted(unit_ids))}" if unit_ids else "modbus_client"

        metadata = ProtocolMetadata(
            server_version=version,
            raw_fields={
                "unit_ids": list(unit_ids),
                "func_codes": list(func_codes),
                "device_id": device_id,
                "vendor": vendor,
                "product": product,
                "note": "Modbus has no built-in auth - tracking device access",
            }
        )

        return ExtractedCredential(
            protocol="modbus",
            username=username,
            domain=server_ip,
            credential_data={
                "unit_ids": list(unit_ids),
                "func_codes": list(func_codes),
                "device_id": device_id,
                "vendor": vendor,
                "product": product,
            },
            hashcat_format=None,
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=502,
            target_service="modbus",
            timestamp=timestamp,
            metadata=metadata,
            auth_success=access_granted,
        )

    def _get_first(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def get_hashcat_mode(self) -> Optional[int]:
        return None
