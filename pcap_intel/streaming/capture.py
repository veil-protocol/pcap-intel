#!/usr/bin/env python3
"""
CAPTURE - Live Packet Capture via tshark

Provides async packet capture using tshark subprocess with JSON output.
"""

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import AsyncIterator, Dict, Any, Optional, List


@dataclass
class CapturedPacket:
    """
    A captured packet with parsed fields.

    Attributes:
        timestamp: Capture timestamp
        protocol: High-level protocol (ntlm, kerberos, http, etc.)
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port
        dst_port: Destination port
        fields: Protocol-specific fields from tshark
        raw_frame: Raw frame number
    """
    timestamp: datetime
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    fields: Dict[str, Any] = field(default_factory=dict)
    raw_frame: int = 0

    @property
    def stream_key(self) -> str:
        """Unique key for this TCP/UDP stream."""
        # Normalize so both directions map to same key
        ips = sorted([self.src_ip, self.dst_ip])
        ports = sorted([self.src_port, self.dst_port])
        return f"{ips[0]}:{ports[0]}-{ips[1]}:{ports[1]}"

    @classmethod
    def from_tshark_json(cls, data: Dict[str, Any]) -> Optional["CapturedPacket"]:
        """Parse a tshark JSON packet."""
        try:
            layers = data.get("_source", {}).get("layers", {})

            # Get frame info
            frame = layers.get("frame", {})
            frame_time = frame.get("frame.time_epoch", "0")
            frame_num = int(frame.get("frame.number", 0))

            # Parse timestamp - tshark 4.x outputs ISO format, older versions output float
            try:
                ts = float(frame_time)
                timestamp = datetime.fromtimestamp(ts)
            except (ValueError, TypeError):
                timestamp = datetime.fromisoformat(str(frame_time).replace("Z", "+00:00"))

            # Get IP info
            ip = layers.get("ip", {})
            src_ip = ip.get("ip.src", "")
            dst_ip = ip.get("ip.dst", "")

            # Get transport info
            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})

            if tcp:
                src_port = int(tcp.get("tcp.srcport", 0))
                dst_port = int(tcp.get("tcp.dstport", 0))
            elif udp:
                src_port = int(udp.get("udp.srcport", 0))
                dst_port = int(udp.get("udp.dstport", 0))
            else:
                src_port = 0
                dst_port = 0

            # Determine protocol
            protocol = cls._detect_protocol(layers)

            # Collect all fields for protocol handlers
            fields = cls._flatten_layers(layers)

            return cls(
                timestamp=timestamp,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                fields=fields,
                raw_frame=frame_num,
            )
        except Exception:
            return None

    @staticmethod
    def _detect_protocol(layers: Dict[str, Any]) -> str:
        """Detect the high-level protocol from layers."""
        # Serialize layer keys to string for deep search — auth protocols
        # are often nested inside transport layers (e.g. NTLM inside SMB)
        layers_str = str(layers)

        # Check for auth protocols first (highest priority)
        if "ntlmssp" in layers or "ntlmssp" in layers_str:
            return "ntlm"
        if "kerberos" in layers or "kerberos" in layers_str:
            return "kerberos"
        if "ldap" in layers:
            return "ldap"
        # Service protocols
        if "ftp" in layers:
            return "ftp"
        if "http" in layers:
            return "http"
        if "smb" in layers or "smb2" in layers:
            return "smb"
        if "ssh" in layers:
            return "ssh"
        if "dns" in layers:
            return "dns"
        if "dcerpc" in layers:
            return "dcerpc"
        if "mssql" in layers or "tds" in layers:
            return "mssql"
        if "mysql" in layers:
            return "mysql"
        if "pgsql" in layers:
            return "postgresql"
        if "vnc" in layers:
            return "vnc"
        if "rdp" in layers:
            return "rdp"
        if "tcp" in layers:
            return "tcp"
        if "udp" in layers:
            return "udp"
        return "unknown"

    @staticmethod
    def _flatten_layers(layers: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """
        Flatten nested tshark layers into a dict keyed by the canonical field name.

        tshark JSON nests fields deeply (e.g. smb2 > security_blob > ntlmssp).
        We store each field under BOTH its full path and its short canonical name
        (e.g. "ntlmssp.messagetype") so protocol handlers can find them.
        """
        result = {}
        for key, value in layers.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                result.update(CapturedPacket._flatten_layers(value, full_key))
            else:
                result[full_key] = value
                # Also store under the short key (last dotted segment that looks
                # like a real tshark field, e.g. "ntlmssp.messagetype")
                # This handles deeply nested auth fields inside SMB/SPNEGO/etc.
                if "." in key:
                    result[key] = value
        return result


class LiveCapture:
    """
    Async live packet capture using tshark.

    Provides streaming access to packets captured from an interface
    or read from a pcap file.
    """

    # tshark fields we want to capture
    TSHARK_FIELDS = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        # Auth protocols
        "ntlmssp",
        "kerberos",
        "ldap",
        "http",
        "smb",
        "smb2",
        "dns",
    ]

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        ring_buffer_size: int = 1000,
    ):
        """
        Initialize capture.

        Args:
            interface: Network interface (e.g., "eth0")
            pcap_file: Path to pcap file (alternative to live)
            bpf_filter: BPF filter expression
            ring_buffer_size: Buffer size for async processing
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.ring_buffer_size = ring_buffer_size

        self._process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    def _find_tshark(self) -> str:
        """Find tshark binary."""
        tshark = shutil.which("tshark")
        if not tshark:
            raise RuntimeError("tshark not found. Install Wireshark/tshark.")
        return tshark

    def _build_command(self) -> List[str]:
        """Build tshark command."""
        tshark = self._find_tshark()

        cmd = [tshark, "-T", "json", "-l"]

        if self.pcap_file:
            cmd.extend(["-r", self.pcap_file])
        elif self.interface:
            cmd.extend(["-i", self.interface])
        else:
            raise ValueError("Must specify interface or pcap_file")

        if self.bpf_filter:
            cmd.extend(["-f", self.bpf_filter])

        return cmd

    async def packets(self) -> AsyncIterator[CapturedPacket]:
        """
        Async generator yielding captured packets.

        Starts tshark subprocess and yields packets as they arrive.
        """
        cmd = self._build_command()
        self._running = True

        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )

            buffer = ""
            bracket_depth = 0
            in_object = False

            while self._running:
                line = await self._process.stdout.readline()
                if not line:
                    break

                line = line.decode("utf-8", errors="replace")

                # Parse JSON objects from tshark output
                for char in line:
                    if char == "{":
                        if bracket_depth == 0:
                            in_object = True
                            buffer = ""
                        bracket_depth += 1
                    if in_object:
                        buffer += char
                    if char == "}":
                        bracket_depth -= 1
                        if bracket_depth == 0 and in_object:
                            in_object = False
                            try:
                                data = json.loads(buffer)
                                packet = CapturedPacket.from_tshark_json(data)
                                if packet:
                                    yield packet
                            except json.JSONDecodeError:
                                pass

        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    async def stop(self):
        """Stop the capture."""
        self._running = False
        proc = self._process
        self._process = None
        if proc:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            except Exception:
                pass
