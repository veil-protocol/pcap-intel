#!/usr/bin/env python3
"""
ENTITY STREAM - Real-Time Entity Extraction

Extracts network entities (flows, hosts, services, DNS) from packet stream.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import AsyncIterator, Dict, Any, Optional, List, Set

from .capture import CapturedPacket
from .pipeline import PipelineEvent, EventType


@dataclass
class NetworkEntity:
    """A discovered network entity."""
    type: str           # flow, host, service, dns_resolution, domain
    value: str          # Flow: "src->dst:port", Host: IP, etc.
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    seen_count: int = 1

    # Flow-specific attributes (for TUI compatibility)
    client_ip: str = ""
    server_ip: str = ""
    service_port: int = 0
    protocol: str = "TCP"

    # DNS-specific attributes
    answers: List[str] = field(default_factory=list)

    # Service-specific
    ip: str = ""
    port: int = 0

    def update(self):
        """Update last seen time and count."""
        self.last_seen = datetime.now()
        self.seen_count += 1


# IPs to filter out (multicast, broadcast, etc.)
NOISE_IP_PREFIXES = ('224.', '239.', '255.', '0.', '127.')
MULTICAST_IPS = {'224.0.0.251', '224.0.0.252', '224.0.0.1', '255.255.255.255'}


def is_noise_ip(ip: str) -> bool:
    """Check if IP is noise (multicast, broadcast, etc.)."""
    if not ip:
        return True
    if ip in MULTICAST_IPS:
        return True
    if ip.startswith(NOISE_IP_PREFIXES):
        return True
    return False


def is_valid_ip(ip: str) -> bool:
    """Basic IP validation."""
    if not ip:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


class StreamingEntityExtractor:
    """
    Real-time entity extractor.

    Discovers:
        - Flows (every packet becomes a flow entity)
        - Hosts (by IP)
        - Services (by port + protocol)
        - DNS resolutions
        - Domains (from Kerberos, LDAP, etc.)
    """

    # Well-known ports to service names
    PORT_SERVICES = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 88: "kerberos", 110: "pop3", 135: "msrpc", 139: "netbios",
        143: "imap", 389: "ldap", 443: "https", 445: "smb", 464: "kpasswd",
        636: "ldaps", 1433: "mssql", 1521: "oracle", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc", 8080: "http-proxy",
        8443: "https-alt",
    }

    def __init__(self):
        """Initialize entity extractor."""
        # Track seen flows to avoid duplicates
        self._seen_flows: Set[str] = set()
        # Track seen hosts
        self._seen_hosts: Set[str] = set()
        # Track seen services
        self._seen_services: Set[str] = set()
        # Track DNS resolutions
        self._seen_dns: Set[str] = set()

        # Stats
        self.packets_processed = 0
        self.flows_emitted = 0

    async def process_packet(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """
        Process packet and extract entities.

        EVERY packet generates a flow entity (if valid IPs).
        """
        self.packets_processed += 1

        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        src_port = packet.src_port
        dst_port = packet.dst_port
        proto = packet.protocol.upper() if packet.protocol else "TCP"

        # Skip noise
        if is_noise_ip(src_ip) and is_noise_ip(dst_ip):
            return
        if not is_valid_ip(src_ip) or not is_valid_ip(dst_ip):
            return

        # === FLOW ENTITY (every valid packet) ===
        # Format: "src->dst:port"
        flow_value = f"{src_ip}->{dst_ip}:{dst_port}"
        flow_key = f"{src_ip}:{dst_ip}:{dst_port}"

        if flow_key not in self._seen_flows:
            self._seen_flows.add(flow_key)
            self.flows_emitted += 1

            flow_entity = NetworkEntity(
                type="flow",
                value=flow_value,
                client_ip=src_ip,
                server_ip=dst_ip,
                service_port=dst_port,
                protocol=proto,
            )
            yield PipelineEvent.entity(flow_entity, source="flow_extraction")

        # === HOST ENTITIES ===
        for ip in [src_ip, dst_ip]:
            if ip and not is_noise_ip(ip) and ip not in self._seen_hosts:
                self._seen_hosts.add(ip)
                host_entity = NetworkEntity(
                    type="host",
                    value=ip,
                    ip=ip,
                )
                yield PipelineEvent.entity(host_entity, source="host_discovery")

        # === SERVICE ENTITY (for known ports on destination) ===
        if dst_port in self.PORT_SERVICES:
            service_key = f"{dst_ip}:{dst_port}"
            if service_key not in self._seen_services:
                self._seen_services.add(service_key)
                service_entity = NetworkEntity(
                    type="service",
                    value=service_key,
                    ip=dst_ip,
                    port=dst_port,
                    metadata={"service_name": self.PORT_SERVICES[dst_port]}
                )
                yield PipelineEvent.entity(service_entity, source="service_discovery")

        # === DNS RESOLUTION ===
        if packet.protocol == "dns":
            async for event in self._extract_dns(packet):
                yield event

        # === DOMAIN (from auth protocols) ===
        if packet.protocol in ("kerberos", "ldap", "ntlm"):
            async for event in self._extract_domain(packet):
                yield event

    async def _extract_dns(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """Extract DNS resolutions."""
        fields = packet.fields

        # Look for DNS response with A/AAAA records
        dns_name = None
        dns_answers = []

        # Try different field names tshark might use (various versions/formats)
        name_fields = [
            "dns.qry.name", "dns.resp.name", "dns.dns.qry.name",
            "dns.qry_name", "dns.resp_name", "Queries.dns.qry.name",
        ]
        for name_field in name_fields:
            if name_field in fields:
                dns_name = fields[name_field]
                break

        # Fallback: search for any field ending with qry.name
        if not dns_name:
            for key, val in fields.items():
                if key.endswith("qry.name") and val:
                    dns_name = val
                    break

        # Get A records - multiple possible field names
        addr_fields = [
            "dns.a", "dns.aaaa", "dns.dns.a", "dns.dns.aaaa",
            "Answers.dns.a", "Answers.dns.aaaa",
        ]
        for addr_field in addr_fields:
            if addr_field in fields:
                addr = fields[addr_field]
                if isinstance(addr, list):
                    dns_answers.extend(addr)
                else:
                    dns_answers.append(addr)

        # Fallback: search for any field that looks like an IP answer
        if not dns_answers:
            for key, val in fields.items():
                if ("dns.a" in key or "dns.aaaa" in key) and val:
                    if isinstance(val, list):
                        dns_answers.extend(val)
                    else:
                        dns_answers.append(val)

        if dns_name and dns_answers:
            dns_key = f"{dns_name}:{','.join(dns_answers)}"
            if dns_key not in self._seen_dns:
                self._seen_dns.add(dns_key)

                dns_entity = NetworkEntity(
                    type="dns_resolution",
                    value=dns_name,
                    answers=dns_answers,
                )
                yield PipelineEvent.entity(dns_entity, source="dns")

    async def _extract_domain(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """Extract domain names from auth protocols."""
        fields = packet.fields
        domain = None

        # Kerberos realm
        if "kerberos.realm" in fields:
            domain = fields["kerberos.realm"]
        # NTLM domain
        elif "ntlmssp.auth.domain" in fields:
            domain = fields["ntlmssp.auth.domain"]
        # LDAP base DN
        elif "ldap.baseObject" in fields:
            base_dn = fields["ldap.baseObject"]
            if "DC=" in str(base_dn):
                parts = [p.split("=")[1] for p in str(base_dn).split(",") if p.startswith("DC=")]
                domain = ".".join(parts)

        if domain:
            domain = str(domain).lower()
            entity = NetworkEntity(
                type="domain",
                value=domain,
                metadata={"source_protocol": packet.protocol}
            )
            yield PipelineEvent.entity(entity, source=packet.protocol)
