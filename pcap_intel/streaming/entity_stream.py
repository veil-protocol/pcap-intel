#!/usr/bin/env python3
"""
ENTITY STREAM - Real-Time Entity Extraction

Extracts network entities (hosts, services, hostnames) from packet stream.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import AsyncIterator, Dict, Any, Optional, List, Set

from .capture import CapturedPacket
from .pipeline import PipelineEvent, EventType


@dataclass
class NetworkEntity:
    """A discovered network entity."""
    type: str           # host, service, hostname, domain
    value: str          # IP, hostname, service name, etc.
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    seen_count: int = 1

    def update(self):
        """Update last seen time and count."""
        self.last_seen = datetime.now()
        self.seen_count += 1


class StreamingEntityExtractor:
    """
    Real-time entity extractor.

    Discovers:
        - Hosts (by IP)
        - Services (by port + protocol)
        - Hostnames (from DNS, NetBIOS, etc.)
        - Domains (from Kerberos, LDAP, etc.)
    """

    # Well-known ports to service names
    PORT_SERVICES = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        88: "kerberos",
        110: "pop3",
        135: "msrpc",
        139: "netbios",
        143: "imap",
        389: "ldap",
        443: "https",
        445: "smb",
        464: "kpasswd",
        636: "ldaps",
        1433: "mssql",
        1521: "oracle",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        8080: "http-proxy",
        8443: "https-alt",
    }

    def __init__(self):
        """Initialize entity extractor."""
        # Discovered entities by (type, value)
        self._entities: Dict[tuple, NetworkEntity] = {}

        # Recently emitted (dedup within time window)
        self._recently_emitted: Set[tuple] = set()

        # Stats
        self.packets_processed = 0
        self.entities_found = 0

    async def process_packet(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """
        Process packet and extract entities.

        Yields entity events for newly discovered entities.
        """
        self.packets_processed += 1

        # Extract hosts
        for ip in [packet.src_ip, packet.dst_ip]:
            if ip and not ip.startswith(("224.", "239.", "255.", "0.")):
                entity = await self._get_or_create_entity("host", ip)
                if entity.seen_count == 1:
                    yield PipelineEvent.entity(entity, source="host_discovery")

        # Extract services
        for port in [packet.src_port, packet.dst_port]:
            if port > 0 and port < 65536:
                service_name = self.PORT_SERVICES.get(port, f"port-{port}")
                if port in self.PORT_SERVICES:
                    key = ("service", f"{packet.dst_ip}:{port}")
                    entity = await self._get_or_create_entity(
                        "service",
                        f"{packet.dst_ip}:{port}",
                        metadata={"port": port, "service": service_name}
                    )
                    if entity.seen_count == 1:
                        yield PipelineEvent.entity(entity, source="service_discovery")

        # Extract DNS names
        if packet.protocol == "dns":
            async for event in self._extract_dns_entities(packet):
                yield event

        # Extract domain info from auth protocols
        if packet.protocol in ("kerberos", "ldap", "ntlm"):
            async for event in self._extract_domain_entities(packet):
                yield event

    async def _get_or_create_entity(
        self,
        entity_type: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> NetworkEntity:
        """Get existing entity or create new one."""
        key = (entity_type, value)

        if key in self._entities:
            self._entities[key].update()
            return self._entities[key]

        entity = NetworkEntity(
            type=entity_type,
            value=value,
            metadata=metadata or {}
        )
        self._entities[key] = entity
        self.entities_found += 1
        return entity

    async def _extract_dns_entities(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """Extract hostnames from DNS packets."""
        fields = packet.fields

        # Look for DNS query names and responses
        dns_name = fields.get("dns.qry.name") or fields.get("dns.resp.name")
        dns_addr = fields.get("dns.a") or fields.get("dns.aaaa")

        if dns_name:
            entity = await self._get_or_create_entity(
                "hostname",
                dns_name,
                metadata={"resolved_ip": dns_addr} if dns_addr else {}
            )
            if entity.seen_count == 1:
                yield PipelineEvent.entity(entity, source="dns")

    async def _extract_domain_entities(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
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
            # Convert DC=corp,DC=local to corp.local
            if "DC=" in base_dn:
                parts = [p.split("=")[1] for p in base_dn.split(",") if p.startswith("DC=")]
                domain = ".".join(parts)

        if domain:
            entity = await self._get_or_create_entity(
                "domain",
                domain.lower(),
                metadata={"source_protocol": packet.protocol}
            )
            if entity.seen_count == 1:
                yield PipelineEvent.entity(entity, source=packet.protocol)

    def get_entities(self, entity_type: Optional[str] = None) -> List[NetworkEntity]:
        """Get discovered entities, optionally filtered by type."""
        entities = list(self._entities.values())
        if entity_type:
            entities = [e for e in entities if e.type == entity_type]
        return entities

    def get_hosts(self) -> List[NetworkEntity]:
        """Get discovered hosts."""
        return self.get_entities("host")

    def get_services(self) -> List[NetworkEntity]:
        """Get discovered services."""
        return self.get_entities("service")
