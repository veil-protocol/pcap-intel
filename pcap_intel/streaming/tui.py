#!/usr/bin/env python3
"""
PCAP-INTEL TUI v2.0 - Network Situational Awareness Console

NSA TAO-grade operator interface for real-time network intelligence.
Works in ANY network environment: AD, Linux, Cloud, K8s, IoT, SCADA.

VERSION 2.0 CAPABILITIES:
========================
- Live packet capture with streaming analysis
- Full-screen ASCII network graph (L-shaped connection lines)
- Universal high-value target detection (Identity, DB, K8s, SCADA)
- Credential extraction and correlation (NTLM, Kerberos, etc.)
- Flow analysis with lateral movement detection
- Manual compromise marking for red team ops
- Sliver-style codename generation
- Pivot score calculation (creds * internal reach)
- Real-time alerts (port scans, beaconing, credential theft)
- Multi-panel TUI with hosts, flows, creds, DNS, alerts

v2.0 NEW FEATURES:
=================
- Session persistence (auto-save, Ctrl+S to save, Ctrl+O to recover)
- Advanced BPF-style filtering (ip, port, proto, codename, etc.)
- Behavioral timeline panel (press 't' to toggle)
- C2 beacon detection with interval analysis
- Encrypted credential storage

KEYBINDS:
=========
- TAB: Cycle panels
- g: Network graph view
- m: Mark host as compromised
- c: Copy selected item
- /: Advanced filter (BPF-style syntax)
- t: Toggle timeline panel
- Ctrl+S: Save session
- Ctrl+O: Open/recover session
- r: Refresh
- q: Quit

Author: TAO Red Team
"""

__version__ = "2.0.0"
__codename__ = "SHADOW_SERPENT"

import asyncio
import sys
from datetime import datetime
from typing import Optional, Dict, Any, List

from textual.app import App, ComposeResult, on
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, DataTable, RichLog
from textual.binding import Binding
from rich.text import Text
from rich.markup import render as render_markup

from .pipeline import LivePipeline, EventType

try:
    import pyperclip
    HAS_CLIPBOARD = True
except ImportError:
    HAS_CLIPBOARD = False

# v2.0: Import session persistence, advanced filtering, and timeline
try:
    from ..tui.session_storage import SessionStorage, create_session_storage
    from ..tui.advanced_filter import AdvancedFilter, FILTER_PRESETS
    from ..tui.timeline_panel import TimelinePanel, ActivityType
    HAS_V2_FEATURES = True
except ImportError:
    HAS_V2_FEATURES = False
    SessionStorage = None
    AdvancedFilter = None
    TimelinePanel = None

# DNS noise filter
# DNS noise filter - only filter truly noisy stuff, keep infrastructure that might be targets
DNS_NOISE = {'doubleclick', 'analytics', 'tracking', 'telemetry', 'ads', 'beacon',
             'metric', 'pixel', 'tag', 'fonts', 'jquery', 'bootstrap', 'gstatic',
             'googlesyndication', 'googleadservices', 'fbcdn', 'facebook.com',
             'crashlytics', 'appsflyer', 'adjust.com', 'branch.io'}

# Multicast/broadcast ranges to filter
NOISE_IP_PREFIXES = ('224.', '239.', '255.', '0.', '127.')
MULTICAST_IPS = {'224.0.0.251', '224.0.0.252', '224.0.0.1', '255.255.255.255'}

# =============================================================================
# HIGH-VALUE TARGET DETECTION (Universal - Works in ANY Network Environment)
# =============================================================================
# Categories: HVT (crown jewel), INFRA (infrastructure), MGMT (management)
# Each entry: (ports, role_code, icon, category, description)

HIGH_VALUE_TARGETS = {
    # === IDENTITY & AUTHENTICATION (Tier 1 HVT - Own these = own the network) ===
    "IDENTITY": {
        "ports": {88, 389, 636, 464},           # Kerberos, LDAP, LDAPS, Kerberos password
        "role": "IDM", "icon": "[C]", "cat": "HVT",
        "desc": "Identity (AD/FreeIPA/LDAP)"
    },
    "RADIUS": {
        "ports": {1812, 1813, 1645, 1646},      # RADIUS auth/accounting
        "role": "RAD", "icon": "[C]", "cat": "HVT",
        "desc": "RADIUS/AAA Server"
    },
    "VAULT": {
        "ports": {8200, 8201},                  # HashiCorp Vault
        "role": "VLT", "icon": "[C]", "cat": "HVT",
        "desc": "Secrets Manager (Vault)"
    },

    # === DATABASES (Tier 1 HVT - Contains the data) ===
    "DB_SQL": {
        "ports": {3306, 5432, 1433, 1521, 5433},  # MySQL, PostgreSQL, MSSQL, Oracle, CockroachDB
        "role": "DB", "icon": "[D]", "cat": "HVT",
        "desc": "SQL Database"
    },
    "DB_NOSQL": {
        "ports": {27017, 27018, 27019, 6379, 9042, 7000, 7001},  # MongoDB, Redis, Cassandra
        "role": "DB", "icon": "[D]", "cat": "HVT",
        "desc": "NoSQL/Cache Database"
    },
    "ELASTICSEARCH": {
        "ports": {9200, 9300},                  # Elasticsearch
        "role": "ELK", "icon": "[D]", "cat": "HVT",
        "desc": "Elasticsearch Cluster"
    },

    # === KUBERNETES & CONTAINER (Tier 1 HVT in cloud-native) ===
    "K8S_API": {
        "ports": {6443, 8443, 10250, 10255},    # K8s API, kubelet
        "role": "K8S", "icon": "[T]", "cat": "HVT",
        "desc": "Kubernetes API/Node"
    },
    "ETCD": {
        "ports": {2379, 2380},                  # etcd (K8s secrets stored here)
        "role": "ETCD", "icon": "[C]", "cat": "HVT",
        "desc": "etcd (K8s secrets)"
    },
    "REGISTRY": {
        "ports": {5000, 5001, 5043},            # Docker registry
        "role": "REG", "icon": "[T]", "cat": "HVT",
        "desc": "Container Registry"
    },

    # === CI/CD (Tier 2 - Supply chain access) ===
    "CICD": {
        "ports": {8080, 8081, 50000},           # Jenkins (also check for /jenkins path)
        "role": "CI", "icon": "[G]", "cat": "INFRA",
        "desc": "CI/CD (Jenkins/Build)"
    },
    "GITLAB": {
        "ports": {22, 80, 443, 5000},           # GitLab uses standard ports (detect via headers)
        "role": "GIT", "icon": "[G]", "cat": "INFRA",
        "desc": "GitLab/Git Server"
    },
    "ARTIFACTORY": {
        "ports": {8081, 8082},                  # JFrog Artifactory
        "role": "ART", "icon": "[G]", "cat": "INFRA",
        "desc": "Artifact Repository"
    },

    # === MANAGEMENT INTERFACES (Tier 2 - Lateral movement goldmine) ===
    "REMOTE_MGMT": {
        "ports": {22, 23, 3389, 5985, 5986, 5900, 5901},  # SSH, Telnet, RDP, WinRM, VNC
        "role": "RMT", "icon": "[M]", "cat": "MGMT",
        "desc": "Remote Management"
    },
    "IPMI_BMC": {
        "ports": {623, 664},                    # IPMI, iLO/DRAC often on 443
        "role": "BMC", "icon": "[M]", "cat": "MGMT",
        "desc": "BMC/IPMI/iLO"
    },
    "ANSIBLE_SALT": {
        "ports": {4505, 4506, 8125},            # Salt master/minion, StatsD
        "role": "CFG", "icon": "[M]", "cat": "MGMT",
        "desc": "Config Management"
    },

    # === NETWORK INFRASTRUCTURE (Tier 2) ===
    "DNS": {
        "ports": {53},                          # DNS
        "role": "DNS", "icon": "[N]", "cat": "INFRA",
        "desc": "DNS Server"
    },
    "DHCP": {
        "ports": {67, 68},                      # DHCP
        "role": "DHCP", "icon": "[N]", "cat": "INFRA",
        "desc": "DHCP Server"
    },
    "NTP": {
        "ports": {123},                         # NTP
        "role": "NTP", "icon": "[N]", "cat": "INFRA",
        "desc": "NTP Server"
    },
    "PROXY": {
        "ports": {3128, 8080, 8888},            # Squid, web proxy
        "role": "PRX", "icon": "[N]", "cat": "INFRA",
        "desc": "Proxy Server"
    },

    # === VPN & EDGE (Tier 2) ===
    "VPN": {
        "ports": {500, 4500, 1194, 1723, 51820},  # IKE, IPSec NAT-T, OpenVPN, PPTP, WireGuard
        "role": "VPN", "icon": "[V]", "cat": "INFRA",
        "desc": "VPN Concentrator"
    },

    # === MAIL (Tier 2 - Often has creds, business intel) ===
    "MAIL": {
        "ports": {25, 465, 587, 110, 995, 143, 993},  # SMTP, SMTPS, POP3, IMAP
        "role": "MAIL", "icon": "[@]", "cat": "INFRA",
        "desc": "Mail Server"
    },

    # === FILE STORAGE (Tier 2) ===
    "SMB_NFS": {
        "ports": {139, 445, 2049},              # SMB, NFS
        "role": "FILE", "icon": "[F]", "cat": "INFRA",
        "desc": "File Server (SMB/NFS)"
    },
    "FTP": {
        "ports": {20, 21, 69, 22},              # FTP, TFTP, SFTP
        "role": "FTP", "icon": "[F]", "cat": "INFRA",
        "desc": "FTP/SFTP Server"
    },
    "S3_MINIO": {
        "ports": {9000, 9001},                  # MinIO S3-compatible
        "role": "S3", "icon": "[F]", "cat": "INFRA",
        "desc": "Object Storage (S3/MinIO)"
    },

    # === MONITORING & LOGGING (Tier 3 - Intel source) ===
    "MONITORING": {
        "ports": {9090, 9093, 9094, 3000, 8086},  # Prometheus, Alertmanager, Grafana, InfluxDB
        "role": "MON", "icon": "[L]", "cat": "INFRA",
        "desc": "Monitoring (Prometheus/Grafana)"
    },
    "LOGGING": {
        "ports": {5044, 5601, 9200, 514, 1514},  # Logstash, Kibana, Elasticsearch, Syslog
        "role": "LOG", "icon": "[L]", "cat": "INFRA",
        "desc": "Logging (ELK/Syslog)"
    },
    "SIEM": {
        "ports": {8089, 9997, 8000},            # Splunk
        "role": "SIEM", "icon": "[L]", "cat": "INFRA",
        "desc": "SIEM (Splunk)"
    },

    # === MESSAGE QUEUES (Tier 3) ===
    "MQ": {
        "ports": {5672, 15672, 61616, 9092},    # RabbitMQ, ActiveMQ, Kafka
        "role": "MQ", "icon": "[Q]", "cat": "INFRA",
        "desc": "Message Queue"
    },

    # === WEB (Tier 3 - Common attack surface) ===
    "WEB": {
        "ports": {80, 443, 8080, 8443, 8000, 8888},
        "role": "WEB", "icon": "[W]", "cat": "SVC",
        "desc": "Web Server"
    },

    # === IOT & SCADA (Tier 1 in OT environments) ===
    "SCADA": {
        "ports": {502, 102, 44818, 47808, 20000},  # Modbus, S7, EtherNet/IP, BACnet, DNP3
        "role": "OT", "icon": "[!]", "cat": "HVT",
        "desc": "SCADA/ICS/OT"
    },
    "IOT_MQTT": {
        "ports": {1883, 8883},                  # MQTT
        "role": "IOT", "icon": "[I]", "cat": "INFRA",
        "desc": "IoT (MQTT)"
    },
}

# Build lookup sets for fast detection
HVT_PORTS = set()        # High-value targets (crown jewels)
INFRA_PORTS = set()      # Infrastructure
MGMT_PORTS = set()       # Management interfaces

for svc_name, svc_data in HIGH_VALUE_TARGETS.items():
    ports = svc_data["ports"]
    cat = svc_data["cat"]
    if cat == "HVT":
        HVT_PORTS.update(ports)
    elif cat == "INFRA":
        INFRA_PORTS.update(ports)
    elif cat == "MGMT":
        MGMT_PORTS.update(ports)


def detect_high_value_target(ports: set) -> tuple:
    """
    Detect if a host is a high-value target based on observed ports.

    Returns: (role, icon, category, description) or (None, None, None, None)

    Priority:
    1. HVT (crown jewels) - Identity, Databases, K8s secrets
    2. MGMT (management) - Remote access, BMC
    3. INFRA (infrastructure) - DNS, VPN, Mail
    4. SVC (services) - Web servers
    """
    if not ports:
        return (None, None, None, None)

    # Check each service definition in priority order
    # HVT first, then MGMT, then INFRA, then SVC
    priority_order = ["HVT", "MGMT", "INFRA", "SVC"]

    for priority_cat in priority_order:
        for svc_name, svc_data in HIGH_VALUE_TARGETS.items():
            if svc_data["cat"] != priority_cat:
                continue
            if ports & svc_data["ports"]:  # Any port match
                return (svc_data["role"], svc_data["icon"], svc_data["cat"], svc_data["desc"])

    return (None, None, None, None)


def get_hvt_icon(ports: set) -> tuple:
    """Get icon and style ONLY for true high-value targets (HVT category)."""
    role, icon, cat, _ = detect_high_value_target(ports)

    # Only show special icons for HVT (crown jewels) - identity, databases, k8s, scada
    if cat == "HVT":
        return (icon or "[H]", "bold #f0883e")

    # Everything else gets no special icon
    return (None, None)


import re
import hashlib
IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')

# Sliver-style codename generator
ADJECTIVES_EXT = ['CRIMSON', 'SHADOW', 'PHANTOM', 'VENOM', 'SPECTER', 'ROGUE', 'SILENT', 'DARK', 'STEALTH', 'CYBER']
NOUNS_EXT = ['VIPER', 'COBRA', 'WRAITH', 'SERPENT', 'SPIDER', 'RAVEN', 'GHOST', 'DEMON', 'REAPER', 'HUNTER']
ADJECTIVES_INT = ['SWIFT', 'IRON', 'STORM', 'FROST', 'NIGHT', 'STEEL', 'RAPID', 'BRAVE', 'FIERCE', 'PRIME']
NOUNS_INT = ['WOLF', 'HAWK', 'BEAR', 'EAGLE', 'TIGER', 'LION', 'FALCON', 'PANTHER', 'SHARK', 'DRAGON']
ADJECTIVES_LAN = ['BLUE', 'RED', 'GOLD', 'GREEN', 'WHITE', 'BLACK', 'AMBER', 'JADE', 'RUBY', 'ONYX']
NOUNS_LAN = ['NODE', 'STATION', 'TOWER', 'CORE', 'NEXUS', 'HUB', 'POINT', 'BASE', 'UNIT', 'CELL']


def get_host_codename(ip: str, local_subnet: str = "10.0.0") -> tuple:
    """Generate consistent codename for IP based on location category."""
    # Use hash for consistent naming
    h = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)

    # Determine location category
    if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                     '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                     '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
        # Check if same subnet (first 3 octets match local)
        ip_prefix = '.'.join(ip.split('.')[:3])
        if ip_prefix == local_subnet:
            # LAN - same subnet
            adj = ADJECTIVES_LAN[h % len(ADJECTIVES_LAN)]
            noun = NOUNS_LAN[(h >> 4) % len(NOUNS_LAN)]
            return (f"LAN-{adj}_{noun}", "lan", "#7ee787")
        else:
            # INT - internal but different subnet
            adj = ADJECTIVES_INT[h % len(ADJECTIVES_INT)]
            noun = NOUNS_INT[(h >> 4) % len(NOUNS_INT)]
            return (f"INT-{adj}_{noun}", "int", "#58a6ff")
    else:
        # EXT - external
        adj = ADJECTIVES_EXT[h % len(ADJECTIVES_EXT)]
        noun = NOUNS_EXT[(h >> 4) % len(NOUNS_EXT)]
        return (f"EXT-{adj}_{noun}", "ext", "#f85149")


def is_valid_ip(value: str) -> bool:
    """Validate that a string is actually an IP address."""
    if not value or not isinstance(value, str):
        return False
    # Quick rejection of obvious non-IPs
    if '=' in value or '+' in value or '/' in value or len(value) > 15:
        return False
    if not IP_PATTERN.match(value):
        return False
    # Validate octets are 0-255
    try:
        parts = value.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    except:
        return False


def is_noise_ip(ip: str) -> bool:
    """Check if IP is multicast, broadcast, or other noise."""
    if not ip:
        return True
    if ip in MULTICAST_IPS:
        return True
    return ip.startswith(NOISE_IP_PREFIXES)


def is_valid_domain(value: str) -> bool:
    """Validate that a string looks like a domain name."""
    if not value or not isinstance(value, str):
        return False
    # Reject if contains obvious non-domain chars
    if '=' in value or '+' in value or ' ' in value:
        return False
    if len(value) > 253 or len(value) < 4:
        return False
    # Must have at least one dot
    if '.' not in value:
        return False
    # Check pattern
    return bool(DOMAIN_PATTERN.match(value))


def is_interesting_dns(domain: str) -> bool:
    if not domain or len(domain) < 5:
        return False
    if not is_valid_domain(domain):
        return False
    d = domain.lower()
    return not any(p in d for p in DNS_NOISE)


def calculate_threat_score(host_data: dict) -> int:
    """Calculate threat score for a host (0-100)."""
    score = 0
    # Credentials captured = high value target
    creds = len(host_data.get("creds", []))
    score += min(creds * 25, 50)
    # Flow activity
    flows = len(host_data.get("flows", []))
    score += min(flows * 2, 20)
    # Services exposed
    services = len(host_data.get("services", set()))
    score += min(services * 5, 15)
    # Known OS (intel value)
    if host_data.get("os") and host_data["os"] != "?":
        score += 5
    # Has DNS name (easier to understand)
    if host_data.get("dns"):
        score += 5
    # Windows hosts are typically higher value targets
    os_str = str(host_data.get("os", "")).lower()
    if "windows" in os_str:
        score += 5
    return min(score, 100)


def get_entity_attr(entity, attr: str, default=None):
    """Safely get attribute from entity (handles both .details and .attributes)."""
    # Try details first (FlowIntel, FingerprintIntel, DNSIntel)
    if hasattr(entity, 'details') and isinstance(entity.details, dict):
        if attr in entity.details:
            return entity.details[attr]
    # Try attributes (StreamingEntity)
    if hasattr(entity, 'attributes') and isinstance(entity.attributes, dict):
        if attr in entity.attributes:
            return entity.attributes[attr]
    # Try direct attribute
    if hasattr(entity, attr):
        return getattr(entity, attr)
    return default


def render_fullscreen_graph(hosts: dict, flows: dict, local_subnet: str = "10.0.0", compromised_hosts: set = None, width: int = 120, height: int = 50) -> Text:
    """
    Full-screen ASCII network graph with L-shaped connection lines.
    Internal hosts on left, external on right, lines connecting them.
    """
    import math

    if compromised_hosts is None:
        compromised_hosts = set()

    # Build connection data
    connections = {}
    edge_weight = {}

    for flow in flows.values():
        src = flow.get('src', '')
        dst = flow.get('dst', '')
        count = flow.get('count', 1)

        if not src or not dst or src == dst:
            continue

        if src not in connections:
            connections[src] = set()
        if dst not in connections:
            connections[dst] = set()

        connections[src].add(dst)
        connections[dst].add(src)

        edge_key = tuple(sorted([src, dst]))
        edge_weight[edge_key] = edge_weight.get(edge_key, 0) + count

    all_nodes = set(connections.keys())
    internal_nodes = sorted([ip for ip in all_nodes if ip.startswith(('10.', '192.168.', '172.'))],
                           key=lambda ip: len(connections.get(ip, set())), reverse=True)[:15]
    external_nodes = sorted([ip for ip in all_nodes if not ip.startswith(('10.', '192.168.', '172.'))],
                           key=lambda ip: len(connections.get(ip, set())), reverse=True)[:12]

    display_nodes = internal_nodes + external_nodes

    if not display_nodes:
        return Text("No network activity detected yet...\n", style="dim")

    # === CREATE GRID ===
    grid = [[' ' for _ in range(width)] for _ in range(height)]
    grid_style = [['' for _ in range(width)] for _ in range(height)]

    # === POSITION NODES ===
    node_positions = {}

    # Internal nodes on left side (spread vertically)
    int_x = 25
    int_spacing = max(3, (height - 8) // max(len(internal_nodes), 1))
    for i, ip in enumerate(internal_nodes):
        y = 4 + i * int_spacing
        node_positions[ip] = (int_x, min(y, height - 4))

    # External nodes on right side
    ext_x = width - 20
    ext_spacing = max(3, (height - 8) // max(len(external_nodes), 1))
    for i, ip in enumerate(external_nodes):
        y = 4 + i * ext_spacing
        node_positions[ip] = (ext_x, min(y, height - 4))

    # === DRAW L-SHAPED LINES ===
    def draw_l_line(x1, y1, x2, y2, style):
        """Draw L-shaped line: horizontal then vertical."""
        mid_x = (x1 + x2) // 2

        # Horizontal from x1 to mid
        for x in range(min(x1, mid_x), max(x1, mid_x) + 1):
            if 0 <= y1 < height and 0 <= x < width and grid[y1][x] == ' ':
                grid[y1][x] = '─'
                grid_style[y1][x] = style

        # Vertical at mid_x
        for y in range(min(y1, y2), max(y1, y2) + 1):
            if 0 <= y < height and 0 <= mid_x < width and grid[y][mid_x] == ' ':
                grid[y][mid_x] = '│'
                grid_style[y][mid_x] = style

        # Horizontal from mid to x2
        for x in range(min(mid_x, x2), max(mid_x, x2) + 1):
            if 0 <= y2 < height and 0 <= x < width and grid[y2][x] == ' ':
                grid[y2][x] = '─'
                grid_style[y2][x] = style

        # Corners
        if 0 <= y1 < height and 0 <= mid_x < width:
            corner = '┐' if x1 < mid_x and y1 < y2 else '┌' if x1 > mid_x and y1 < y2 else '┘' if x1 < mid_x else '└'
            grid[y1][mid_x] = corner
            grid_style[y1][mid_x] = style

        if 0 <= y2 < height and 0 <= mid_x < width and y1 != y2:
            corner = '└' if mid_x < x2 and y1 < y2 else '┘' if mid_x > x2 and y1 < y2 else '┌' if mid_x < x2 else '┐'
            grid[y2][mid_x] = corner
            grid_style[y2][mid_x] = style

    # Draw edges
    drawn = set()
    for ip1 in display_nodes:
        for ip2 in connections.get(ip1, set()):
            if ip2 not in node_positions:
                continue
            edge_key = tuple(sorted([ip1, ip2]))
            if edge_key in drawn:
                continue
            drawn.add(edge_key)

            x1, y1 = node_positions[ip1]
            x2, y2 = node_positions[ip2]

            ip1_int = ip1.startswith(('10.', '192.168.', '172.'))
            ip2_int = ip2.startswith(('10.', '192.168.', '172.'))
            weight = edge_weight.get(edge_key, 1)

            if ip1_int and ip2_int:
                style = "#58a6ff" if weight > 5 else "#3b5998"
            elif ip1_int or ip2_int:
                style = "#7ee787" if weight > 5 else "#3d6e3d"
            else:
                style = "dim"

            draw_l_line(x1, y1, x2, y2, style)

    # === DRAW NODES ===
    for ip, (x, y) in node_positions.items():
        cn, _, color = get_host_codename(ip, local_subnet)
        is_int = ip.startswith(('10.', '192.168.', '172.'))
        has_creds = ip in hosts and len(hosts.get(ip, {}).get('creds', [])) > 0
        is_comp = ip in compromised_hosts or has_creds
        ports = hosts.get(ip, {}).get('services', set())

        hvt_icon, hvt_style = get_hvt_icon(ports)

        if is_comp:
            icon, node_style = "*", "bold #f85149"
        elif hvt_icon:
            icon, node_style = hvt_icon, hvt_style
        elif is_int:
            icon, node_style = "o", f"bold {color}"
        else:
            icon, node_style = ".", "bold #d29922"

        conn_count = len(connections.get(ip, set()))
        label = f"[{icon}{cn[:10]}×{conn_count}]"

        start_x = max(0, x - len(label) // 2)
        for i, ch in enumerate(label):
            px = start_x + i
            if 0 <= px < width and 0 <= y < height:
                grid[y][px] = ch
                grid_style[y][px] = node_style

    # === BUILD OUTPUT ===
    result = Text()

    # Header
    result.append(f"{'═' * width}\n", style="bold #58a6ff")
    header = f"  [NET]  NETWORK SITUATIONAL AWARENESS  |  {len(internal_nodes)} internal  {len(external_nodes)} external  {len(drawn)} links  |  [r]efresh [m]ark [ESC]close  "
    result.append(f"{header:<{width}}\n", style="bold white on #1a1a2e")
    result.append(f"{'═' * width}\n", style="bold #58a6ff")

    # Render grid
    for row in range(height - 4):
        for col in range(width):
            result.append(grid[row][col], style=grid_style[row][col] or "")
        result.append("\n")

    # Footer
    result.append(f"{'─' * width}\n", style="dim")
    result.append(" *", style="bold #f85149")
    result.append("=PWNED ", style="dim")
    result.append("[HVT]", style="#f0883e")
    result.append("=HVT ", style="dim")
    result.append("o", style="cyan")
    result.append("=INTERNAL ", style="dim")
    result.append(".", style="#d29922")
    result.append("=EXTERNAL ", style="dim")
    result.append("│─┐└", style="#58a6ff")
    result.append("=LINK ", style="dim")
    result.append("×N", style="bold")
    result.append("=conns", style="dim")

    return result


def render_fullscreen_graph_visual(hosts: dict, flows: dict, local_subnet: str = "10.0.0", compromised_hosts: set = None, width: int = 120, height: int = 50) -> Text:
    """
    Visual ASCII graph with actual lines - backup version.
    """
    import math

    if compromised_hosts is None:
        compromised_hosts = set()

    # Build connection data
    connections = {}
    edge_weight = {}

    for flow in flows.values():
        src = flow.get('src', '')
        dst = flow.get('dst', '')
        count = flow.get('count', 1)

        if not src or not dst or src == dst:
            continue

        if src not in connections:
            connections[src] = set()
        if dst not in connections:
            connections[dst] = set()

        connections[src].add(dst)
        connections[dst].add(src)

        edge_key = tuple(sorted([src, dst]))
        edge_weight[edge_key] = edge_weight.get(edge_key, 0) + count

    all_nodes = set(connections.keys())
    internal_nodes = sorted([ip for ip in all_nodes if ip.startswith(('10.', '192.168.', '172.'))],
                           key=lambda ip: len(connections.get(ip, set())), reverse=True)[:10]
    external_nodes = sorted([ip for ip in all_nodes if not ip.startswith(('10.', '192.168.', '172.'))],
                           key=lambda ip: len(connections.get(ip, set())), reverse=True)[:8]

    display_nodes = internal_nodes + external_nodes

    if not display_nodes:
        return Text("No network activity yet...\n", style="dim")

    # Create grid
    grid = [[' ' for _ in range(width)] for _ in range(height)]
    grid_style = [['' for _ in range(width)] for _ in range(height)]

    # Position nodes
    node_positions = {}
    center_x, center_y = width // 2, height // 2

    # Internal: inner circle
    for i, ip in enumerate(internal_nodes):
        angle = (2 * math.pi * i) / max(len(internal_nodes), 1)
        r = min(width, height) // 4
        x = int(center_x + r * math.cos(angle))
        y = int(center_y + r * 0.4 * math.sin(angle))
        node_positions[ip] = (max(12, min(x, width-12)), max(3, min(y, height-3)))

    # External: outer circle
    for i, ip in enumerate(external_nodes):
        angle = (2 * math.pi * i) / max(len(external_nodes), 1)
        r = min(width, height) // 2.5
        x = int(center_x + r * math.cos(angle))
        y = int(center_y + r * 0.4 * math.sin(angle))
        node_positions[ip] = (max(12, min(x, width-12)), max(3, min(y, height-3)))

    # Draw simple lines (just dots along the path)
    for ip1 in display_nodes:
        for ip2 in connections.get(ip1, set()):
            if ip2 not in node_positions or ip1 >= ip2:
                continue
            x1, y1 = node_positions[ip1]
            x2, y2 = node_positions[ip2]

            # Bresenham line
            dx, dy = abs(x2-x1), abs(y2-y1)
            sx, sy = (1 if x1 < x2 else -1), (1 if y1 < y2 else -1)
            err = dx - dy
            x, y = x1, y1

            while True:
                if 0 <= x < width and 0 <= y < height and grid[y][x] == ' ':
                    grid[y][x] = '·'
                    grid_style[y][x] = "#3b5998"
                if x == x2 and y == y2:
                    break
                e2 = 2 * err
                if e2 > -dy:
                    err -= dy
                    x += sx
                if e2 < dx:
                    err += dx
                    y += sy

    # Draw nodes on top
    for ip, (x, y) in node_positions.items():
        cn, _, color = get_host_codename(ip, local_subnet)
        is_int = ip.startswith(('10.', '192.168.', '172.'))
        is_comp = ip in compromised_hosts

        if is_comp:
            icon, style = "*", "bold #f85149"
        elif is_int:
            icon, style = "o", f"bold {color}"
        else:
            icon, style = ".", "bold #d29922"

        label = f"{icon}{cn[:8]}"
        for i, ch in enumerate(label):
            px = x - len(label)//2 + i
            if 0 <= px < width and 0 <= y < height:
                grid[y][px] = ch
                grid_style[y][px] = style

    # Build result
    result = Text()
    result.append(f"{'═'*width}\n", style="bold #58a6ff")
    result.append(f"  [NET] NETWORK TOPOLOGY  |  {len(internal_nodes)} int  {len(external_nodes)} ext  |  [r]efresh [ESC]close\n", style="bold white")
    result.append(f"{'═'*width}\n", style="bold #58a6ff")

    for row in range(height - 4):
        for col in range(width):
            result.append(grid[row][col], style=grid_style[row][col] or "")
        result.append("\n")

    # Footer/Legend
    result.append(f"{'─' * width}\n", style="dim")
    result.append(" ", style="")
    result.append("*", style="bold #f85149")
    result.append("=PWNED ", style="dim")
    result.append("o", style="cyan")
    result.append("=INTERNAL ", style="dim")
    result.append(".", style="#d29922")
    result.append("=EXTERNAL ", style="dim")
    result.append(".", style="#3b5998")
    result.append("=LINK", style="dim")

    return result


def render_network_map(hosts: dict, flows: dict, local_subnet: str = "10.0.0", compromised_hosts: set = None) -> Text:
    """
    Render true network topology map - nodes connected by edges.
    Shows the actual web of who's connected to who.
    """
    graph = Text()

    if compromised_hosts is None:
        compromised_hosts = set()

    # Build bidirectional adjacency (for internal network view)
    connections = {}  # ip -> set of connected ips
    edge_data = {}    # (ip1, ip2) -> {ports, count}

    for flow in flows.values():
        src = flow.get('src', '')
        dst = flow.get('dst', '')
        port = flow.get('port', 0)
        count = flow.get('count', 1)

        if not src or not dst:
            continue

        # Only internal hosts for the mesh view
        src_int = src.startswith(('10.', '192.168.', '172.'))
        dst_int = dst.startswith(('10.', '192.168.', '172.'))

        if src_int:
            if src not in connections:
                connections[src] = set()
            connections[src].add(dst)

        if dst_int:
            if dst not in connections:
                connections[dst] = set()
            connections[dst].add(src)

        # Track edge data (canonical order)
        edge_key = tuple(sorted([src, dst]))
        if edge_key not in edge_data:
            edge_data[edge_key] = {'ports': set(), 'count': 0}
        edge_data[edge_key]['ports'].add(port)
        edge_data[edge_key]['count'] += count

    # Get all internal nodes sorted by connection count
    internal_nodes = sorted(
        [(ip, len(conns)) for ip, conns in connections.items()
         if ip.startswith(('10.', '192.168.', '172.'))],
        key=lambda x: -x[1]
    )

    # Node label helper
    def node_label(ip):
        cn, _, color = get_host_codename(ip, local_subnet)
        has_creds = ip in hosts and len(hosts[ip].get('creds', [])) > 0
        is_comp = ip in compromised_hosts or has_creds

        # Determine node type - only HVT gets special icons
        ports = hosts.get(ip, {}).get('services', set())
        hvt_icon, _ = get_hvt_icon(ports)

        if is_comp:
            icon = "*"   # Compromised
        elif hvt_icon:  # Only true HVT (identity, DB, K8s, SCADA)
            icon = hvt_icon
        else:
            icon = "o"   # Normal

        return cn[:10], color, icon, is_comp

    # === HEADER ===
    total_internal = len(internal_nodes)
    total_edges = sum(1 for (a, b) in edge_data if a.startswith(('10.', '192.168.', '172.')) and b.startswith(('10.', '192.168.', '172.')))

    graph.append("╔" + "═" * 78 + "╗\n", style="bold #58a6ff")
    graph.append("║", style="#58a6ff")
    graph.append("  [NET]  INTERNAL NETWORK MAP  ", style="bold white on #58a6ff")
    graph.append(f"  {total_internal} nodes  {total_edges} conns  |  [r]efresh [ESC]close", style="dim")
    graph.append("║\n", style="#58a6ff")
    graph.append("╚" + "═" * 78 + "╝\n\n", style="bold #58a6ff")

    # === DRAW NODE MESH ===
    # Place nodes in rows, draw connections

    nodes_to_show = [ip for ip, _ in internal_nodes[:16]]
    node_positions = {}  # ip -> (row, col)

    # Arrange in a grid (4 columns)
    cols = 4
    for i, ip in enumerate(nodes_to_show):
        row = i // cols
        col = i % cols
        node_positions[ip] = (row, col)

    # Build the visual grid
    rows_needed = (len(nodes_to_show) + cols - 1) // cols

    # For each row of nodes
    for row in range(rows_needed):
        # Get nodes in this row
        row_nodes = [(ip, node_positions[ip][1]) for ip in nodes_to_show
                    if node_positions.get(ip, (None, None))[0] == row]
        row_nodes.sort(key=lambda x: x[1])

        # Draw the nodes
        line = Text()
        line.append("  ", style="")

        for col in range(cols):
            node_ip = None
            for ip, c in row_nodes:
                if c == col:
                    node_ip = ip
                    break

            if node_ip:
                label, color, icon, is_comp = node_label(node_ip)
                style = "bold red" if is_comp else f"bold {color}"

                # Draw node box
                line.append("┌", style="dim")
                line.append(f"{icon}{label:<9}", style=style)
                line.append("┐", style="dim")
            else:
                line.append(" " * 13, style="")

            if col < cols - 1:
                # Check for horizontal connection
                has_conn = False
                if node_ip:
                    for ip2, c2 in row_nodes:
                        if c2 == col + 1 and ip2 in connections.get(node_ip, set()):
                            has_conn = True
                            break
                if has_conn:
                    line.append("════", style="#58a6ff")
                else:
                    line.append("    ", style="")

        graph.append(line)
        graph.append("\n")

        # Draw bottom of node boxes with vertical connections
        line2 = Text()
        line2.append("  ", style="")

        for col in range(cols):
            node_ip = None
            for ip, c in row_nodes:
                if c == col:
                    node_ip = ip
                    break

            if node_ip:
                # Check for vertical connection to next row
                has_down = False
                if row < rows_needed - 1:
                    for ip2 in nodes_to_show:
                        pos = node_positions.get(ip2)
                        if pos and pos[0] == row + 1 and ip2 in connections.get(node_ip, set()):
                            has_down = True
                            break

                line2.append("└", style="dim")
                if has_down:
                    line2.append("────║────", style="dim")
                else:
                    line2.append("─────────", style="dim")
                line2.append("┘", style="dim")
            else:
                line2.append(" " * 13, style="")

            if col < cols - 1:
                line2.append("    ", style="")

        graph.append(line2)
        graph.append("\n")

        # Draw vertical connectors between rows
        if row < rows_needed - 1:
            line3 = Text()
            line3.append("  ", style="")
            for col in range(cols):
                node_ip = None
                for ip, c in row_nodes:
                    if c == col:
                        node_ip = ip
                        break

                has_down = False
                if node_ip:
                    for ip2 in nodes_to_show:
                        pos = node_positions.get(ip2)
                        if pos and pos[0] == row + 1 and ip2 in connections.get(node_ip, set()):
                            has_down = True
                            break

                if has_down:
                    line3.append("      ║      ", style="#58a6ff")
                else:
                    line3.append(" " * 13, style="")

                if col < cols - 1:
                    line3.append("    ", style="")

            graph.append(line3)
            graph.append("\n")

    # === CONNECTION MATRIX ===
    graph.append("\n")
    graph.append("  ┌─ CONNECTION MATRIX ", style="bold #a371f7")
    graph.append("─" * 56 + "┐\n", style="#a371f7")

    # Show top connections with details
    sorted_edges = sorted(edge_data.items(), key=lambda x: -x[1]['count'])

    for (ip1, ip2), data in sorted_edges[:15]:
        # Only show internal-internal or internal-external
        ip1_int = ip1.startswith(('10.', '192.168.', '172.'))
        ip2_int = ip2.startswith(('10.', '192.168.', '172.'))

        if not ip1_int and not ip2_int:
            continue

        l1, c1, i1, comp1 = node_label(ip1)
        l2, c2, i2, comp2 = node_label(ip2)

        s1 = "bold red" if comp1 else c1
        s2 = "bold red" if comp2 else c2

        ports_str = ','.join(str(p) for p in sorted(data['ports'])[:3])

        # Connection type
        if ip1_int and ip2_int:
            conn = "+--+"
            conn_style = "#58a6ff"
        elif ip1_int:
            conn = "+==>>"
            conn_style = "#7ee787"
        else:
            conn = "<<=+"
            conn_style = "#f85149"

        graph.append("  │ ", style="#a371f7")
        graph.append(f"{i1}{l1:<10}", style=s1)
        graph.append(f" {conn} ", style=conn_style)
        graph.append(f"{i2}{l2:<10}", style=s2)
        graph.append(f" :{ports_str:<12}", style="dim")
        graph.append(f" ×{data['count']}", style="bold" if data['count'] > 10 else "dim")
        graph.append(" │\n", style="#a371f7")

    graph.append("  └" + "─" * 76 + "┘\n", style="#a371f7")

    # === EXTERNAL CONNECTIONS ===
    ext_connections = {}
    for (ip1, ip2), data in edge_data.items():
        ip1_int = ip1.startswith(('10.', '192.168.', '172.'))
        ip2_int = ip2.startswith(('10.', '192.168.', '172.'))

        if ip1_int and not ip2_int:
            if ip2 not in ext_connections:
                ext_connections[ip2] = {'hosts': set(), 'count': 0}
            ext_connections[ip2]['hosts'].add(ip1)
            ext_connections[ip2]['count'] += data['count']
        elif ip2_int and not ip1_int:
            if ip1 not in ext_connections:
                ext_connections[ip1] = {'hosts': set(), 'count': 0}
            ext_connections[ip1]['hosts'].add(ip2)
            ext_connections[ip1]['count'] += data['count']

    if ext_connections:
        graph.append("\n  ┌─ EXTERNAL DESTINATIONS ", style="bold yellow")
        graph.append("─" * 52 + "┐\n", style="yellow")

        for ext_ip, data in sorted(ext_connections.items(), key=lambda x: -x[1]['count'])[:8]:
            l, c, i, _ = node_label(ext_ip)
            int_hosts = [node_label(h)[0] for h in list(data['hosts'])[:3]]

            graph.append("  │ ", style="yellow")
            graph.append(f". {l:<12}", style="bold yellow")
            graph.append(" <- ", style="#f85149")
            graph.append(", ".join(int_hosts), style="cyan")
            if len(data['hosts']) > 3:
                graph.append(f" +{len(data['hosts'])-3}", style="dim")
            graph.append(f"  ×{data['count']}", style="dim")
            graph.append(" │\n", style="yellow")

        graph.append("  └" + "─" * 76 + "┘\n", style="yellow")

    # Legend
    graph.append("\n  ")
    graph.append("*", style="bold red")
    graph.append("=Pwned ", style="dim")
    graph.append("[HVT]", style="#f0883e")
    graph.append("=HVT ", style="dim")
    graph.append("o", style="cyan")
    graph.append("=Host ", style="dim")
    graph.append("═══", style="#58a6ff")
    graph.append("=Connected", style="dim")

    return graph


def render_network_graph(hosts: dict, flows: dict, dns: dict) -> Text:
    """Render fullscreen ASCII network topology graph."""
    graph = Text()

    # Categorize hosts
    local_hosts = []
    external_hosts = []

    for ip, data in hosts.items():
        if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                         '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                         '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
            local_hosts.append((ip, data))
        else:
            external_hosts.append((ip, data))

    local_hosts.sort(key=lambda x: calculate_threat_score(x[1]), reverse=True)
    external_hosts.sort(key=lambda x: calculate_threat_score(x[1]), reverse=True)

    # Build connection map
    connections = {}
    port_map = {}  # (src, dst) -> set of ports
    for key, flow in flows.items():
        src, dst = flow.get('src', '?'), flow.get('dst', '?')
        port = flow.get('port', 0)
        cnt = flow.get('count', 1)
        connections[(src, dst)] = connections.get((src, dst), 0) + cnt
        if (src, dst) not in port_map:
            port_map[(src, dst)] = set()
        port_map[(src, dst)].add(port)

    # Summary stats
    graph.append("═" * 80 + "\n", style="bold #58a6ff")
    graph.append("  [NET]  NETWORK TOPOLOGY  ", style="bold white on #21262d")
    graph.append(f"  Hosts: {len(hosts)}  Flows: {len(flows)}  Connections: {len(connections)}  |  [ESC]close\n", style="dim")
    graph.append("═" * 80 + "\n\n", style="bold #58a6ff")

    # LOCAL HOSTS
    graph.append("┌─ LOCAL HOSTS ", style="bold cyan")
    graph.append("─" * 64 + "┐\n", style="cyan")
    graph.append("│ ", style="cyan")
    graph.append(f"{'MARKER':<3} {'IP ADDRESS':<16} {'OS':<20} {'SVCS':<12} {'IN':<4} {'OUT':<4} {'SCR':<4}", style="bold")
    graph.append(" │\n", style="cyan")
    graph.append("├" + "─" * 78 + "┤\n", style="cyan")

    for ip, data in local_hosts[:15]:
        score = calculate_threat_score(data)
        creds = len(data.get("creds", []))
        os_info = data.get("os", "?")[:18]
        svcs = data.get("services", set())
        svc_str = ",".join(str(s) for s in list(svcs)[:3])[:10]

        if creds > 0:
            style, marker = "bold #f85149", "*"
        elif score >= 50:
            style, marker = "bold #d29922", "o"
        elif score >= 25:
            style, marker = "#d29922", "o"
        elif score >= 10:
            style, marker = "#7ee787", "."
        else:
            style, marker = "dim", "."

        out_conns = sum(1 for (s, d) in connections if s == ip)
        in_conns = sum(1 for (s, d) in connections if d == ip)

        graph.append("│ ", style="cyan")
        graph.append(f" {marker}  ", style=style)
        graph.append(f"{ip:<16}", style=style)
        graph.append(f" {os_info:<20} {svc_str:<12}", style="dim")
        graph.append(f" {in_conns:<4} {out_conns:<4}", style="cyan")
        graph.append(f" {score:<4}", style=style)
        graph.append(" │\n", style="cyan")

    if len(local_hosts) > 15:
        graph.append(f"│     ... +{len(local_hosts)-15} more local hosts" + " " * 50 + "│\n", style="dim")
    graph.append("└" + "─" * 78 + "┘\n\n", style="cyan")

    # EXTERNAL HOSTS
    if external_hosts:
        graph.append("┌─ EXTERNAL HOSTS ", style="bold yellow")
        graph.append("─" * 61 + "┐\n", style="yellow")
        graph.append("│ ", style="yellow")
        graph.append(f"{'MARKER':<3} {'IP / DOMAIN':<35} {'OS':<18} {'SCR':<4} {'FLOWS':<6}", style="bold")
        graph.append(" │\n", style="yellow")
        graph.append("├" + "─" * 78 + "┤\n", style="yellow")

        for ip, data in external_hosts[:12]:
            score = calculate_threat_score(data)
            creds = len(data.get("creds", []))
            os_info = data.get("os", "?")[:16]

            # Find DNS name
            dns_name = None
            for domain, ips in dns.items():
                if ip in [str(i) for i in ips]:
                    dns_name = domain
                    break
            display = dns_name[:33] if dns_name else ip

            if creds > 0:
                style, marker = "bold #f85149", "*"
            elif score >= 20:
                style, marker = "#d29922", "+"
            else:
                style, marker = "dim", "-"

            flow_count = sum(1 for (s, d) in connections if s == ip or d == ip)

            graph.append("│ ", style="yellow")
            graph.append(f" {marker}  ", style=style)
            graph.append(f"{display:<35}", style=style)
            graph.append(f" {os_info:<18}", style="dim")
            graph.append(f" {score:<4}", style=style)
            graph.append(f" {flow_count:<6}", style="cyan")
            graph.append(" │\n", style="yellow")

        if len(external_hosts) > 12:
            graph.append(f"│     ... +{len(external_hosts)-12} more external hosts" + " " * 46 + "│\n", style="dim")
        graph.append("└" + "─" * 78 + "┘\n\n", style="yellow")

    # TOP CONNECTIONS
    if connections:
        graph.append("┌─ TOP CONNECTIONS ", style="bold #79c0ff")
        graph.append("─" * 60 + "┐\n", style="#79c0ff")
        graph.append("│ ", style="#79c0ff")
        graph.append(f"{'SOURCE':<18} {'DIR':^5} {'DESTINATION':<18} {'PORTS':<15} {'COUNT':<8}", style="bold")
        graph.append(" │\n", style="#79c0ff")
        graph.append("├" + "─" * 78 + "┤\n", style="#79c0ff")

        sorted_conns = sorted(connections.items(), key=lambda x: x[1], reverse=True)[:15]
        for (src, dst), cnt in sorted_conns:
            ports = port_map.get((src, dst), set())
            port_str = ",".join(str(p) for p in sorted(ports)[:3])[:13]

            # Determine if internal<->external
            src_local = src.startswith(('10.', '192.168.', '172.'))
            dst_local = dst.startswith(('10.', '192.168.', '172.'))

            if src_local and not dst_local:
                direction = " >>> "
                style = "#7ee787"
            elif not src_local and dst_local:
                direction = " <<< "
                style = "#f85149"
            else:
                direction = " <-> "
                style = "dim"

            graph.append("│ ", style="#79c0ff")
            graph.append(f" {src:<17}", style="#7ee787" if src_local else "#d29922")
            graph.append(f"{direction}", style=style)
            graph.append(f"{dst:<18}", style="#7ee787" if dst_local else "#d29922")
            graph.append(f" {port_str:<15}", style="dim")
            graph.append(f" {cnt:<8}", style="bold" if cnt >= 10 else "")
            graph.append(" │\n", style="#79c0ff")

        graph.append("└" + "─" * 78 + "┘\n", style="#79c0ff")

    # Legend
    graph.append("\n")
    graph.append("  LEGEND: ", style="bold")
    graph.append("*", style="#f85149")
    graph.append("=Creds  ", style="dim")
    graph.append("o", style="#d29922")
    graph.append("=High  ", style="dim")
    graph.append(".", style="#7ee787")
    graph.append("=Active  ", style="dim")
    graph.append(".", style="dim")
    graph.append("=Low  |  ", style="dim")
    graph.append(">>>", style="#7ee787")
    graph.append("=Outbound  ", style="dim")
    graph.append("<<<", style="#f85149")
    graph.append("=Inbound", style="dim")

    return graph


class PcapIntelApp(App):
    """PCAP-INTEL TAO Operator Interface."""

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("1", "focus_creds", "Creds", priority=True),
        Binding("2", "focus_flows", "Flows", priority=True),
        Binding("3", "focus_dns", "DNS", priority=True),
        Binding("4", "focus_hosts", "Hosts", priority=True),
        Binding("5", "focus_alerts", "Alerts", priority=True),
        Binding("6", "focus_targets", "Targets", priority=True),
        Binding("7", "show_attack_graph", "Attack", priority=True),
        Binding("m", "mark_compromised", "Mark", priority=True),
        Binding("g", "toggle_graph", "Graph", priority=True),
        Binding("r", "refresh_graph", "Refresh", priority=True),
        Binding("f", "toggle_fullscreen", "Detail", priority=True),
        Binding("/", "advanced_filter", "Filter", priority=True),
        Binding("escape", "exit_fullscreen", "Back", priority=True),
        Binding("c", "copy", "Copy", priority=True),
        Binding("e", "export", "Export", priority=True),
        Binding("d", "toggle_debug", "Debug", priority=True),
        Binding("space", "pause", "Pause", priority=True),
        # v2.0: Session persistence
        Binding("ctrl+s", "save_session", "Save", priority=True),
        Binding("ctrl+o", "open_session", "Open", priority=True),
        Binding("O", "open_session", "Open", priority=True),  # Alt: Shift+O (cycle)
        Binding("L", "load_selected_session", "Load", priority=True),  # Load selected
        # v2.0: Timeline
        Binding("t", "toggle_timeline", "Timeline", priority=True),
    ]

    CSS = """
    Screen { background: #0d1117; }
    Header { dock: top; height: 1; background: #161b22; }
    Footer { dock: bottom; height: 1; background: #161b22; }

    #stats {
        dock: top;
        height: 1;
        width: 100%;
        background: #21262d;
        padding: 0 1;
    }

    #main { width: 100%; height: 1fr; }

    /* Row 1: FLOWS + PIVOTS + LIVE */
    #row1 { width: 100%; height: 40%; border-bottom: solid #30363d; }
    /* Row 2: DNS + HOSTS */
    #row2 { width: 100%; height: 35%; border-bottom: solid #30363d; }
    /* Row 3: CREDS + ALERTS (high-value hits) */
    #row3 { width: 100%; height: 25%; }

    #flows-pane { width: 60%; height: 100%; border-right: solid #30363d; }
    #intel-pane { width: 40%; height: 100%; }
    #dns-pane { width: 38%; height: 100%; border-right: solid #30363d; }
    #hosts-pane { width: 62%; height: 100%; }
    #creds-pane { width: 25%; height: 100%; border-right: solid #30363d; }
    #alerts-pane { width: 75%; height: 100%; }

    /* GRAPH OVERLAY */
    #graph-overlay {
        display: none;
        width: 100%;
        height: 100%;
        background: #0d1117;
        layer: graph;
        dock: top;
    }
    #graph-overlay.visible { display: block; }

    #graph-header {
        dock: top;
        height: 0;
        display: none;
    }

    #graph-content {
        width: 100%;
        height: 1fr;
        padding: 1;
        overflow: auto;
    }

    #graph-footer {
        dock: bottom;
        height: 0;
        display: none;
    }

    .pane-title {
        height: 1;
        width: 100%;
        background: #21262d;
        padding: 0 1;
    }

    DataTable { height: 1fr; width: 100%; }
    DataTable:focus { border: tall #388bfd; }
    DataTable > .datatable--header { background: #161b22; color: #58a6ff; }
    DataTable > .datatable--cursor { background: #388bfd; color: white; }
    DataTable > .datatable--even-row { background: #0d1117; }
    DataTable > .datatable--odd-row { background: #161b22; }

    /* FULLSCREEN DETAIL VIEW */
    #detail-overlay {
        display: none;
        width: 100%;
        height: 100%;
        background: #0d1117;
        layer: fullscreen;
        dock: top;
        offset: 0 0;
    }
    #detail-overlay.visible { display: block; }

    #detail-overlay DataTable {
        height: 100%;
        width: 100%;
    }
    #detail-overlay DataTable:focus { border: tall #f85149; }

    #detail-header {
        dock: top;
        height: 1;
        width: 100%;
        background: #f85149;
        color: white;
        text-style: bold;
        padding: 0 1;
    }

    #detail-content {
        width: 100%;
        height: 1fr;
    }

    #detail-left {
        width: 50%;
        height: 100%;
        border-right: solid #30363d;
    }

    #detail-right {
        width: 50%;
        height: 100%;
    }

    #detail-info {
        height: 45%;
        width: 100%;
        border-bottom: solid #30363d;
        padding: 0 1;
        overflow: auto;
    }

    #detail-related {
        height: 55%;
        width: 100%;
    }

    #detail-table { width: 100%; height: 100%; }

    #detail-footer {
        dock: bottom;
        height: 1;
        width: 100%;
        background: #21262d;
        color: #8b949e;
        padding: 0 1;
    }

    RichLog {
        height: 100%;
        width: 100%;
        background: #0d1117;
        padding: 0 1;
        scrollbar-size: 1 1;
    }

    /* DEBUG OVERLAY */
    #debug-overlay {
        display: none;
        width: 100%;
        height: 100%;
        background: #0d1117;
        layer: debug;
    }
    #debug-overlay.visible { display: block; }
    """

    TITLE = "PCAP-INTEL"

    def __init__(self, interface: str = None, pcap_file: str = None, bpf_filter: str = "", debug: bool = False):
        super().__init__()
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.debug_mode = debug

        self.credentials: List[Any] = []
        self.cred_hashes: set = set()
        self.hosts: Dict[str, Dict] = {}  # ip -> {os, services, creds, flows, dns}
        self.dns_resolutions: Dict[str, List] = {}
        self.alerts: List[Dict] = []
        self.flows: Dict[str, Dict] = {}

        # Codename tracking
        self.codenames: Dict[str, tuple] = {}  # ip -> (codename, category, color)
        self.local_subnet = "10.0.0"  # Will be auto-detected

        # Filter mode
        self.filter_ip: Optional[str] = None  # IP to filter on
        self.filter_codename: Optional[str] = None  # Codename display

        # Manual compromise tracking (for hosts pwned without captured creds)
        self.compromised_hosts: set = set()  # Manually marked as compromised

        self.packets = 0
        self.start_time = None
        self.paused = False
        self.fullscreen_active = False
        self.fullscreen_type: Optional[str] = None
        self.graph_mode: int = 0  # 0=none, 1=network, 2=attack
        self._intel_data: List[tuple] = []
        self._last_ui_update = 0
        self._debug_log: List[str] = []
        self._last_error: Optional[str] = None
        self._status_message: Optional[str] = None  # v2.0: Success messages

        # v2.0: Initialize advanced features
        self._init_v2_features()

    def _init_v2_features(self) -> None:
        """Initialize v2.0 features: session persistence, advanced filtering, timeline."""
        # Session storage
        self._session_storage: Optional[SessionStorage] = None
        self._auto_save_task = None

        # Advanced filter
        if HAS_V2_FEATURES and AdvancedFilter:
            self._advanced_filter = AdvancedFilter(
                codename_resolver=lambda ip: self._get_codename(ip)
            )
        else:
            self._advanced_filter = None

        # Timeline panel
        if HAS_V2_FEATURES and TimelinePanel:
            self._timeline = TimelinePanel(
                codename_resolver=lambda ip: self._get_codename(ip),
                local_subnet=self.local_subnet
            )
        else:
            self._timeline = None
        self._timeline_visible = False

    def _start_session_storage(self) -> None:
        """Start session storage with auto-save."""
        if not HAS_V2_FEATURES or not SessionStorage:
            return

        source_type = "pcap" if self.pcap_file else "interface"
        source_name = self.pcap_file or self.interface or "unknown"

        self._session_storage = create_session_storage(
            source_type=source_type,
            source_name=source_name
        )

        # Start auto-save background task
        if self._auto_save_task is None:
            self._auto_save_task = asyncio.create_task(self._auto_save_loop())

    async def _auto_save_loop(self) -> None:
        """Background auto-save every 30 seconds."""
        while True:
            await asyncio.sleep(30)
            try:
                if self._session_storage and self._session_storage.should_auto_save():
                    self._save_session_data()
                    self._log_debug("Auto-saved session")
            except Exception as e:
                self._log_debug(f"Auto-save error: {e}")

    def _save_session_data(self) -> None:
        """Save current session state."""
        if not self._session_storage:
            return

        source_type = "pcap" if self.pcap_file else "interface"
        source_name = self.pcap_file or self.interface or "unknown"

        self._session_storage.save_all(
            source_type=source_type,
            source_name=source_name,
            packets=self.packets,
            hosts=self.hosts,
            flows=self.flows,
            credentials=self.credentials,
            dns_resolutions=self.dns_resolutions,
            alerts=self.alerts,
            compromised_hosts=self.compromised_hosts,
            codenames=self.codenames
        )

    def _feed_to_timeline(self, event_type: str, **kwargs) -> None:
        """Feed event to timeline panel."""
        if not self._timeline:
            return

        if event_type == "flow":
            self._timeline.add_flow(
                src=kwargs.get("src", ""),
                dst=kwargs.get("dst", ""),
                port=kwargs.get("port", 0),
                proto=kwargs.get("proto", "TCP"),
                count=kwargs.get("count", 1)
            )
        elif event_type == "credential":
            cred = kwargs.get("cred")
            if cred:
                self._timeline.add_credential(
                    protocol=cred.protocol,
                    username=cred.username,
                    domain=cred.domain,
                    target_ip=cred.target_ip,
                    target_port=cred.target_port
                )
        elif event_type == "alert":
            alert = kwargs.get("alert", {})
            self._timeline.add_alert(
                severity=alert.get("severity", "info"),
                alert_type=alert.get("type", "unknown"),
                message=alert.get("message", ""),
                src_ip=alert.get("src_ip", ""),
                dst_ip=alert.get("dst_ip", "") or alert.get("target", "")
            )
        elif event_type == "dns":
            self._timeline.add_dns(
                domain=kwargs.get("domain", ""),
                answers=kwargs.get("answers", [])
            )

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="stats")

        with Vertical(id="main"):
            # Row 1: FLOWS + PIVOTS
            with Horizontal(id="row1"):
                with Container(id="flows-pane"):
                    yield Static(Text(" [2] FLOWS ", style="bold #7ee787"), classes="pane-title")
                    yield DataTable(id="flows-table")
                with Container(id="intel-pane"):
                    yield Static(Text(" [6] INTEL ", style="bold #f85149"), classes="pane-title")
                    yield Static(id="intel-content")

            # Row 2: DNS (correlation) + HOSTS (assets)
            with Horizontal(id="row2"):
                with Container(id="dns-pane"):
                    yield Static(Text(" [3] DNS ", style="bold #58a6ff"), classes="pane-title")
                    yield DataTable(id="dns-table")
                with Container(id="hosts-pane"):
                    yield Static(Text(" [4] HOSTS ", style="bold #a371f7"), classes="pane-title")
                    yield DataTable(id="hosts-table")

            # Row 3: CREDS + ALERTS (high-value hits)
            with Horizontal(id="row3"):
                with Container(id="creds-pane"):
                    yield Static(Text(" [1] CREDS ", style="bold #f85149"), classes="pane-title")
                    yield DataTable(id="creds-table")
                with Container(id="alerts-pane"):
                    yield Static(Text(" [5] ALERTS ", style="bold #d29922"), classes="pane-title")
                    yield DataTable(id="alerts-table")

        # Detail overlay
        with Container(id="detail-overlay"):
            yield Static("", id="detail-header")
            with Horizontal(id="detail-content"):
                with Container(id="detail-left"):
                    yield DataTable(id="detail-table")
                with Container(id="detail-right"):
                    yield Static("", id="detail-info")
                    with Container(id="detail-related"):
                        yield RichLog(id="detail-log")
            yield Static(" [ESC/f] Close  [c] Copy  [↑↓] Navigate ", id="detail-footer")

        # Graph overlay (toggle with 'g')
        with Container(id="graph-overlay"):
            yield Static(" ★ NETWORK TOPOLOGY ★ ", id="graph-header")
            yield Static("", id="graph-content")
            yield Static(" [g/7] Network Map  [r] Refresh  [m] Mark Host  [ESC] Close ", id="graph-footer")

        # Debug overlay
        with Container(id="debug-overlay"):
            yield RichLog(id="debug-log")

        yield Footer()

    def on_mount(self) -> None:
        self.start_time = datetime.now()

        # Credentials table
        t = self.query_one("#creds-table", DataTable)
        t.add_columns("PROTO", "USER", "DOMAIN", "TARGET")
        t.cursor_type = "row"
        t.zebra_stripes = True

        # Flows table - full width with codenames
        t = self.query_one("#flows-table", DataTable)
        t.add_columns("DIR", "SOURCE", "DESTINATION", "PORT", "PROTO", "CNT", "LAST")
        t.cursor_type = "row"
        t.zebra_stripes = True

        # DNS table - enhanced with codenames
        t = self.query_one("#dns-table", DataTable)
        t.add_columns("DOMAIN", "CODENAME", "IP")
        t.cursor_type = "row"
        t.zebra_stripes = True

        # Hosts table - TAO red team intel with codenames
        t = self.query_one("#hosts-table", DataTable)
        t.add_columns("CODENAME", "IP", "OS", "PORTS", "CRED", "IN", "OUT", "PIV", "AGE", "SCR")
        t.cursor_type = "row"
        t.zebra_stripes = True

        # Alerts table - add time and source
        t = self.query_one("#alerts-table", DataTable)
        t.add_columns("TIME", "SEV", "TYPE", "SRC", "MESSAGE", "TARGET")
        t.cursor_type = "row"
        t.zebra_stripes = True

        # Detail table
        t = self.query_one("#detail-table", DataTable)
        t.cursor_type = "row"
        t.zebra_stripes = True

        self.query_one("#creds-table", DataTable).focus()
        self._update_stats()  # Show initial stats
        self._log_debug(f"Starting capture: interface={self.interface}, pcap={self.pcap_file}")
        self.run_worker(self._run_pipeline())

    def _log_debug(self, msg: str) -> None:
        """Log debug message."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self._debug_log.append(f"[{ts}] {msg}")
        if len(self._debug_log) > 500:
            self._debug_log = self._debug_log[-500:]
        if self.debug_mode:
            try:
                log = self.query_one("#debug-log", RichLog)
                log.write(f"[dim]{ts}[/] {msg}")
            except:
                pass

    def _get_codename(self, ip: str) -> tuple:
        """Get or create codename for IP."""
        if ip not in self.codenames:
            self.codenames[ip] = get_host_codename(ip, self.local_subnet)
        return self.codenames[ip]

    def _detect_local_subnet(self, ip: str) -> None:
        """Auto-detect local subnet from first local IP seen."""
        if ip.startswith(('10.', '192.168.', '172.')):
            prefix = '.'.join(ip.split('.')[:3])
            if self.local_subnet == "10.0.0" or prefix.startswith('192.168'):
                self.local_subnet = prefix

    def _update_stats(self) -> None:
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        rate = self.packets / elapsed if elapsed > 0 else 0
        stats = self.query_one("#stats", Static)
        t = Text()
        t.append(f" {self.packets:,} pkt ", style="#7ee787")
        t.append(f"({rate:.0f}/s) ", style="dim")
        t.append("│ ", style="#30363d")
        t.append(f"CRED:{len(self.credentials)} ", style="bold #f85149" if self.credentials else "dim")
        t.append(f"FLOW:{len(self.flows)} ", style="#7ee787" if self.flows else "dim")
        t.append(f"DNS:{len(self.dns_resolutions)} ", style="#58a6ff" if self.dns_resolutions else "dim")
        t.append(f"HOST:{len(self.hosts)} ", style="#a371f7" if self.hosts else "dim")
        t.append(f"ALRT:{len(self.alerts)}", style="bold #d29922" if self.alerts else "dim")
        # v2.0: Show advanced filter or simple filter
        if self._advanced_filter and self._advanced_filter.is_active:
            t.append(" │ ", style="#30363d")
            t.append(f"FILTER: {self._advanced_filter.filter_text[:20]}", style="bold white on #a371f7")
        elif self.filter_ip:
            t.append(" │ ", style="#30363d")
            t.append(f"FILTER: {self.filter_codename}", style="bold white on #388bfd")
        # v2.0: Show timeline indicator
        if self._timeline_visible:
            t.append(" │ ", style="#30363d")
            t.append("TIMELINE", style="bold #7ee787")
        if self.paused:
            t.append(" │ PAUSED", style="bold #bf8700")
        if self._last_error:
            t.append(f" │ ERR: {self._last_error[:30]}", style="bold red")
        if self._status_message:
            t.append(f" │ {self._status_message[:30]}", style="bold #7ee787")
            self._status_message = None  # Clear after display
        stats.update(t)

        # Update TAO intel panels every 10 packets
        if self.packets % 10 == 0:
            self._update_intel_panel()

    async def _run_pipeline(self) -> None:
        self._log_debug("Pipeline starting...")
        try:
            pipeline = LivePipeline(
                interface=self.interface,
                pcap_file=self.pcap_file,
                bpf_filter=self.bpf_filter,
                enable_intel=True,
            )
        except Exception as e:
            self._last_error = str(e)
            self._log_debug(f"Pipeline init error: {e}")
            self._update_stats()
            return

        event_count = 0
        try:
            self._log_debug("Starting event stream...")
            async for event in pipeline.stream():
                event_count += 1
                if event_count % 100 == 0:
                    await asyncio.sleep(0)  # Yield to UI

                if self.paused:
                    continue

                try:
                    if event.type == EventType.PACKET:
                        self.packets += 1
                        pkt = event.data
                        # Log auth protocol packets for debugging
                        if pkt.protocol in ("ntlm", "kerberos", "http", "ldap"):
                            auth_fields = {k: v for k, v in pkt.fields.items() if any(x in k for x in ['auth', 'ntlm', 'kerber', 'ldap.simple', 'ldap.name'])}
                            if auth_fields:
                                self._log_debug(f"AUTH-PKT: {pkt.protocol} {pkt.src_ip}->{pkt.dst_ip}:{pkt.dst_port} fields={list(auth_fields.keys())[:5]}")
                        # Update more frequently at start
                        threshold = 25 if self.packets < 500 else 100 if self.packets < 2000 else 500
                        if self.packets - self._last_ui_update >= threshold:
                            self._last_ui_update = self.packets
                            self._update_stats()

                    elif event.type == EventType.CREDENTIAL:
                        self._log_debug(f"CRED-EVENT: {event.data.protocol} user={event.data.username}")
                        self._handle_credential(event.data)

                    elif event.type == EventType.ALERT:
                        self._handle_alert(event.data)

                    elif event.type == EventType.ENTITY:
                        self._handle_entity(event.data)

                except Exception as e:
                    import traceback
                    tb = traceback.format_exc()
                    self._log_debug(f"Event handler error: {e}\n{tb}")
                    self._last_error = str(e)[:50]

        except Exception as e:
            self._last_error = str(e)
            self._log_debug(f"Pipeline stream error: {e}")
        finally:
            self._log_debug(f"Pipeline finished. Events: {event_count}, Packets: {self.packets}")
            self._update_stats()

    def _handle_credential(self, cred) -> None:
        h = cred.hashcat_format or f"{cred.username}@{cred.domain}"
        if h in self.cred_hashes:
            return
        self.cred_hashes.add(h)
        self.credentials.append(cred)
        self._log_debug(f"CRED: {cred.username}@{cred.domain} -> {cred.target_ip}")

        # v2.0: Feed to timeline
        self._feed_to_timeline("credential", cred=cred)

        now = datetime.now()
        # Track by target host
        target = cred.target_ip
        if target:
            existing_creds = 0
            if target not in self.hosts:
                self.hosts[target] = {"os": "?", "services": set(), "creds": [], "flows": [], "dns": None, "first_seen": now}
            else:
                existing_creds = len(self.hosts[target].get("creds", []))

            self.hosts[target]["creds"].append(cred)
            if cred.target_port:
                self.hosts[target]["services"].add(cred.target_port)

            # CREDENTIAL CHAIN ALERT - multiple creds for same host = high value
            if existing_creds > 0:
                target_codename, _, _ = self._get_codename(target)
                chain_alert = {
                    "severity": "CRITICAL",
                    "type": "cred_chain",
                    "message": f"Credential chain: {existing_creds + 1} creds for {target_codename}",
                    "src_ip": "",
                    "dst_ip": target,
                    "target": target,
                    "time": now,
                }
                self.alerts.append(chain_alert)
                self._log_debug(f"CRED-CHAIN: {existing_creds + 1} creds for {target}")

                # Add to alerts table
                if len(self.alerts) <= 100:
                    t = self.query_one("#alerts-table", DataTable)
                    t.add_row(
                        now.strftime("%H:%M:%S"),
                        Text("CRIT", style="bold white on red"),
                        "cred_chain",
                        "",
                        chain_alert["message"][:70],
                        target[:15],
                    )

        if len(self.credentials) <= 200:
            t = self.query_one("#creds-table", DataTable)
            t.add_row(
                Text(cred.protocol.upper()[:6], style="bold #f85149"),
                cred.username[:15] if cred.username else "?",
                cred.domain[:15] if cred.domain else "?",
                f"{cred.target_ip}:{cred.target_port}" if cred.target_ip else "?",
            )
            # Update stats for first few creds
            if len(self.credentials) <= 5:
                self._update_stats()

    def _handle_alert(self, alert) -> None:
        sev = alert.get("severity", "info").upper()
        if sev not in ["CRITICAL", "HIGH", "MEDIUM"]:
            return
        # Add timestamp
        alert["time"] = datetime.now()
        self.alerts.append(alert)
        self._log_debug(f"ALERT: {sev} - {alert.get('type', '?')}: {alert.get('message', '?')[:40]}")

        # v2.0: Feed to timeline
        self._feed_to_timeline("alert", alert=alert)

        # Extract IPs BEFORE conditional (fixes UnboundLocalError when alerts > 100)
        src_ip = alert.get("src_ip") or alert.get("client") or alert.get("source") or ""
        target = alert.get("dst_ip") or alert.get("target") or alert.get("destination") or ""
        if not target:
            # Try to extract from message like "10.0.0.133 -> 89.144.8.38"
            msg = alert.get("message", "")
            if " -> " in msg:
                parts = msg.split(" -> ")
                if len(parts) >= 2:
                    target = parts[1].split()[0][:15]

        if len(self.alerts) <= 100:
            t = self.query_one("#alerts-table", DataTable)
            style = "bold white on red" if sev == "CRITICAL" else "bold #d29922" if sev == "HIGH" else "#d29922"
            time_str = alert["time"].strftime("%H:%M:%S")
            t.add_row(
                time_str,
                Text(sev[:4], style=style),
                alert.get("type", "")[:18],
                src_ip[:14] if src_ip else "",
                alert.get("message", "")[:70],
                target[:15] if target else "",
            )

        # ENRICH: Add alert IPs to hosts
        now = datetime.now()
        for ip in [src_ip, target]:
            if ip and is_valid_ip(ip) and not is_noise_ip(ip):
                if ip not in self.hosts:
                    self.hosts[ip] = {"os": "?", "services": set(), "creds": [], "flows": [], "dns": None, "first_seen": now}
                # Track alert count on host
                if "alert_count" not in self.hosts[ip]:
                    self.hosts[ip]["alert_count"] = 0
                self.hosts[ip]["alert_count"] += 1

        # Refresh intel panel so alerts show in PROTOCOLS/DETECTIONS
        self._update_intel_panel()

    def _handle_entity(self, entity) -> None:
        """Handle entity events from pipeline."""
        etype = getattr(entity, 'type', None)
        if not etype:
            return

        self._log_debug(f"ENTITY: {etype} = {getattr(entity, 'value', '?')[:40]}")

        if etype == "flow":
            self._handle_flow(entity)
        elif etype == "os_fingerprint":
            self._handle_os_fingerprint(entity)
        elif etype == "dns_resolution":
            self._handle_dns(entity)
        elif etype == "dns_query":
            pass  # Ignore queries, only care about resolutions
        elif etype == "service":
            self._handle_service(entity)
        elif etype == "host":
            self._handle_host_entity(entity)

    def _handle_flow(self, entity) -> None:
        """Handle flow entity."""
        # Get flow details (FlowIntel uses .details)
        src = get_entity_attr(entity, "client_ip", "?")
        dst = get_entity_attr(entity, "server_ip", "?")
        port = get_entity_attr(entity, "service_port", "?")
        proto = get_entity_attr(entity, "protocol", "TCP")

        # Auto-detect local subnet from first local IP
        if src != "?" and is_valid_ip(src):
            self._detect_local_subnet(src)

        # Parse from value if details missing
        if src == "?" and hasattr(entity, 'value'):
            # Value format: "192.168.45.173->192.168.154.173:445"
            val = entity.value
            if "->" in val:
                parts = val.split("->")
                src = parts[0]
                if ":" in parts[1]:
                    dst, port = parts[1].rsplit(":", 1)

        # Validate IPs - skip if either is invalid or noise
        if not is_valid_ip(src) or not is_valid_ip(dst):
            return
        # Skip pure multicast flows (both endpoints are noise)
        if is_noise_ip(src) and is_noise_ip(dst):
            return

        flow_key = f"{src}:{dst}:{port}"
        now = datetime.now()
        if flow_key in self.flows:
            self.flows[flow_key]["count"] += 1
            self.flows[flow_key]["last_seen"] = now
        else:
            self.flows[flow_key] = {"src": src, "dst": dst, "port": port, "proto": proto, "count": 1, "first_seen": now, "last_seen": now}

            # Track flow on hosts (only for valid, non-noise IPs)
            for ip in [src, dst]:
                if ip and is_valid_ip(ip) and not is_noise_ip(ip):
                    if ip not in self.hosts:
                        self.hosts[ip] = {"os": "?", "services": set(), "creds": [], "flows": [], "dns": None, "first_seen": now}
                    if flow_key not in self.hosts[ip]["flows"]:
                        self.hosts[ip]["flows"].append(flow_key)

            # ENRICH: Add port as service on DESTINATION host (server)
            if dst and is_valid_ip(dst) and not is_noise_ip(dst) and port:
                try:
                    self.hosts[dst]["services"].add(int(port))
                except:
                    pass

        # v2.0: Feed to timeline
        try:
            port_int = int(port) if port and port != "?" else 0
        except:
            port_int = 0
        self._feed_to_timeline("flow", src=src, dst=dst, port=port_int, proto=proto)

        # Update table periodically
        if len(self.flows) <= 10 or len(self.flows) % 10 == 0:
            self._update_flows_table()
            # Also refresh intel panel every 20 flows
            if len(self.flows) % 20 == 0:
                self._update_intel_panel()

    def _handle_os_fingerprint(self, entity) -> None:
        """Handle OS fingerprint entity."""
        ip = get_entity_attr(entity, "ip", "")
        if not ip:
            return
        # Validate IP
        if not is_valid_ip(ip) or is_noise_ip(ip):
            return
        os_info = getattr(entity, 'value', '?')

        if ip not in self.hosts:
            self.hosts[ip] = {"os": os_info, "services": set(), "creds": [], "flows": [], "dns": None, "first_seen": datetime.now()}
        else:
            self.hosts[ip]["os"] = os_info

        self._update_hosts_table()

    def _handle_dns(self, entity) -> None:
        """Handle DNS resolution entity."""
        domain = getattr(entity, 'value', '')
        answers = get_entity_attr(entity, "answers", [])

        if not domain or not answers:
            return
        if not is_interesting_dns(domain):
            return
        if domain in self.dns_resolutions:
            return

        # Filter answers to only valid, non-noise IPs
        valid_answers = [str(a) for a in answers if is_valid_ip(str(a)) and not is_noise_ip(str(a))]
        if not valid_answers:
            return

        self.dns_resolutions[domain] = valid_answers
        self._log_debug(f"DNS: {domain} -> {valid_answers}")

        # v2.0: Feed to timeline
        self._feed_to_timeline("dns", domain=domain, answers=valid_answers)

        # Cross-reference IPs
        for ip_str in valid_answers:
            if ip_str not in self.hosts:
                self.hosts[ip_str] = {"os": "?", "services": set(), "creds": [], "flows": [], "dns": domain, "first_seen": datetime.now()}
            else:
                self.hosts[ip_str]["dns"] = domain

        # Refresh DNS table with new data
        self._update_dns_table()

    def _handle_service(self, entity) -> None:
        """Handle service entity."""
        # Try to get IP and port from details or parse from value
        ip = get_entity_attr(entity, "ip", "")
        port = get_entity_attr(entity, "port", "")

        # Parse from value if needed (format: "192.168.154.173:445")
        if not ip and hasattr(entity, 'value'):
            val = entity.value
            if ":" in val:
                parts = val.rsplit(":", 1)
                ip = parts[0]
                port = parts[1]

        # Validate IP
        if not is_valid_ip(ip) or is_noise_ip(ip):
            return

        if ip and port:
            if ip not in self.hosts:
                self.hosts[ip] = {"os": "?", "services": set(), "creds": [], "flows": [], "dns": None, "first_seen": datetime.now()}
            try:
                self.hosts[ip]["services"].add(int(port))
            except:
                self.hosts[ip]["services"].add(str(port))

    def _handle_host_entity(self, entity) -> None:
        """Handle host entity (from StreamingEntity)."""
        ip = getattr(entity, 'value', '')
        if not ip:
            return
        # Validate IP - reject garbage
        if not is_valid_ip(ip) or is_noise_ip(ip):
            return
        if ip not in self.hosts:
            self.hosts[ip] = {"os": "?", "services": set(), "creds": [], "flows": [], "dns": None, "first_seen": datetime.now()}
        # Copy any attributes
        if hasattr(entity, 'attributes') and entity.attributes:
            for k, v in entity.attributes.items():
                if k not in self.hosts[ip] or self.hosts[ip].get(k) == "?":
                    self.hosts[ip][k] = v

    def _update_flows_table(self) -> None:
        if not self.flows:
            return
        sorted_flows = sorted(self.flows.items(), key=lambda x: x[1]["count"], reverse=True)
        t = self.query_one("#flows-table", DataTable)
        t.clear()

        # Lateral movement ports (admin protocols)
        LATERAL_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986, 5900, 5901}

        for _, f in sorted_flows[:100]:
            src = f.get('src', '?')
            dst = f.get('dst', '?')
            port = f.get('port', 0)
            count = f.get('count', 0)

            # Apply filter if active
            if self.filter_ip and src != self.filter_ip and dst != self.filter_ip:
                continue

            # Get codenames
            src_codename, src_cat, src_color = self._get_codename(src) if is_valid_ip(src) else (src[:15], "", "dim")
            dst_codename, dst_cat, dst_color = self._get_codename(dst) if is_valid_ip(dst) else (dst[:15], "", "dim")

            # Determine direction with lateral movement detection
            src_local = src.startswith(('10.', '192.168.', '172.'))
            dst_local = dst.startswith(('10.', '192.168.', '172.'))

            # Check if source has credentials (potential lateral movement)
            src_has_creds = src in self.hosts and len(self.hosts[src].get("creds", [])) > 0

            if src_local and not dst_local:
                # Outbound - check for exfiltration indicators
                if port in (443, 53, 80) and count > 50:
                    direction = Text("EGR!", style="bold red")  # Potential exfil
                else:
                    direction = Text("OUT", style="bold #7ee787")
            elif not src_local and dst_local:
                direction = Text("IN", style="bold #f85149")
            elif src_local and dst_local:
                # Internal - check for lateral movement
                if port in LATERAL_PORTS:
                    if src_has_creds:
                        direction = Text("LAT!", style="bold red on yellow")  # Active lateral w/ creds
                    else:
                        direction = Text("LAT", style="bold #f0883e")  # Potential lateral
                else:
                    direction = Text("LAN", style="cyan")
            else:
                direction = Text("EXT", style="dim")

            # Guess protocol from port
            proto = {443: 'HTTPS', 80: 'HTTP', 22: 'SSH', 21: 'FTP', 53: 'DNS',
                     445: 'SMB', 3389: 'RDP', 5353: 'mDNS', 1900: 'SSDP',
                     25: 'SMTP', 110: 'POP3', 143: 'IMAP', 389: 'LDAP',
                     135: 'RPC', 139: 'NBT', 5985: 'WinRM', 5986: 'WinRMS',
                     88: 'KERB', 636: 'LDAPS'}.get(port, '')
            last = f.get('last_seen')
            last_str = last.strftime('%H:%M:%S') if last else ''

            t.add_row(
                direction,
                Text(src_codename, style=src_color),
                Text(dst_codename, style=dst_color),
                str(port),
                proto,
                str(count),
                last_str,
            )

    def _update_hosts_table(self) -> None:
        if not self.hosts:
            return
        # Sort by threat score
        sorted_hosts = sorted(
            self.hosts.items(),
            key=lambda x: calculate_threat_score(x[1]),
            reverse=True
        )
        t = self.query_one("#hosts-table", DataTable)
        t.clear()
        now = datetime.now()
        internal_prefixes = ('10.', '192.168.', '172.')

        for ip, data in sorted_hosts[:50]:
            # Skip if filtering and this host doesn't match
            if self.filter_ip and ip != self.filter_ip:
                continue

            # Get codename for this host
            codename, category, color = self._get_codename(ip)

            ports = data.get("services", set())
            ports_str = ",".join(str(s) for s in sorted(ports)[:5]) if ports else ""
            os_str = data.get("os", "?")[:12]
            cred_count = len(data.get("creds", []))
            score = calculate_threat_score(data)

            # Detect high-value target for icon prefix (only HVT gets icons)
            hvt_icon, _ = get_hvt_icon(ports)

            # Count inbound/outbound connections
            in_count = sum(1 for f in self.flows.values() if f.get("dst") == ip)
            out_count = sum(1 for f in self.flows.values() if f.get("src") == ip)

            # Calculate PIVOT SCORE: cred_count * outbound_internal_flows
            outbound_internal = sum(1 for f in self.flows.values()
                                   if f.get("src") == ip
                                   and f.get("dst", "").startswith(internal_prefixes))
            pivot_score = cred_count * max(outbound_internal, 1) if cred_count else 0

            # Calculate AGE (time since first seen)
            first_seen = data.get("first_seen")
            if first_seen:
                age_secs = (now - first_seen).total_seconds()
                if age_secs < 60:
                    age_str = f"{int(age_secs)}s"
                elif age_secs < 3600:
                    age_str = f"{int(age_secs/60)}m"
                else:
                    age_str = f"{int(age_secs/3600)}h"
            else:
                age_str = "?"

            # Pivot score styling
            is_manually_compromised = ip in self.compromised_hosts
            if is_manually_compromised and not cred_count:
                pivot_score = max(outbound_internal, 1)

            if pivot_score >= 10:
                piv_style = "bold red on yellow"
            elif pivot_score >= 5:
                piv_style = "bold #f85149"
            elif pivot_score > 0:
                piv_style = "#d29922"
            else:
                piv_style = "dim"

            # Codename display with HVT icon + compromise indicators
            hvt_prefix = hvt_icon if hvt_icon else ""
            if is_manually_compromised and cred_count:
                codename_display = f"{hvt_prefix}[P]*{codename}"
                codename_style = "bold red on yellow"
            elif is_manually_compromised:
                codename_display = f"{hvt_prefix}[P]{codename}"
                codename_style = "bold red"
            elif cred_count:
                codename_display = f"{hvt_prefix}★{codename}"
                codename_style = "bold #f85149"
            elif cat == "HVT":
                codename_display = f"{hvt_prefix}{codename}"
                codename_style = "bold #f0883e"
            else:
                codename_display = codename
                codename_style = f"bold {color}"

            # CRED column
            if is_manually_compromised and cred_count:
                cred_display = Text(f"{cred_count}+P", style="bold red on yellow")
            elif is_manually_compromised:
                cred_display = Text("P", style="bold red")
            elif cred_count:
                cred_display = Text(str(cred_count), style="bold red")
            else:
                cred_display = Text("", style="dim")

            t.add_row(
                Text(codename_display[:20], style=codename_style),
                ip,
                os_str,
                ports_str[:12],
                cred_display,
                Text(str(in_count), style="#f85149") if in_count else "",
                Text(str(out_count), style="#7ee787") if out_count else "",
                Text(str(pivot_score), style=piv_style) if pivot_score else "",
                Text(age_str, style="dim"),
                Text(str(score), style=color),
            )

    def _update_dns_table(self) -> None:
        """Refresh DNS table with all resolutions and codenames."""
        if not self.dns_resolutions:
            return
        t = self.query_one("#dns-table", DataTable)
        t.clear()
        for domain, ips in list(self.dns_resolutions.items())[:100]:
            # Apply filter if active
            if self.filter_ip:
                if not any(ip == self.filter_ip for ip in ips):
                    continue

            # Get first IP for codename display
            first_ip = str(ips[0]) if ips else "?"
            codename, _, color = self._get_codename(first_ip) if first_ip != "?" else ("?", "", "dim")

            # Format IPs (show first + count of others)
            ip_str = first_ip
            if len(ips) > 1:
                ip_str += f" +{len(ips)-1}"

            t.add_row(
                domain[:28],
                Text(codename, style=color),
                ip_str,
            )

    # Port to service name mapping (comprehensive)
    PORT_TO_SVC = {
        21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        69: "TFTP", 80: "HTTP", 88: "KERB", 110: "POP3", 111: "RPC", 123: "NTP",
        135: "MSRPC", 137: "NETBIOS", 138: "NETBIOS", 139: "NETBIOS", 143: "IMAP",
        161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "KERB",
        500: "IKE", 514: "SYSLOG", 515: "LPD", 520: "RIP", 523: "IBM-DB2", 548: "AFP",
        554: "RTSP", 587: "SMTP", 631: "IPP", 636: "LDAPS", 873: "RSYNC", 902: "VMW",
        993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OVPN", 1433: "MSSQL",
        1434: "MSSQL", 1521: "ORACLE", 1723: "PPTP", 1883: "MQTT", 1900: "SSDP",
        2049: "NFS", 2082: "CPANEL", 2083: "CPANEL", 2181: "ZOOK", 2375: "DOCKER",
        2376: "DOCKER", 3000: "DEV", 3306: "MYSQL", 3389: "RDP", 3690: "SVN",
        4369: "EPMD", 4443: "HTTPS", 5000: "DEV", 5060: "SIP", 5222: "XMPP",
        5351: "NAT-PMP", 5353: "mDNS", 5355: "LLMNR", 5432: "PGSQL", 5672: "AMQP",
        5900: "VNC", 5901: "VNC", 5985: "WINRM", 5986: "WINRMS", 6379: "REDIS",
        6443: "K8S", 6666: "IRC", 6667: "IRC", 7001: "WEBLOG", 8000: "HTTP",
        8008: "HTTP", 8080: "HTTP", 8081: "HTTP", 8443: "HTTPS", 8888: "HTTP",
        9000: "PHP", 9090: "PROM", 9200: "ELASTIC", 9418: "GIT", 9999: "DEV",
        11211: "MEMCACHE", 15672: "RABBIT", 21027: "SYNC", 22000: "SYNC",
        24800: "SYNC", 27017: "MONGO", 27018: "MONGO", 49152: "DCOM", 57621: "SPOT"
    }

    def _get_service_name(self, port) -> str:
        """Get service name for a port."""
        try:
            port_int = int(port)
            return self.PORT_TO_SVC.get(port_int, str(port_int))
        except:
            return str(port)

    def _update_intel_panel(self) -> None:
        """Update INTEL panel - Network traffic intel for red team ops."""
        try:
            self._do_update_intel_panel()
        except Exception as e:
            try:
                self.query_one("#intel-content", Static).update(f"[red]ERROR: {e}[/]")
            except:
                pass

    def _do_update_intel_panel(self) -> None:
        """Actual intel panel update - Aggregates ALL data sources."""
        # v2.0: Show timeline instead of intel when toggled
        if self._timeline_visible and self._timeline:
            self._render_timeline_panel()
            return

        lines = []

        # === AGGREGATE: Unified service metrics ===
        # Combines: flows, host services, alerts into single view
        # Key: (port, service_name) -> {flows: N, hosts: set()}

        services = {}  # (port, name) -> {"flows": int, "hosts": set()}

        # From FLOWS - count traffic per service
        for f in self.flows.values():
            port = f.get("port", 0)
            if port:
                svc = self._get_service_name(port)
                key = (port, svc)
                if key not in services:
                    services[key] = {"flows": 0, "hosts": set()}
                services[key]["flows"] += 1

        # From HOSTS - track which hosts have each service
        for ip, data in self.hosts.items():
            for port in data.get("services", set()):
                svc = self._get_service_name(port)
                key = (port, svc)
                if key not in services:
                    services[key] = {"flows": 0, "hosts": set()}
                services[key]["hosts"].add(ip)

        # From CREDS - track compromised services
        cred_ports = set()
        for c in self.credentials:
            if c.target_port:
                cred_ports.add(c.target_port)

        # === DISPLAY ===

        # Get panel width for bar scaling
        try:
            panel = self.query_one("#intel-content", Static)
            width = panel.size.width if panel.size.width > 0 else 35
        except:
            width = 35

        # Bar width = width - prefix (port 6 + svc 8 + flows 4 + hosts 3 + spaces 4)
        bar_width = max(4, width - 26)

        # Summary line
        lines.append(f"[bold]{len(self.hosts)}[/]H [bold]{len(self.flows)}[/]F [bold]{len(self.credentials)}[/]C")
        lines.append(f"[dim]{'─' * min(width, 40)}[/]")

        # === SERVICES (unified view) ===
        lines.append("[bold cyan]═ SERVICES ═[/]")
        if services:
            # Sort by total activity (flows + host count)
            sorted_svcs = sorted(
                services.items(),
                key=lambda x: x[1]["flows"] + len(x[1]["hosts"]) * 10,
                reverse=True
            )[:15]

            max_flows = max((s["flows"] for _, s in sorted_svcs), default=1) or 1

            for (port, svc), data in sorted_svcs:
                flows = data["flows"]
                hosts = len(data["hosts"])
                compromised = "[red]★[/]" if port in cred_ports else ""

                # Bar proportional to flow count
                bar_len = int((flows / max_flows) * bar_width) if max_flows > 0 else 0
                bar = "█" * bar_len

                lines.append(f":{port:<5} {svc[:8]:<8} {flows:>3}f {hosts:>2}h [dim]{bar}[/]{compromised}")
        else:
            lines.append("[dim]Collecting...[/]")

        content = "\n".join(lines)
        self.query_one("#intel-content", Static).update(render_markup(content))

    def _render_timeline_panel(self) -> None:
        """Render behavioral timeline in intel panel (v2.0) - full width."""
        lines = []
        summary = self._timeline.get_summary()

        # Get panel width
        try:
            panel = self.query_one("#intel-content", Static)
            width = panel.size.width if panel.size.width > 0 else 50
        except:
            width = 50

        # Stats
        crit = summary.get('critical_count', 0)
        high = summary.get('high_count', 0)
        lat = summary.get('lateral_count', 0)
        creds = summary.get('credential_count', 0)
        beacons = summary.get('beacon_count', 0)
        total = summary.get('total_events', 0)

        # Header with stats inline
        stats = f"{total}ev"
        if crit:
            stats += f" [bold red]{crit}![/]"
        if high:
            stats += f" [#ffa657]{high}▲[/]"
        if lat:
            stats += f" [#ffa657]{lat}L[/]"
        if creds:
            stats += f" [#f85149]{creds}C[/]"
        if beacons:
            stats += f" [#a371f7]{beacons}B[/]"

        lines.append(f"[bold #7ee787]═ TIMELINE[/] {stats}")
        lines.append(f"[dim]{'─' * width}[/]")

        # Column layout - fill full width
        col_time = 8
        col_sev = 2
        col_type = 5
        col_flow = width - col_time - col_sev - col_type - 3  # remaining space

        # Events
        max_events = 12
        recent = list(reversed(self._timeline.events[-max_events:])) if self._timeline.events else []

        for event in recent:
            ts = event.timestamp.strftime("%H:%M:%S")

            # Severity
            if event.severity == "critical":
                sev = "[bold red]![/]"
            elif event.severity == "high":
                sev = "[#ffa657]▲[/]"
            else:
                sev = "[dim]·[/]"

            # Type with color
            etype = event.activity_type.value[:4].upper()
            tcol = {"CRED": "#f85149", "LATE": "#ffa657", "C2_B": "#a371f7",
                    "EXFI": "#d29922", "ALER": "#f85149", "DNS": "#58a6ff"}.get(etype, "dim")

            # Flow: src→dst:port - USE FULL REMAINING WIDTH
            src = (event.codenames[0] or event.src_ip or "─")[:12]
            dst = (event.codenames[1] or event.dst_ip or "─")[:12]
            port = self._timeline.SERVICE_MAP.get(event.port, str(event.port) if event.port else "")[:6]

            flow = f"{src}→{dst}"
            if port:
                flow += f":{port}"
            flow = flow[:col_flow].ljust(col_flow)  # Pad to fill width

            lines.append(f"[dim]{ts}[/] {sev} [{tcol}]{etype:<4}[/] {flow}")

        if not recent:
            lines.append("[dim italic]  Waiting for events...[/]")

        content = "\n".join(lines)
        self.query_one("#intel-content", Static).update(render_markup(content))

    def _get_focused_table_id(self) -> Optional[str]:
        for tid in ["#creds-table", "#flows-table", "#dns-table", "#hosts-table", "#alerts-table"]:
            try:
                if self.query_one(tid, DataTable).has_focus:
                    return tid
            except:
                pass
        return None

    # ===== ENRICHED DETAIL VIEW =====

    def _show_detail(self, title: str, columns: List[str], rows: List[tuple], info_text, related_lines: List[str], selected_idx: int = 0) -> None:
        """Show enriched detail view."""
        self.query_one("#detail-header", Static).update(f" ★ {title} ★ ")

        t = self.query_one("#detail-table", DataTable)
        t.clear(columns=True)
        for col in columns:
            t.add_column(col)
        for row in rows:
            t.add_row(*row)

        self.query_one("#detail-info", Static).update(info_text)

        log = self.query_one("#detail-log", RichLog)
        log.clear()
        for line in related_lines:
            # Render markup if line contains Rich markup tags
            if '[' in line and ']' in line:
                log.write(render_markup(line))
            else:
                log.write(line)

        self.query_one("#detail-overlay").add_class("visible")
        self.fullscreen_active = True
        t.focus()

        # Move cursor to selected row
        if rows and selected_idx < len(rows):
            t.move_cursor(row=selected_idx)

    def _hide_detail(self) -> None:
        self.query_one("#detail-overlay").remove_class("visible")
        self.fullscreen_active = False
        self.fullscreen_type = None
        self.query_one("#creds-table", DataTable).focus()

    @on(DataTable.RowHighlighted, "#detail-table")
    def on_detail_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Update detail panels when row is highlighted in fullscreen detail table."""
        idx = event.cursor_row
        self._log_debug(f"DETAIL ROW: row={idx} fs_active={self.fullscreen_active} fs_type={self.fullscreen_type}")

        if not self.fullscreen_active or not self.fullscreen_type:
            return

        if idx is None:
            return

        self._log_debug(f"DETAIL UPDATE: type={self.fullscreen_type} idx={idx}")

        if self.fullscreen_type == "creds":
            self._update_cred_detail(idx)
        elif self.fullscreen_type == "flows":
            self._update_flow_detail(idx)
        elif self.fullscreen_type == "dns":
            self._update_dns_detail(idx)
        elif self.fullscreen_type == "hosts":
            self._update_host_detail(idx)
        elif self.fullscreen_type == "alerts":
            self._update_alert_detail(idx)
        elif self.fullscreen_type == "intel":
            self._update_intel_detail(idx)

    def _enrich_credential(self, idx: int) -> None:
        if idx >= len(self.credentials):
            return
        cred = self.credentials[idx]
        target_codename, _, target_color = self._get_codename(cred.target_ip) if cred.target_ip else ("?", "", "dim")

        cols = ["#", "PROTO", "USER", "DOMAIN", "TARGET", "HASH"]
        rows = []
        for i, c in enumerate(self.credentials):
            h = c.hashcat_format or "-"
            style = "bold #f85149" if i == idx else ""
            tgt_cn, _, _ = self._get_codename(c.target_ip) if c.target_ip else ("?", "", "")
            rows.append((
                str(i+1),
                Text(c.protocol.upper() if c.protocol else "?", style=style),
                c.username or "?",
                c.domain or "?",
                tgt_cn,
                h[:50] + "..." if len(h) > 50 else h,
            ))

        info = Text()
        info.append("═══ CREDENTIAL CAPTURED ═══\n\n", style="bold #f85149")
        info.append("Protocol: ", style="dim")
        info.append(f"{cred.protocol.upper() if cred.protocol else '?'}\n", style="bold")
        info.append("Username: ", style="dim")
        info.append(f"{cred.username or '?'}\n", style="bold #7ee787")
        info.append("Domain: ", style="dim")
        info.append(f"{cred.domain or '?'}\n", style="bold")

        # Show password if captured (plaintext creds like HTTP Basic, LDAP Simple)
        cred_data = cred.credential_data if hasattr(cred, 'credential_data') and cred.credential_data else {}
        if cred_data.get("password"):
            info.append("Password: ", style="dim")
            info.append(f"{cred_data['password']}\n", style="bold red on yellow")
        if cred_data.get("token"):
            info.append("Token: ", style="dim")
            info.append(f"{cred_data['token'][:50]}...\n" if len(str(cred_data['token'])) > 50 else f"{cred_data['token']}\n", style="bold #f85149")

        info.append("\n═══ TARGET ═══\n", style="bold yellow")
        info.append("Codename: ", style="dim")
        info.append(f"{target_codename}\n", style=f"bold {target_color}")
        info.append("IP: ", style="dim")
        info.append(f"{cred.target_ip}:{cred.target_port}\n", style="bold #58a6ff")

        if cred.target_ip and cred.target_ip in self.hosts:
            h = self.hosts[cred.target_ip]
            info.append("OS: ", style="dim")
            info.append(f"{h.get('os', '?')}\n", style="bold")

        if cred.hashcat_format:
            info.append("\n═══ HASHCAT ATTACK ═══\n", style="bold yellow")
            info.append(f"Mode: {cred.hashcat_mode or '5600'}\n", style="dim")
            info.append("Command:\n", style="dim")
            info.append(f"hashcat -m {cred.hashcat_mode or 5600} hash.txt wordlist.txt\n", style="#7ee787")

        related = ["[bold cyan]═══ ATTACK INTELLIGENCE ═══[/]"]

        same_target = [c for c in self.credentials if c.target_ip == cred.target_ip and c != cred]
        if same_target:
            related.append(f"\n[red]★ OTHER CREDS FOR {target_codename} ({len(same_target)}):[/]")
            for c in same_target[:5]:
                related.append(f"  • {c.protocol.upper()}: {c.username}@{c.domain}")

        target_flows = [f for k, f in self.flows.items() if f.get("dst") == cred.target_ip]
        if target_flows:
            related.append(f"\n[yellow]Network activity to target ({len(target_flows)} flows):[/]")
            for f in sorted(target_flows, key=lambda x: x.get("count", 0), reverse=True)[:5]:
                src_cn, _, _ = self._get_codename(f.get('src', '?'))
                related.append(f"  • {src_cn} → :{f.get('port', '?')} ({f.get('count', 0)}x)")

        if cred.target_ip and cred.target_ip in self.hosts:
            h = self.hosts[cred.target_ip]
            svcs = h.get('services', set())
            if svcs:
                related.append(f"\n[cyan]Attack surface (open ports):[/]")
                related.append(f"  • {', '.join(str(s) for s in sorted(svcs))}")

        if cred.hashcat_format:
            related.append(f"\n[magenta]Hash for cracking:[/]")
            hf = cred.hashcat_format
            # Split long hash for display
            for i in range(0, len(hf), 70):
                related.append(f"  {hf[i:i+70]}")

        self.fullscreen_type = "creds"
        self._show_detail(f"CREDENTIAL: {cred.username}@{cred.domain} → {target_codename}", cols, rows, info, related, selected_idx=idx)

    def _update_cred_detail(self, idx: int) -> None:
        if idx >= len(self.credentials):
            return
        cred = self.credentials[idx]
        target_codename, _, target_color = self._get_codename(cred.target_ip) if cred.target_ip else ("?", "", "dim")
        target_role = self._detect_role(cred.target_ip) if cred.target_ip else ""

        self.query_one("#detail-header", Static).update(f" ★ CREDENTIAL: {cred.username}@{cred.domain} → {target_codename} ★ ")

        info = Text()
        info.append("═══ CREDENTIAL CAPTURED ═══\n\n", style="bold #f85149")
        info.append("Protocol: ", style="dim")
        info.append(f"{cred.protocol.upper() if cred.protocol else '?'}\n", style="bold")
        info.append("Username: ", style="dim")
        info.append(f"{cred.username or '?'}\n", style="bold #7ee787")
        info.append("Domain: ", style="dim")
        info.append(f"{cred.domain or '?'}\n", style="bold")

        # Show password if captured (plaintext creds like HTTP Basic, LDAP Simple)
        cred_data = cred.credential_data if hasattr(cred, 'credential_data') and cred.credential_data else {}
        if cred_data.get("password"):
            info.append("Password: ", style="dim")
            info.append(f"{cred_data['password']}\n", style="bold red on yellow")
        if cred_data.get("token"):
            info.append("Token: ", style="dim")
            info.append(f"{cred_data['token'][:50]}...\n" if len(str(cred_data['token'])) > 50 else f"{cred_data['token']}\n", style="bold #f85149")

        info.append("\n═══ TARGET ═══\n", style="bold yellow")
        info.append("Codename: ", style="dim")
        info.append(f"{target_codename}\n", style=f"bold {target_color}")
        info.append("IP: ", style="dim")
        info.append(f"{cred.target_ip}:{cred.target_port}\n", style="bold #58a6ff")
        if target_role:
            info.append("Role: ", style="dim")
            info.append(f"{target_role}\n", style="bold cyan")
        if cred.target_ip and cred.target_ip in self.hosts:
            h = self.hosts[cred.target_ip]
            info.append("OS: ", style="dim")
            info.append(f"{h.get('os', '?')}\n", style="bold")

        if cred.hashcat_format:
            info.append("\n═══ HASHCAT ATTACK ═══\n", style="bold yellow")
            info.append(f"Mode: {cred.hashcat_mode or '5600'}\n", style="dim")
            info.append("Command:\n", style="dim")
            info.append(f"hashcat -m {cred.hashcat_mode or 5600} hash.txt wordlist.txt\n", style="#7ee787")

        self.query_one("#detail-info", Static).update(info)

        log = self.query_one("#detail-log", RichLog)
        log.clear()
        log.write(render_markup("[bold cyan]═══ ATTACK INTELLIGENCE ═══[/]"))

        same_target = [c for c in self.credentials if c.target_ip == cred.target_ip and c != cred]
        if same_target:
            log.write(render_markup(f"\n[red]★ OTHER CREDS FOR {target_codename} ({len(same_target)}):[/]"))
            for c in same_target[:5]:
                log.write(f"  • {c.protocol.upper()}: {c.username}@{c.domain}")

        target_flows = [f for k, f in self.flows.items() if f.get("dst") == cred.target_ip]
        if target_flows:
            log.write(render_markup(f"\n[yellow]Network activity to target ({len(target_flows)} flows):[/]"))
            for f in sorted(target_flows, key=lambda x: x.get("count", 0), reverse=True)[:5]:
                src_cn, _, _ = self._get_codename(f.get('src', '?'))
                log.write(f"  • {src_cn} → :{f.get('port', '?')} ({f.get('count', 0)}x)")

        if cred.target_ip and cred.target_ip in self.hosts:
            h = self.hosts[cred.target_ip]
            svcs = h.get('services', set())
            if svcs:
                log.write(render_markup(f"\n[cyan]Attack surface (open ports):[/]"))
                log.write(f"  • {', '.join(str(s) for s in sorted(svcs))}")

        if cred.hashcat_format:
            log.write(render_markup(f"\n[magenta]Hash for cracking:[/]"))
            hf = cred.hashcat_format
            for i in range(0, len(hf), 70):
                log.write(f"  {hf[i:i+70]}")

    def _detect_role(self, ip: str) -> str:
        """Stub - role detection removed. Returns empty string."""
        return ""

    def _enrich_flow(self, idx: int) -> None:
        sorted_flows = sorted(self.flows.items(), key=lambda x: x[1].get("count", 0), reverse=True)
        if idx >= len(sorted_flows):
            return
        flow_key, flow = sorted_flows[idx]

        src_ip = flow.get("src", "?")
        dst_ip = flow.get("dst", "?")
        src_cn, src_cat, src_color = self._get_codename(src_ip) if src_ip != "?" else ("?", "", "dim")
        dst_cn, dst_cat, dst_color = self._get_codename(dst_ip) if dst_ip != "?" else ("?", "", "dim")

        cols = ["#", "SOURCE", "→", "DESTINATION", "PORT", "COUNT"]
        rows = []
        for i, (k, f) in enumerate(sorted_flows):
            style = "bold #7ee787" if i == idx else ""
            s_cn, _, s_col = self._get_codename(f.get("src", "?"))
            d_cn, _, d_col = self._get_codename(f.get("dst", "?"))
            rows.append((
                str(i+1),
                Text(s_cn, style=f"bold {s_col}" if i == idx else s_col),
                "→",
                Text(d_cn, style=d_col),
                str(f.get("port", "?")),
                str(f.get("count", 0)),
            ))

        info = Text()
        info.append("═══ NETWORK FLOW ═══\n\n", style="bold cyan")
        info.append("Source: ", style="dim")
        info.append(f"{src_cn}", style=f"bold {src_color}")
        info.append(f" ({src_ip})\n", style="dim")
        src_role = self._detect_role(src_ip)
        if src_role:
            info.append("  Role: ", style="dim")
            info.append(f"{src_role}\n", style="bold cyan")
        info.append("\nDestination: ", style="dim")
        info.append(f"{dst_cn}", style=f"bold {dst_color}")
        info.append(f" ({dst_ip})\n", style="dim")
        dst_role = self._detect_role(dst_ip)
        if dst_role:
            info.append("  Role: ", style="dim")
            info.append(f"{dst_role}\n", style="bold cyan")
        info.append("\nPort: ", style="dim")
        info.append(f"{flow.get('port', '?')}\n", style="bold")
        info.append("Protocol: ", style="dim")
        info.append(f"{flow.get('proto', 'TCP').upper()}\n", style="bold")
        info.append("Activity: ", style="dim")
        info.append(f"{flow.get('count', 0)} events\n", style="bold yellow")
        if flow.get("last_seen"):
            info.append("Last Seen: ", style="dim")
            info.append(f"{flow['last_seen'].strftime('%H:%M:%S')}\n", style="bold")

        related = ["[bold cyan]═══ ATTACK INTELLIGENCE ═══[/]"]

        # Credentials for destination (target)
        flow_creds = [c for c in self.credentials if c.target_ip == dst_ip]
        if flow_creds:
            related.append(f"\n[bold red]★ CREDENTIALS FOR {dst_cn} ({len(flow_creds)}):[/]")
            for c in flow_creds[:5]:
                related.append(f"  • {c.protocol.upper()}: {c.username}@{c.domain}")

        # DNS resolution
        for label, ip, cn in [("Source", src_ip, src_cn), ("Dest", dst_ip, dst_cn)]:
            for domain, ips in self.dns_resolutions.items():
                if ip in [str(i) for i in ips]:
                    related.append(f"\n[cyan]DNS for {cn}: {domain}[/]")
                    break

        # Host intel for both endpoints
        for label, ip, cn, color in [("Source", src_ip, src_cn, src_color), ("Destination", dst_ip, dst_cn, dst_color)]:
            if ip and ip in self.hosts:
                h = self.hosts[ip]
                role = self._detect_role(ip)
                related.append(f"\n[{color}]{label}: {cn}[/] ({ip})")
                if role:
                    related.append(f"  • Role: [bold]{role}[/]")
                if h.get("os") and h["os"] != "?":
                    related.append(f"  • OS: {h['os']}")
                svcs = h.get("services", set())
                if svcs:
                    related.append(f"  • Ports: {', '.join(str(s) for s in sorted(svcs)[:8])}")
                if h.get("creds"):
                    related.append(f"  • [red]★ {len(h['creds'])} CREDS CAPTURED[/]")
                # Alert count
                alert_count = sum(1 for a in self.alerts if a.get("src_ip") == ip or a.get("dst_ip") == ip or a.get("target") == ip)
                if alert_count:
                    related.append(f"  • [yellow]⚠ {alert_count} alerts[/]")

        self.fullscreen_type = "flows"
        self._show_detail(f"FLOW: {src_cn} → {dst_cn}:{flow.get('port', '?')}", cols, rows, info, related, selected_idx=idx)

    def _update_flow_detail(self, idx: int) -> None:
        sorted_flows = sorted(self.flows.items(), key=lambda x: x[1].get("count", 0), reverse=True)
        if idx >= len(sorted_flows):
            return
        flow_key, flow = sorted_flows[idx]

        src_ip = flow.get("src", "?")
        dst_ip = flow.get("dst", "?")
        src_cn, _, src_color = self._get_codename(src_ip) if src_ip != "?" else ("?", "", "dim")
        dst_cn, _, dst_color = self._get_codename(dst_ip) if dst_ip != "?" else ("?", "", "dim")

        self.query_one("#detail-header", Static).update(f" ★ FLOW: {src_cn} → {dst_cn}:{flow.get('port', '?')} ★ ")

        info = Text()
        info.append("═══ NETWORK FLOW ═══\n\n", style="bold cyan")
        info.append("Source: ", style="dim")
        info.append(f"{src_cn}", style=f"bold {src_color}")
        info.append(f" ({src_ip})\n", style="dim")
        src_role = self._detect_role(src_ip)
        if src_role:
            info.append("  Role: ", style="dim")
            info.append(f"{src_role}\n", style="bold cyan")
        info.append("\nDestination: ", style="dim")
        info.append(f"{dst_cn}", style=f"bold {dst_color}")
        info.append(f" ({dst_ip})\n", style="dim")
        dst_role = self._detect_role(dst_ip)
        if dst_role:
            info.append("  Role: ", style="dim")
            info.append(f"{dst_role}\n", style="bold cyan")
        info.append("\nPort: ", style="dim")
        info.append(f"{flow.get('port', '?')}\n", style="bold")
        info.append("Protocol: ", style="dim")
        info.append(f"{flow.get('proto', 'TCP').upper()}\n", style="bold")
        info.append("Activity: ", style="dim")
        info.append(f"{flow.get('count', 0)} events\n", style="bold yellow")
        if flow.get("last_seen"):
            info.append("Last Seen: ", style="dim")
            info.append(f"{flow['last_seen'].strftime('%H:%M:%S')}\n", style="bold")

        self.query_one("#detail-info", Static).update(info)

        log = self.query_one("#detail-log", RichLog)
        log.clear()
        log.write(render_markup("[bold cyan]═══ ATTACK INTELLIGENCE ═══[/]"))

        # Credentials for destination
        flow_creds = [c for c in self.credentials if c.target_ip == dst_ip]
        if flow_creds:
            log.write(render_markup(f"\n[bold red]★ CREDENTIALS FOR {dst_cn} ({len(flow_creds)}):[/]"))
            for c in flow_creds[:5]:
                log.write(f"  • {c.protocol.upper()}: {c.username}@{c.domain}")

        # DNS resolution
        for label, ip, cn in [("Source", src_ip, src_cn), ("Dest", dst_ip, dst_cn)]:
            for domain, ips in self.dns_resolutions.items():
                if ip in [str(i) for i in ips]:
                    log.write(render_markup(f"\n[cyan]DNS for {cn}: {domain}[/]"))
                    break

        # Host intel
        for label, ip, cn, color in [("Source", src_ip, src_cn, src_color), ("Destination", dst_ip, dst_cn, dst_color)]:
            if ip and ip in self.hosts:
                h = self.hosts[ip]
                role = self._detect_role(ip)
                log.write(render_markup(f"\n[{color}]{label}: {cn}[/]"))
                if role:
                    log.write(f"  • Role: {role}")
                if h.get("os") and h["os"] != "?":
                    log.write(f"  • OS: {h['os']}")
                svcs = h.get("services", set())
                if svcs:
                    log.write(f"  • Ports: {', '.join(str(s) for s in sorted(svcs)[:8])}")
                if h.get("creds"):
                    log.write(render_markup(f"  • [red]★ {len(h['creds'])} CREDS CAPTURED[/]"))

    def _enrich_dns(self, idx: int) -> None:
        dns_list = list(self.dns_resolutions.items())
        if idx >= len(dns_list):
            return
        domain, ips = dns_list[idx]

        cols = ["#", "DOMAIN", "CODENAME", "IP"]
        rows = []
        for i, (d, answers) in enumerate(dns_list):
            style = "bold #58a6ff" if i == idx else ""
            # Get codename for first resolved IP
            first_ip = str(answers[0]) if answers else "?"
            cn, _, color = self._get_codename(first_ip) if first_ip != "?" else ("?", "", "dim")
            rows.append((
                str(i+1),
                Text(d, style=style),
                Text(cn, style=color),
                first_ip + (f" +{len(answers)-1}" if len(answers) > 1 else ""),
            ))

        info = Text()
        info.append("═══ DNS RESOLUTION ═══\n\n", style="bold cyan")
        info.append("Domain: ", style="dim")
        info.append(f"{domain}\n", style="bold #58a6ff")
        info.append("\nResolved Hosts:\n", style="dim")
        for ip in ips:
            ip_str = str(ip)
            cn, cat, color = self._get_codename(ip_str)
            role = self._detect_role(ip_str)
            info.append(f"  • ", style="dim")
            info.append(f"{cn}", style=f"bold {color}")
            info.append(f" ({ip_str})", style="dim")
            if role:
                info.append(f" [{role}]", style="bold cyan")
            info.append("\n")

        related = ["[bold cyan]═══ HOST INTELLIGENCE ═══[/]"]

        for ip in ips:
            ip_str = str(ip)
            cn, _, color = self._get_codename(ip_str)
            role = self._detect_role(ip_str)
            related.append(f"\n[{color}]═ {cn} ═[/] ({ip_str})")
            if role:
                related.append(f"  Role: [bold cyan]{role}[/]")

            ip_creds = [c for c in self.credentials if c.target_ip == ip_str]
            if ip_creds:
                related.append(f"  [bold red]★ {len(ip_creds)} CREDENTIALS CAPTURED:[/]")
                for c in ip_creds[:3]:
                    related.append(f"    • {c.protocol.upper()}: {c.username}@{c.domain}")

            ip_flows = [f for f in self.flows.values() if f.get("dst") == ip_str or f.get("src") == ip_str]
            if ip_flows:
                in_flows = [f for f in ip_flows if f.get("dst") == ip_str]
                out_flows = [f for f in ip_flows if f.get("src") == ip_str]
                related.append(f"  Flows: [red]{len(in_flows)} in[/] / [green]{len(out_flows)} out[/]")

            if ip_str in self.hosts:
                h = self.hosts[ip_str]
                if h.get("os") and h["os"] != "?":
                    related.append(f"  OS: {h['os']}")
                svcs = h.get("services", set())
                if svcs:
                    related.append(f"  Ports: {', '.join(str(s) for s in sorted(svcs)[:10])}")
                # Alerts
                alert_count = sum(1 for a in self.alerts if a.get("src_ip") == ip_str or a.get("dst_ip") == ip_str or a.get("target") == ip_str)
                if alert_count:
                    related.append(f"  [yellow]⚠ {alert_count} alerts[/]")

        self.fullscreen_type = "dns"
        self._show_detail(f"DNS: {domain}", cols, rows, info, related, selected_idx=idx)

    def _update_dns_detail(self, idx: int) -> None:
        dns_list = list(self.dns_resolutions.items())
        if idx >= len(dns_list):
            return
        domain, ips = dns_list[idx]

        self.query_one("#detail-header", Static).update(f" ★ DNS: {domain} ★ ")

        info = Text()
        info.append("═══ DNS RESOLUTION ═══\n\n", style="bold cyan")
        info.append("Domain: ", style="dim")
        info.append(f"{domain}\n", style="bold #58a6ff")
        info.append("\nResolved Hosts:\n", style="dim")
        for ip in ips:
            ip_str = str(ip)
            cn, cat, color = self._get_codename(ip_str)
            role = self._detect_role(ip_str)
            info.append(f"  • ", style="dim")
            info.append(f"{cn}", style=f"bold {color}")
            info.append(f" ({ip_str})", style="dim")
            if role:
                info.append(f" [{role}]", style="bold cyan")
            info.append("\n")

        self.query_one("#detail-info", Static).update(info)

        log = self.query_one("#detail-log", RichLog)
        log.clear()
        log.write(render_markup("[bold cyan]═══ HOST INTELLIGENCE ═══[/]"))

        for ip in ips:
            ip_str = str(ip)
            cn, _, color = self._get_codename(ip_str)
            role = self._detect_role(ip_str)
            log.write(render_markup(f"\n[{color}]═ {cn} ═[/]"))
            if role:
                log.write(f"  Role: {role}")

            ip_creds = [c for c in self.credentials if c.target_ip == ip_str]
            if ip_creds:
                log.write(render_markup(f"  [bold red]★ {len(ip_creds)} CREDENTIALS CAPTURED:[/]"))
                for c in ip_creds[:3]:
                    log.write(f"    • {c.protocol.upper()}: {c.username}@{c.domain}")

            ip_flows = [f for f in self.flows.values() if f.get("dst") == ip_str or f.get("src") == ip_str]
            if ip_flows:
                in_flows = [f for f in ip_flows if f.get("dst") == ip_str]
                out_flows = [f for f in ip_flows if f.get("src") == ip_str]
                log.write(render_markup(f"  Flows: [red]{len(in_flows)} in[/] / [green]{len(out_flows)} out[/]"))

            if ip_str in self.hosts:
                h = self.hosts[ip_str]
                if h.get("os") and h["os"] != "?":
                    log.write(f"  OS: {h['os']}")
                svcs = h.get("services", set())
                if svcs:
                    log.write(f"  Ports: {', '.join(str(s) for s in sorted(svcs)[:10])}")

    def _enrich_host(self, idx: int) -> None:
        # Sort by threat score
        sorted_hosts = sorted(
            self.hosts.items(),
            key=lambda x: calculate_threat_score(x[1]),
            reverse=True
        )
        if idx >= len(sorted_hosts):
            return
        ip, host = sorted_hosts[idx]
        score = calculate_threat_score(host)
        codename, category, color = self._get_codename(ip)
        role = self._detect_role(ip)

        cols = ["#", "CODENAME", "IP", "OS", "CREDS", "SCORE"]
        rows = []
        for i, (h_ip, h) in enumerate(sorted_hosts):
            h_score = calculate_threat_score(h)
            cn, _, col = self._get_codename(h_ip)
            cred_count = len(h.get("creds", []))
            style = "bold" if i == idx else ""
            rows.append((
                str(i+1),
                Text(cn, style=f"bold {col}" if i == idx else col),
                h_ip,
                h.get("os", "?")[:12],
                Text(str(cred_count), style="bold red") if cred_count else Text("0", style="dim"),
                Text(str(h_score), style="bold #f85149" if h_score >= 50 else "#d29922" if h_score >= 25 else "dim"),
            ))

        info = Text()
        info.append("═══ TARGET PROFILE ═══\n\n", style="bold cyan")
        info.append("Codename: ", style="dim")
        info.append(f"{codename}\n", style=f"bold {color}")
        info.append("Category: ", style="dim")
        info.append(f"{category}\n", style=color)
        info.append("IP Address: ", style="dim")
        info.append(f"{ip}\n", style="bold")
        info.append("\n═══ THREAT ASSESSMENT ═══\n", style="bold #f85149")
        info.append("Threat Score: ", style="dim")
        score_style = "bold #f85149" if score >= 50 else "bold #d29922" if score >= 25 else "bold"
        info.append(f"{score}/100\n", style=score_style)
        creds = host.get("creds", [])
        if creds:
            info.append("Credentials: ", style="dim")
            info.append(f"★ {len(creds)} CAPTURED\n", style="bold red")
        # Count connections
        in_count = sum(1 for f in self.flows.values() if f.get("dst") == ip)
        out_count = sum(1 for f in self.flows.values() if f.get("src") == ip)
        info.append("Connections: ", style="dim")
        info.append(f"{in_count} in", style="#f85149")
        info.append(" / ", style="dim")
        info.append(f"{out_count} out\n", style="#7ee787")
        info.append("\n═══ SYSTEM INFO ═══\n", style="bold yellow")
        info.append("OS: ", style="dim")
        info.append(f"{host.get('os', 'Unknown')}\n", style="bold")
        if host.get("dns"):
            info.append("DNS: ", style="dim")
            info.append(f"{host.get('dns')}\n", style="bold #58a6ff")
        svcs = host.get("services", set())
        info.append("Open Ports: ", style="dim")
        info.append(f"{', '.join(str(s) for s in sorted(svcs)) or 'None'}\n", style="bold")
        if host.get("first_seen"):
            info.append("First Seen: ", style="dim")
            info.append(f"{host['first_seen'].strftime('%H:%M:%S')}\n", style="bold")

        related = ["[bold cyan]═══ ATTACK INTELLIGENCE ═══[/]"]

        # Credentials with hashcat commands
        if creds:
            related.append(f"\n[bold red]★ CAPTURED CREDENTIALS ({len(creds)}):[/]")
            for c in creds:
                related.append(f"  • {c.protocol.upper() if c.protocol else '?'}: {c.username}@{c.domain}")
                if c.hashcat_format:
                    hf = c.hashcat_format
                    related.append(f"    [dim]hashcat -m {c.hashcat_mode or 5600}[/]")
                    related.append(f"    [dim]{hf[:60]}...[/]" if len(hf) > 60 else f"    [dim]{hf}[/]")

        # Related DNS lookups
        dns_for_ip = [d for d, ips in self.dns_resolutions.items() if ip in ips]
        if dns_for_ip:
            related.append(f"\n[cyan]DNS Names ({len(dns_for_ip)}):[/]")
            for d in dns_for_ip[:5]:
                related.append(f"  • {d}")

        # Related alerts
        host_alerts = [a for a in self.alerts if a.get("src_ip") == ip or a.get("dst_ip") == ip or a.get("target") == ip]
        if host_alerts:
            related.append(f"\n[yellow]⚠ SECURITY ALERTS ({len(host_alerts)}):[/]")
            for a in host_alerts[:5]:
                sev = a.get("severity", "info").upper()
                sev_color = "bold red" if sev == "CRITICAL" else "yellow"
                related.append(f"  • [{sev_color}][{sev}][/] {a.get('message', '')[:50]}")

        # Network flows with codenames
        host_flows = [(k, self.flows[k]) for k in host.get("flows", []) if k in self.flows]
        if host_flows:
            related.append(f"\n[#7ee787]Network Activity ({len(host_flows)} flows):[/]")
            for k, f in sorted(host_flows, key=lambda x: x[1].get("count", 0), reverse=True)[:10]:
                direction = "←" if f.get("dst") == ip else "→"
                other_ip = f.get("src") if f.get("dst") == ip else f.get("dst")
                other_cn, _, other_col = self._get_codename(other_ip)
                ts = f.get("last_seen")
                ts_str = f" @ {ts.strftime('%H:%M:%S')}" if ts else ""
                related.append(f"  {direction} [{other_col}]{other_cn}[/]:{f.get('port', '?')} ({f.get('count', 0)}x){ts_str}")

        self.fullscreen_type = "hosts"
        self._show_detail(f"HOST: {codename} [{role or category}] Score:{score}", cols, rows, info, related, selected_idx=idx)

    def _update_host_detail(self, idx: int) -> None:
        # Sort by threat score (same as _enrich_host)
        sorted_hosts = sorted(
            self.hosts.items(),
            key=lambda x: calculate_threat_score(x[1]),
            reverse=True
        )
        if idx >= len(sorted_hosts):
            return
        ip, host = sorted_hosts[idx]
        score = calculate_threat_score(host)
        codename, category, color = self._get_codename(ip)
        role = self._detect_role(ip)

        self.query_one("#detail-header", Static).update(f" ★ {codename} [{role or category}] Score:{score} ★ ")

        info = Text()
        info.append("═══ TARGET PROFILE ═══\n\n", style="bold cyan")
        info.append("Codename: ", style="dim")
        info.append(f"{codename}\n", style=f"bold {color}")
        info.append("Category: ", style="dim")
        info.append(f"{category}\n", style=color)
        info.append("IP Address: ", style="dim")
        info.append(f"{ip}\n", style="bold")
        if role:
            info.append("Role: ", style="dim")
            info.append(f"{role}\n", style="bold cyan")
        info.append("\n═══ THREAT ASSESSMENT ═══\n", style="bold #f85149")
        info.append("Threat Score: ", style="dim")
        score_style = "bold #f85149" if score >= 50 else "bold #d29922" if score >= 25 else "bold"
        info.append(f"{score}/100\n", style=score_style)
        creds = host.get("creds", [])
        if creds:
            info.append("Credentials: ", style="dim")
            info.append(f"★ {len(creds)} CAPTURED\n", style="bold red")
        in_count = sum(1 for f in self.flows.values() if f.get("dst") == ip)
        out_count = sum(1 for f in self.flows.values() if f.get("src") == ip)
        info.append("Connections: ", style="dim")
        info.append(f"{in_count} in", style="#f85149")
        info.append(" / ", style="dim")
        info.append(f"{out_count} out\n", style="#7ee787")
        info.append("\n═══ SYSTEM INFO ═══\n", style="bold yellow")
        info.append("OS: ", style="dim")
        info.append(f"{host.get('os', 'Unknown')}\n", style="bold")
        if host.get("dns"):
            info.append("DNS: ", style="dim")
            info.append(f"{host.get('dns')}\n", style="bold #58a6ff")
        svcs = host.get("services", set())
        info.append("Open Ports: ", style="dim")
        info.append(f"{', '.join(str(s) for s in sorted(svcs)) or 'None'}\n", style="bold")
        if host.get("first_seen"):
            info.append("First Seen: ", style="dim")
            info.append(f"{host['first_seen'].strftime('%H:%M:%S')}\n", style="bold")

        self.query_one("#detail-info", Static).update(info)

        log = self.query_one("#detail-log", RichLog)
        log.clear()
        log.write(render_markup("[bold cyan]═══ ATTACK INTELLIGENCE ═══[/]"))

        # Credentials with hashcat
        if creds:
            log.write(render_markup(f"\n[bold red]★ CAPTURED CREDENTIALS ({len(creds)}):[/]"))
            for c in creds:
                log.write(f"  • {c.protocol.upper() if c.protocol else '?'}: {c.username}@{c.domain}")
                if c.hashcat_format:
                    log.write(render_markup(f"    [dim]hashcat -m {c.hashcat_mode or 5600}[/]"))

        # DNS names resolving to this IP
        dns_for_ip = [d for d, ips in self.dns_resolutions.items() if ip in ips]
        if dns_for_ip:
            log.write(render_markup(f"\n[cyan]DNS Names ({len(dns_for_ip)}):[/]"))
            for d in dns_for_ip[:5]:
                log.write(f"  • {d}")

        # Alerts for this host
        host_alerts = [a for a in self.alerts if a.get("src_ip") == ip or a.get("dst_ip") == ip or a.get("target") == ip]
        if host_alerts:
            log.write(render_markup(f"\n[yellow]⚠ SECURITY ALERTS ({len(host_alerts)}):[/]"))
            for a in host_alerts[:5]:
                sev = a.get("severity", "info").upper()
                sev_color = "bold red" if sev == "CRITICAL" else "yellow"
                log.write(render_markup(f"  • [{sev_color}][{sev}][/] {a.get('message', '')[:50]}"))

        # Network flows with codenames
        host_flows = [(k, self.flows[k]) for k in host.get("flows", []) if k in self.flows]
        if host_flows:
            log.write(render_markup(f"\n[#7ee787]Network Activity ({len(host_flows)} flows):[/]"))
            for k, f in sorted(host_flows, key=lambda x: x[1].get("count", 0), reverse=True)[:10]:
                direction = "←" if f.get("dst") == ip else "→"
                other_ip = f.get("src") if f.get("dst") == ip else f.get("dst")
                other_cn, _, other_col = self._get_codename(other_ip)
                ts = f.get("last_seen")
                ts_str = f" @ {ts.strftime('%H:%M:%S')}" if ts else ""
                log.write(render_markup(f"  {direction} [{other_col}]{other_cn}[/]:{f.get('port', '?')} ({f.get('count', 0)}x){ts_str}"))

    def _enrich_alert(self, idx: int) -> None:
        if idx >= len(self.alerts):
            return
        alert = self.alerts[idx]

        # Extract IPs from alert
        src_ip = alert.get("src_ip") or alert.get("client") or ""
        dst_ip = alert.get("dst_ip") or alert.get("target") or ""
        src_cn, _, src_color = self._get_codename(src_ip) if src_ip else ("?", "", "dim")
        dst_cn, _, dst_color = self._get_codename(dst_ip) if dst_ip else ("?", "", "dim")

        cols = ["#", "SEV", "TYPE", "SOURCE", "TARGET", "MESSAGE"]
        rows = []
        for i, a in enumerate(self.alerts):
            sev = a.get("severity", "info").upper()
            style = "bold" if i == idx else ""
            sev_style = "bold white on red" if sev == "CRITICAL" else "bold #d29922" if sev == "HIGH" else "yellow"
            a_src = a.get("src_ip") or a.get("client") or ""
            a_dst = a.get("dst_ip") or a.get("target") or ""
            s_cn, _, s_col = self._get_codename(a_src) if a_src else ("?", "", "dim")
            d_cn, _, d_col = self._get_codename(a_dst) if a_dst else ("?", "", "dim")
            rows.append((
                str(i+1),
                Text(sev, style=sev_style),
                a.get("type", "")[:15],
                Text(s_cn, style=s_col),
                Text(d_cn, style=d_col),
                Text(a.get("message", "")[:40], style=style),
            ))

        info = Text()
        info.append("═══ SECURITY ALERT ═══\n\n", style="bold red")
        sev = alert.get("severity", "info").upper()
        info.append("Severity: ", style="dim")
        sev_style = "bold white on red" if sev == "CRITICAL" else "bold red" if sev == "HIGH" else "bold yellow"
        info.append(f"{sev}\n", style=sev_style)
        info.append("Type: ", style="dim")
        info.append(f"{alert.get('type', 'unknown')}\n", style="bold")
        if alert.get("timestamp"):
            info.append("Time: ", style="dim")
            ts = alert["timestamp"]
            info.append(f"{ts.strftime('%H:%M:%S') if hasattr(ts, 'strftime') else ts}\n", style="bold")
        info.append("\n═══ ENDPOINTS ═══\n", style="bold cyan")
        if src_ip:
            info.append("Source: ", style="dim")
            info.append(f"{src_cn}", style=f"bold {src_color}")
            info.append(f" ({src_ip})\n", style="dim")
            src_role = self._detect_role(src_ip)
            if src_role:
                info.append("  Role: ", style="dim")
                info.append(f"{src_role}\n", style="bold cyan")
        if dst_ip:
            info.append("Target: ", style="dim")
            info.append(f"{dst_cn}", style=f"bold {dst_color}")
            info.append(f" ({dst_ip})\n", style="dim")
            dst_role = self._detect_role(dst_ip)
            if dst_role:
                info.append("  Role: ", style="dim")
                info.append(f"{dst_role}\n", style="bold cyan")
        info.append("\n═══ MESSAGE ═══\n", style="bold yellow")
        info.append(f"{alert.get('message', '')}\n", style="bold")

        related = ["[bold cyan]═══ HOST INTELLIGENCE ═══[/]"]

        # Intel for both endpoints
        seen_ips = set()
        for label, ip, cn, color in [("Source", src_ip, src_cn, src_color), ("Target", dst_ip, dst_cn, dst_color)]:
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                role = self._detect_role(ip)
                related.append(f"\n[{color}]═ {cn} ═[/] ({ip})")
                if role:
                    related.append(f"  Role: [bold cyan]{role}[/]")
                if ip in self.hosts:
                    h = self.hosts[ip]
                    if h.get("os") and h["os"] != "?":
                        related.append(f"  OS: {h['os']}")
                    svcs = h.get("services", set())
                    if svcs:
                        related.append(f"  Ports: {', '.join(str(s) for s in sorted(svcs)[:8])}")
                    if h.get("creds"):
                        related.append(f"  [bold red]★ {len(h['creds'])} CREDS CAPTURED[/]")
                # Related alerts for this host
                host_alerts = [a for a in self.alerts if a != alert and (a.get("src_ip") == ip or a.get("dst_ip") == ip or a.get("target") == ip)]
                if host_alerts:
                    related.append(f"  [yellow]⚠ {len(host_alerts)} other alerts[/]")
                # Flow activity
                host_flows = [f for f in self.flows.values() if f.get("src") == ip or f.get("dst") == ip]
                if host_flows:
                    in_count = sum(1 for f in host_flows if f.get("dst") == ip)
                    out_count = sum(1 for f in host_flows if f.get("src") == ip)
                    related.append(f"  Flows: [red]{in_count} in[/] / [green]{out_count} out[/]")

        self.fullscreen_type = "alerts"
        self._show_detail(f"ALERT: {alert.get('type', '')} [{sev}]", cols, rows, info, related, selected_idx=idx)

    def _update_alert_detail(self, idx: int) -> None:
        if idx >= len(self.alerts):
            return
        alert = self.alerts[idx]

        src_ip = alert.get("src_ip") or alert.get("client") or ""
        dst_ip = alert.get("dst_ip") or alert.get("target") or ""
        src_cn, _, src_color = self._get_codename(src_ip) if src_ip else ("?", "", "dim")
        dst_cn, _, dst_color = self._get_codename(dst_ip) if dst_ip else ("?", "", "dim")
        sev = alert.get("severity", "info").upper()

        self.query_one("#detail-header", Static).update(f" ★ ALERT: {alert.get('type', '')} [{sev}] ★ ")

        info = Text()
        info.append("═══ SECURITY ALERT ═══\n\n", style="bold red")
        info.append("Severity: ", style="dim")
        sev_style = "bold white on red" if sev == "CRITICAL" else "bold red" if sev == "HIGH" else "bold yellow"
        info.append(f"{sev}\n", style=sev_style)
        info.append("Type: ", style="dim")
        info.append(f"{alert.get('type', 'unknown')}\n", style="bold")
        if alert.get("timestamp"):
            info.append("Time: ", style="dim")
            ts = alert["timestamp"]
            info.append(f"{ts.strftime('%H:%M:%S') if hasattr(ts, 'strftime') else ts}\n", style="bold")
        info.append("\n═══ ENDPOINTS ═══\n", style="bold cyan")
        if src_ip:
            info.append("Source: ", style="dim")
            info.append(f"{src_cn}", style=f"bold {src_color}")
            info.append(f" ({src_ip})\n", style="dim")
            src_role = self._detect_role(src_ip)
            if src_role:
                info.append("  Role: ", style="dim")
                info.append(f"{src_role}\n", style="bold cyan")
        if dst_ip:
            info.append("Target: ", style="dim")
            info.append(f"{dst_cn}", style=f"bold {dst_color}")
            info.append(f" ({dst_ip})\n", style="dim")
            dst_role = self._detect_role(dst_ip)
            if dst_role:
                info.append("  Role: ", style="dim")
                info.append(f"{dst_role}\n", style="bold cyan")
        info.append("\n═══ MESSAGE ═══\n", style="bold yellow")
        info.append(f"{alert.get('message', '')}\n", style="bold")

        self.query_one("#detail-info", Static).update(info)

        log = self.query_one("#detail-log", RichLog)
        log.clear()
        log.write(render_markup("[bold cyan]═══ HOST INTELLIGENCE ═══[/]"))

        # Intel for both endpoints
        seen_ips = set()
        for label, ip, cn, color in [("Source", src_ip, src_cn, src_color), ("Target", dst_ip, dst_cn, dst_color)]:
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                role = self._detect_role(ip)
                log.write(render_markup(f"\n[{color}]═ {cn} ═[/]"))
                if role:
                    log.write(f"  Role: {role}")
                if ip in self.hosts:
                    h = self.hosts[ip]
                    if h.get("os") and h["os"] != "?":
                        log.write(f"  OS: {h['os']}")
                    svcs = h.get("services", set())
                    if svcs:
                        log.write(f"  Ports: {', '.join(str(s) for s in sorted(svcs)[:8])}")
                    if h.get("creds"):
                        log.write(render_markup(f"  [bold red]★ {len(h['creds'])} CREDS CAPTURED[/]"))
                # Related alerts
                host_alerts = [a for a in self.alerts if a != alert and (a.get("src_ip") == ip or a.get("dst_ip") == ip or a.get("target") == ip)]
                if host_alerts:
                    log.write(render_markup(f"  [yellow]⚠ {len(host_alerts)} other alerts[/]"))

    def _update_intel_detail(self, idx: int) -> None:
        """Update intel detail view when row changes in fullscreen."""
        # Intel rows are stored in self._intel_data during fullscreen generation
        # For intel, we just update the info panel based on the selected row type
        if not hasattr(self, '_intel_rows') or idx >= len(self._intel_rows):
            return

        row = self._intel_rows[idx]
        category = row[0] if len(row) > 0 else ""

        info = Text()
        log = self.query_one("#detail-log", RichLog)
        log.clear()

        if category == "TOPOLOGY":
            info.append("═══ TOPOLOGY INTEL ═══\n\n", style="bold cyan")
            info.append(f"Subnet: {row[2]}\n", style="bold")
            info.append(f"Hosts: {row[3]}\n", style="bold")
        elif category == "SERVICE":
            info.append("═══ SERVICE INTEL ═══\n\n", style="bold #a371f7")
            svc = row[1]
            info.append(f"Service: {svc}\n", style="bold")
            info.append(f"Host Count: {row[2]}\n", style="bold")
            info.append(f"\nHosts with {svc}:\n", style="dim")
            # Show hosts with this service
            for ip, data in self.hosts.items():
                for port in data.get("services", set()):
                    if self._get_service_name(port) == svc:
                        cn, _, col = self._get_codename(ip)
                        log.write(f"  {cn} ({ip})")
                        break
        elif category == "CENTRAL":
            info.append("═══ CENTRAL HOST ═══\n\n", style="bold #d29922")
            info.append(f"Host: {row[1]}\n", style="bold")
            info.append(f"Connections: {row[2]}\n", style="bold")
            if row[3]:
                info.append(f"Status: {row[3]}\n", style="bold red")
        elif category == "PATH":
            info.append("═══ LATERAL PATH ═══\n\n", style="bold red")
            info.append(f"Source: {row[1]}\n", style="bold")
            info.append(f"Target: {row[2]}\n", style="bold")
            info.append(f"Service: {row[3]}\n", style="bold cyan")

        self.query_one("#detail-info", Static).update(info)

    # ===== INTEL FULLSCREEN =====

    def _show_intel_fullscreen(self) -> None:
        """Show expanded INTEL view in fullscreen."""
        # Build comprehensive intel for fullscreen
        internal = [ip for ip in self.hosts if ip.startswith(('10.', '192.168.', '172.'))]
        external = [ip for ip in self.hosts if not ip.startswith(('10.', '192.168.', '172.'))]

        # Build rows for the detail table - each row is a piece of intel
        rows = []
        cols = ["CATEGORY", "ITEM", "VALUE", "DETAILS"]

        # TOPOLOGY
        subnets = {}
        for ip in internal:
            parts = ip.split('.')
            if len(parts) >= 3:
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.x"
                subnets[subnet] = subnets.get(subnet, 0) + 1
        for subnet, count in sorted(subnets.items(), key=lambda x: x[1], reverse=True):
            rows.append(("TOPOLOGY", "Internal Subnet", subnet, f"{count} hosts"))
        if external:
            rows.append(("TOPOLOGY", "External Hosts", str(len(external)), "Remote connections"))

        # SERVICES
        service_counts = {}
        service_hosts = {}  # svc -> [hosts]
        for ip, data in self.hosts.items():
            for port in data.get("services", set()):
                svc = self._get_service_name(port)
                service_counts[svc] = service_counts.get(svc, 0) + 1
                if svc not in service_hosts:
                    service_hosts[svc] = []
                service_hosts[svc].append(ip)
        for svc, cnt in sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:12]:
            hosts_str = ", ".join([self._get_codename(h)[0][:12] for h in service_hosts[svc][:3]])
            rows.append(("SERVICE", svc, str(cnt), hosts_str))

        # CENTRAL HOSTS
        host_conns = {}
        for ip in self.hosts:
            out_c = sum(1 for f in self.flows.values() if f.get("src") == ip)
            in_c = sum(1 for f in self.flows.values() if f.get("dst") == ip)
            host_conns[ip] = (out_c, in_c)
        for ip, (out_c, in_c) in sorted(host_conns.items(), key=lambda x: x[1][0]+x[1][1], reverse=True)[:8]:
            cn, _, _ = self._get_codename(ip)
            creds = len(self.hosts[ip].get("creds", []))
            cred_str = f"★{creds} CREDS" if creds > 0 else ""
            rows.append(("CENTRAL", cn, f"↑{out_c} ↓{in_c}", cred_str))

        # PATHS
        paths_seen = set()
        for src_ip in internal:
            for f in self.flows.values():
                if f.get("src") == src_ip:
                    dst_ip = f.get("dst", "")
                    if dst_ip in internal and dst_ip != src_ip:
                        port = f.get("port", "")
                        svc = self._get_service_name(port)
                        key = (src_ip, dst_ip, svc)
                        if key not in paths_seen:
                            paths_seen.add(key)
                            src_cn, _, _ = self._get_codename(src_ip)
                            dst_cn, _, _ = self._get_codename(dst_ip)
                            creds = len(self.hosts.get(src_ip, {}).get("creds", []))
                            marker = "★" if creds > 0 else ""
                            rows.append(("PATH", f"{src_cn}{marker}", f"→ {dst_cn}", svc))

        # Info panel
        info = Text()
        info.append("═══ NETWORK INTELLIGENCE ═══\n\n", style="bold cyan")
        info.append("Hosts: ", style="dim")
        info.append(f"{len(internal)} internal, {len(external)} external\n", style="bold")
        info.append("Flows: ", style="dim")
        info.append(f"{len(self.flows)} unique connections\n", style="bold")
        info.append("Services: ", style="dim")
        info.append(f"{len(service_counts)} types detected\n", style="bold")
        info.append("Credentials: ", style="dim")
        info.append(f"{len(self.credentials)} captured\n", style="bold #f85149")
        info.append("Alerts: ", style="dim")
        info.append(f"{len(self.alerts)} total\n", style="bold #d29922")

        # Related info
        related = []
        related.append("[bold cyan]═══ ATTACK SURFACE ═══[/]")
        high_value_svcs = ["SMB", "RDP", "SSH", "LDAP", "KERB", "MSSQL", "MYSQL", "PGSQL", "WINRM"]
        for svc in high_value_svcs:
            if svc in service_counts:
                hosts = service_hosts.get(svc, [])[:3]
                host_names = [self._get_codename(h)[0][:15] for h in hosts]
                related.append(f" {svc}: {', '.join(host_names)}")

        if self.credentials:
            related.append("\n[bold red]═══ COMPROMISED ACCESS ═══[/]")
            for cred in self.credentials[:5]:
                target_cn, _, _ = self._get_codename(cred.target_ip) if cred.target_ip else ("?", "", "")
                related.append(f" {cred.protocol.upper()}: {cred.username}@{cred.domain} → {target_cn}")

        self.fullscreen_type = "intel"
        self._intel_rows = rows  # Store for _update_intel_detail
        self._show_detail("NETWORK INTELLIGENCE SUMMARY", cols, rows, info, related, selected_idx=0)

    # ===== ACTIONS =====

    def action_focus_creds(self) -> None:
        if not self.fullscreen_active:
            self.query_one("#creds-table", DataTable).focus()

    def action_focus_flows(self) -> None:
        if not self.fullscreen_active:
            self._update_flows_table()
            self.query_one("#flows-table", DataTable).focus()

    def action_focus_dns(self) -> None:
        if not self.fullscreen_active:
            self.query_one("#dns-table", DataTable).focus()

    def action_focus_hosts(self) -> None:
        if not self.fullscreen_active:
            self._update_hosts_table()
            self.query_one("#hosts-table", DataTable).focus()

    def action_focus_alerts(self) -> None:
        if not self.fullscreen_active:
            self.query_one("#alerts-table", DataTable).focus()

    def action_focus_targets(self) -> None:
        """Toggle intel fullscreen (press 6)."""
        if not self.fullscreen_active:
            self._show_intel_fullscreen()
        elif self.fullscreen_type == "intel":
            self._hide_detail()
        else:
            self._update_intel_panel()

    def action_toggle_graph(self) -> None:
        """Toggle full-screen network graph."""
        overlay = self.query_one("#graph-overlay")
        if overlay.has_class("visible"):
            overlay.remove_class("visible")
            self.fullscreen_active = False
            self.graph_mode = 0
        else:
            self.graph_mode = 1
            self._update_network_map()
            self.query_one("#graph-header", Static).update("")  # Header is in the graph itself
            overlay.add_class("visible")
            self.fullscreen_active = True

    def action_show_attack_graph(self) -> None:
        """Show full-screen network graph (key 7)."""
        overlay = self.query_one("#graph-overlay")
        self.graph_mode = 1
        self._update_network_map()
        self.query_one("#graph-header", Static).update("")  # Header is in the graph itself
        overlay.add_class("visible")
        self.fullscreen_active = True

    def action_refresh_graph(self) -> None:
        """Refresh graph if visible."""
        if self.query_one("#graph-overlay").has_class("visible"):
            self._update_network_map()

    def action_filter_host(self) -> None:
        """Toggle filter mode on selected host."""
        if self.filter_ip:
            # Clear filter
            self.filter_ip = None
            self.filter_codename = None
            self._refresh_all_tables()
            self._update_stats()
            return

        # Get selected host from hosts table
        focused = self._get_focused_table_id()
        if focused == "#hosts-table":
            t = self.query_one("#hosts-table", DataTable)
            idx = t.cursor_row
            if idx is not None:
                sorted_hosts = sorted(
                    self.hosts.items(),
                    key=lambda x: calculate_threat_score(x[1]),
                    reverse=True
                )
                if idx < len(sorted_hosts):
                    ip, _ = sorted_hosts[idx]
                    codename, _, _ = self._get_codename(ip)
                    self.filter_ip = ip
                    self.filter_codename = codename
                    self._refresh_all_tables()
                    self._update_stats()

    def action_mark_compromised(self) -> None:
        """Mark/unmark selected host as compromised (key 'm')."""
        # Get selected host from hosts table
        focused = self._get_focused_table_id()
        if focused != "#hosts-table":
            self._log_debug("Mark: Focus hosts table first (press 4)")
            return

        t = self.query_one("#hosts-table", DataTable)
        idx = t.cursor_row
        if idx is None:
            return

        sorted_hosts = sorted(
            self.hosts.items(),
            key=lambda x: calculate_threat_score(x[1]),
            reverse=True
        )
        if idx >= len(sorted_hosts):
            return

        ip, _ = sorted_hosts[idx]
        codename, _, _ = self._get_codename(ip)

        # Toggle compromised status
        if ip in self.compromised_hosts:
            self.compromised_hosts.remove(ip)
            self._log_debug(f"UNMARK: {codename} ({ip}) removed from compromised")
        else:
            self.compromised_hosts.add(ip)
            self._log_debug(f"PWNED: {codename} ({ip}) marked as COMPROMISED")

            # Generate alert for the compromise
            now = datetime.now()
            alert = {
                "severity": "CRITICAL",
                "type": "host_compromised",
                "message": f"Host marked COMPROMISED: {codename}",
                "src_ip": "",
                "dst_ip": ip,
                "target": ip,
                "time": now,
            }
            self.alerts.append(alert)

            # Add to alerts table
            if len(self.alerts) <= 100:
                at = self.query_one("#alerts-table", DataTable)
                at.add_row(
                    now.strftime("%H:%M:%S"),
                    Text("CRIT", style="bold white on red"),
                    "COMPROMISED",
                    "",
                    alert["message"][:70],
                    ip[:15],
                )

        # Refresh displays
        self._update_hosts_table()
        self._update_intel_panel()
        self._update_stats()

    def _refresh_all_tables(self) -> None:
        """Refresh all data tables (used after filter change)."""
        self._update_flows_table()
        self._update_hosts_table()
        self._update_dns_table()
        self._update_intel_panel()
        # Refresh credentials table with filter
        t = self.query_one("#creds-table", DataTable)
        t.clear()
        for cred in self.credentials[:200]:
            if self.filter_ip and cred.target_ip != self.filter_ip:
                continue
            t.add_row(
                Text(cred.protocol.upper()[:6] if cred.protocol else "?", style="bold #f85149"),
                cred.username[:12] if cred.username else "?",
                cred.domain[:12] if cred.domain else "?",
                f"{cred.target_ip}:{cred.target_port}" if cred.target_ip else "?",
            )
        # Refresh alerts table with filter
        t = self.query_one("#alerts-table", DataTable)
        t.clear()
        for alert in self.alerts[:100]:
            if self.filter_ip:
                if not (alert.get("src_ip") == self.filter_ip or
                       alert.get("dst_ip") == self.filter_ip or
                       alert.get("target") == self.filter_ip):
                    continue
            sev = alert.get("severity", "info").upper()
            style = "bold white on red" if sev == "CRITICAL" else "bold #d29922" if sev == "HIGH" else "#d29922"
            time_str = alert.get("time", datetime.now()).strftime("%H:%M:%S")
            src_ip = alert.get("src_ip") or alert.get("client") or ""
            target = alert.get("dst_ip") or alert.get("target") or ""
            t.add_row(
                time_str,
                Text(sev[:4], style=style),
                alert.get("type", "")[:18],
                src_ip[:14] if src_ip else "",
                alert.get("message", "")[:70],
                target[:15] if target else "",
            )

    def _update_network_graph(self) -> None:
        """Update the network topology graph."""
        try:
            graph = render_network_graph(self.hosts, self.flows, self.dns_resolutions)
            self.query_one("#graph-content", Static).update(graph)
        except Exception as e:
            self._log_debug(f"Graph update error: {e}")

    def _update_network_map(self) -> None:
        """Update the full-screen network graph showing nodes and connections."""
        try:
            # Get terminal size for full-screen rendering
            size = self.screen.size
            width = max(80, size.width - 4)
            height = max(30, size.height - 8)

            graph = render_fullscreen_graph(
                self.hosts,
                self.flows,
                self.local_subnet,
                self.compromised_hosts,
                width=width,
                height=height
            )
            self.query_one("#graph-content", Static).update(graph)
        except Exception as e:
            self._log_debug(f"Network map update error: {e}")

    def action_toggle_fullscreen(self) -> None:
        if self.fullscreen_active:
            self._hide_detail()
            return

        focused = self._get_focused_table_id()
        if focused == "#creds-table":
            idx = self.query_one("#creds-table", DataTable).cursor_row
            if idx is not None and self.credentials:
                self._enrich_credential(idx)
        elif focused == "#flows-table":
            idx = self.query_one("#flows-table", DataTable).cursor_row
            if idx is not None and self.flows:
                self._enrich_flow(idx)
        elif focused == "#dns-table":
            idx = self.query_one("#dns-table", DataTable).cursor_row
            if idx is not None and self.dns_resolutions:
                self._enrich_dns(idx)
        elif focused == "#hosts-table":
            idx = self.query_one("#hosts-table", DataTable).cursor_row
            if idx is not None and self.hosts:
                self._enrich_host(idx)
        elif focused == "#alerts-table":
            idx = self.query_one("#alerts-table", DataTable).cursor_row
            if idx is not None and self.alerts:
                self._enrich_alert(idx)

    def action_exit_fullscreen(self) -> None:
        if self.fullscreen_active:
            # Close graph overlay if open
            graph_overlay = self.query_one("#graph-overlay")
            if graph_overlay.has_class("visible"):
                graph_overlay.remove_class("visible")
                self.fullscreen_active = False
                return
            # Otherwise close detail overlay
            self._hide_detail()

    def action_toggle_debug(self) -> None:
        """Toggle debug overlay."""
        overlay = self.query_one("#debug-overlay")
        if "visible" in overlay.classes:
            overlay.remove_class("visible")
            self.debug_mode = False
        else:
            overlay.add_class("visible")
            self.debug_mode = True
            # Populate with existing logs
            log = self.query_one("#debug-log", RichLog)
            log.clear()
            for line in self._debug_log[-100:]:
                log.write(line)

    def action_copy(self) -> None:
        if not HAS_CLIPBOARD:
            return

        focused = self._get_focused_table_id()
        copied = None

        if focused == "#creds-table" and self.credentials:
            idx = self.query_one("#creds-table", DataTable).cursor_row
            if idx is not None and idx < len(self.credentials):
                copied = self.credentials[idx].hashcat_format

        elif focused == "#flows-table" and self.flows:
            idx = self.query_one("#flows-table", DataTable).cursor_row
            sorted_flows = sorted(self.flows.items(), key=lambda x: x[1].get("count", 0), reverse=True)
            if idx is not None and idx < len(sorted_flows):
                _, f = sorted_flows[idx]
                copied = f"{f.get('src', '?')} -> {f.get('dst', '?')}:{f.get('port', '?')}"

        elif focused == "#dns-table" and self.dns_resolutions:
            idx = self.query_one("#dns-table", DataTable).cursor_row
            dns_list = list(self.dns_resolutions.items())
            if idx is not None and idx < len(dns_list):
                domain, ips = dns_list[idx]
                copied = f"{domain} -> {', '.join(str(i) for i in ips)}"

        elif focused == "#hosts-table" and self.hosts:
            idx = self.query_one("#hosts-table", DataTable).cursor_row
            sorted_hosts = sorted(self.hosts.items(), key=lambda x: len(x[1].get("creds", [])), reverse=True)
            if idx is not None and idx < len(sorted_hosts):
                copied = sorted_hosts[idx][0]

        elif focused == "#alerts-table" and self.alerts:
            idx = self.query_one("#alerts-table", DataTable).cursor_row
            if idx is not None and idx < len(self.alerts):
                copied = self.alerts[idx].get("message", "")

        if copied:
            try:
                pyperclip.copy(str(copied))
                self._log_debug(f"Copied: {str(copied)[:50]}...")
            except:
                pass

    def action_export(self) -> None:
        if not self.credentials:
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"hashes_{ts}.txt"
        with open(filename, "w") as f:
            for c in self.credentials:
                if c.hashcat_format:
                    f.write(c.hashcat_format + "\n")
        self._log_debug(f"Exported {len(self.credentials)} hashes to {filename}")

    def action_pause(self) -> None:
        self.paused = not self.paused
        self._update_stats()

    # ===== v2.0 ACTIONS =====

    def action_save_session(self) -> None:
        """Save current session (Ctrl+S)."""
        if not HAS_V2_FEATURES:
            self._log_debug("v2 features not available")
            return

        if not self._session_storage:
            self._start_session_storage()

        self._save_session_data()
        self._status_message = f"Saved: {len(self.hosts)}H {len(self.credentials)}C"
        self._update_stats()
        self._log_debug(f"Session saved: {self._session_storage.db_path}")

    def action_open_session(self) -> None:
        """Open session selection (Ctrl+O or O). Press again to cycle sessions."""
        if not HAS_V2_FEATURES or not SessionStorage:
            self._status_message = "v2 features required"
            self._update_stats()
            return

        sessions = SessionStorage.list_sessions()
        if not sessions:
            self._status_message = "No saved sessions"
            self._update_stats()
            return

        # Initialize or increment session selection index
        if not hasattr(self, '_session_select_idx'):
            self._session_select_idx = 0
            self._session_list = sessions
        else:
            # Cycle through sessions
            self._session_select_idx = (self._session_select_idx + 1) % len(sessions)
            self._session_list = sessions

        # Show current selection
        s = sessions[self._session_select_idx]
        total = len(sessions)
        idx = self._session_select_idx + 1

        # Extract info
        hosts = s.get('host_count', 0)
        creds = s.get('credential_count', 0)
        source = s.get('source_name', 'unknown')

        self._status_message = f"[{idx}/{total}] {source}: {hosts}H {creds}C - Enter to load"
        self._update_stats()
        self._log_debug(f"Session {idx}/{total}: {s.get('filename')} - {hosts} hosts, {creds} creds")

    def action_load_selected_session(self) -> None:
        """Load the currently selected session (Enter when session selected)."""
        if hasattr(self, '_session_list') and hasattr(self, '_session_select_idx'):
            if self._session_list and self._session_select_idx < len(self._session_list):
                path = self._session_list[self._session_select_idx]["path"]
                self._load_session(path)
                # Clear selection state
                del self._session_select_idx
                del self._session_list

    def _load_session(self, path: str) -> None:
        """Load session from path."""
        try:
            storage = SessionStorage.load_session(db_path=path)
            data = storage.load_all()

            # Apply loaded data
            self.hosts = data.get("hosts", {})
            self.flows = data.get("flows", {})
            self.credentials = data.get("credentials", [])  # FIX: Load credentials
            self.dns_resolutions = data.get("dns_resolutions", {})
            self.alerts = data.get("alerts", [])
            self.compromised_hosts = data.get("compromised_hosts", set())
            self.codenames = data.get("codenames", {})

            # Refresh tables
            self._refresh_all_tables()
            self._update_stats()

            metadata = data.get("metadata", {})
            self._status_message = f"Loaded: {len(self.hosts)}H {len(self.flows)}F"
            self._log_debug(f"Loaded session: {metadata.get('source_name', 'unknown')} ({len(self.hosts)} hosts)")
            storage.close()
        except Exception as e:
            self._last_error = f"Load error: {str(e)[:20]}"
            self._log_debug(f"Session load error: {e}")

    def action_advanced_filter(self) -> None:
        """Filter to selected host (/)."""
        # Use simple filter - filter to selected host or clear
        self._simple_filter_prompt()

    def _simple_filter_prompt(self) -> None:
        """Fallback simple IP filter (when v2 not available)."""
        if self.filter_ip:
            # Clear filter
            self.filter_ip = None
            self.filter_codename = None
            self._refresh_all_tables()
            self._update_stats()
            return

        # Get selected host from hosts table
        focused = self._get_focused_table_id()
        if focused == "#hosts-table":
            t = self.query_one("#hosts-table", DataTable)
            idx = t.cursor_row
            if idx is not None:
                sorted_hosts = sorted(
                    self.hosts.items(),
                    key=lambda x: calculate_threat_score(x[1]),
                    reverse=True
                )
                if idx < len(sorted_hosts):
                    ip, _ = sorted_hosts[idx]
                    codename, _, _ = self._get_codename(ip)
                    self.filter_ip = ip
                    self.filter_codename = codename
                    self._refresh_all_tables()
                    self._update_stats()

    def action_toggle_timeline(self) -> None:
        """Toggle timeline panel visibility (t)."""
        if not HAS_V2_FEATURES or not self._timeline:
            self._status_message = "Timeline: v2 required"
            self._update_stats()
            return

        self._timeline_visible = not self._timeline_visible
        self._update_intel_panel()  # Refresh to show/hide timeline
        self._update_stats()

        if self._timeline_visible:
            self._status_message = "Timeline: ON"
        else:
            self._status_message = "Timeline: OFF"


def run_tui(interface: str = None, pcap_file: str = None, bpf_filter: str = "", debug: bool = False):
    app = PcapIntelApp(interface=interface, pcap_file=pcap_file, bpf_filter=bpf_filter, debug=debug)
    app.run()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PCAP-INTEL TUI")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-i", "--interface", help="Network interface")
    source.add_argument("-r", "--pcap", dest="pcap_file", help="PCAP file")
    parser.add_argument("-f", "--filter", dest="bpf_filter", default="", help="BPF filter")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()
    run_tui(interface=args.interface, pcap_file=args.pcap_file, bpf_filter=args.bpf_filter, debug=args.debug)
