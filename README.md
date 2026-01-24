# PCAP-Intel v2.0 "SHADOW_SERPENT"

Real-time network traffic intelligence TUI for red team operators and security analysts.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  [NET]  PCAP-INTEL v2.0  |  SHADOW_SERPENT  |  Real-Time Network Intel      ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## Screenshots

### Main Dashboard
![Main TUI Dashboard](docs/images/tui-main.png)
*Multi-panel real-time analysis: Flows, DNS, Hosts, Credentials, Alerts, and Intel summary with unified service metrics*

### Network Graph
![Network Graph View](docs/images/tui-graph.png)
*ASCII network topology showing internal/external hosts with connection mapping and compromise indicators*

## Features

### Core Capabilities
- **Real-time Streaming** - Live packet capture with tshark backend
- **Credential Extraction** - NTLM, Kerberos, LDAP, HTTP Basic/Digest
- **Host Discovery** - Automatic OS fingerprinting and service detection
- **Network Graphing** - ASCII topology visualization with L-shaped connections
- **Attack Surface Mapping** - High-value target identification (AD, databases, K8s)

### v2.0 New Features
- **Session Persistence** - Save/load analysis sessions (SQLite + Fernet encryption)
- **Advanced Filtering** - BPF-style filter syntax (`ip 10.0.0.0/24 and port 445`)
- **Behavioral Timeline** - Track lateral movement and C2 patterns
- **Modular Panel System** - Extensible UI architecture

## Installation

### Requirements
- Python 3.10+
- tshark (Wireshark CLI)
- Root/sudo for live capture

### Install from PyPI
```bash
pip install pcap-intel
```

### Install from Source
```bash
git clone https://github.com/pcap-intel/pcap-intel.git
cd pcap-intel
pip install -e .
```

## Usage

### Live Capture (requires root)
```bash
sudo pcap-intel -i eth0
```

### Analyze PCAP File
```bash
pcap-intel -r capture.pcap
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `1-6` | Focus panels (Creds/Flows/DNS/Hosts/Alerts/Targets) |
| `g` | Toggle network graph |
| `m` | Mark host as compromised |
| `/` | Filter to selected host |
| `f` | Toggle fullscreen detail |
| `t` | Toggle behavioral timeline |
| `s` | Save session |
| `O` | Open saved session |
| `q` | Quit |

## Architecture

```
pcap_intel/
├── streaming/
│   ├── tui.py          # Main TUI application (4000+ lines)
│   └── auth_stream.py  # Real-time credential extraction
├── auth_engine/
│   ├── engine.py       # Credential correlation engine
│   └── handlers/       # Protocol-specific extractors
│       ├── ntlm.py
│       ├── kerberos.py
│       ├── ldap.py
│       └── http.py
└── tui/
    ├── session_storage.py   # v2.0: Session persistence
    ├── advanced_filter.py   # v2.0: BPF-style filtering
    └── timeline_panel.py    # v2.0: Behavioral timeline
```

## High-Value Target Detection

Automatically identifies critical infrastructure:

| Category | Services | Icon |
|----------|----------|------|
| **Identity** | AD, LDAP, Kerberos, RADIUS | `[C]` |
| **Databases** | SQL, NoSQL, Redis, Elasticsearch | `[D]` |
| **Kubernetes** | API Server, etcd, kubelet | `[T]` |
| **SCADA/OT** | Modbus, S7, DNP3, BACnet | `[!]` |

## Network Graph Legend

```
*=PWNED  [HVT]=High-Value Target  o=INTERNAL  .=EXTERNAL
>>>=Outbound  <<<=Inbound  <->=Bidirectional
```

## Session Management

### Save Session
Press `s` or `Ctrl+S` to save current analysis state.

### Load Session
Press `O` to cycle through saved sessions, `L` to load selected.

Sessions are encrypted with Fernet and stored in `~/.pcap-intel/sessions/`.

## Advanced Filtering

```
# Filter by IP
ip 10.0.0.1

# Filter by CIDR
ip 192.168.0.0/16

# Filter by port
port 445

# Filter by protocol
proto smb

# Compound filters
ip 10.0.0.0/24 and port 445
compromised or hvt
not port 80
```

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is intended for authorized security testing and network analysis only.
Ensure you have proper authorization before capturing network traffic.
