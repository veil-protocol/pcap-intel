#!/usr/bin/env python3
"""
PCAP-INTEL Session Storage - Encrypted SQLite Persistence

Provides:
- Auto-save session state every 30 seconds
- Encrypted credential storage (Fernet)
- Session recovery on restart
- Export/import capabilities
"""

import sqlite3
import json
import os
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from dataclasses import dataclass, asdict
from contextlib import contextmanager

# Encryption support (optional - graceful degradation)
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@dataclass
class SessionMetadata:
    """Session metadata for tracking."""
    session_id: str
    created_at: str
    updated_at: str
    source_type: str  # "interface" or "pcap"
    source_name: str  # interface name or pcap path
    packets_processed: int
    credential_count: int
    host_count: int
    alert_count: int
    version: str = "1.0.0"


class SessionStorage:
    """
    SQLite-based session persistence with optional encryption.

    Features:
    - Stores hosts, flows, credentials, alerts, dns, codenames
    - Encrypts sensitive credential data
    - Auto-save with configurable interval
    - Session recovery and export
    """

    SCHEMA = """
    -- Session metadata
    CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    -- Hosts table
    CREATE TABLE IF NOT EXISTS hosts (
        ip TEXT PRIMARY KEY,
        os TEXT,
        services TEXT,  -- JSON array of ports
        dns TEXT,
        first_seen TEXT,
        alert_count INTEGER DEFAULT 0,
        is_compromised INTEGER DEFAULT 0,
        properties TEXT  -- JSON for additional data
    );

    -- Credentials table (encrypted)
    CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        protocol TEXT,
        username TEXT,
        domain TEXT,
        target_ip TEXT,
        target_port INTEGER,
        hashcat_format TEXT,  -- Encrypted
        raw_data TEXT,  -- Encrypted JSON
        timestamp TEXT
    );

    -- Flows table
    CREATE TABLE IF NOT EXISTS flows (
        flow_key TEXT PRIMARY KEY,
        src TEXT,
        dst TEXT,
        port INTEGER,
        proto TEXT,
        count INTEGER DEFAULT 1,
        first_seen TEXT,
        last_seen TEXT
    );

    -- DNS resolutions
    CREATE TABLE IF NOT EXISTS dns (
        domain TEXT PRIMARY KEY,
        answers TEXT  -- JSON array
    );

    -- Alerts
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        severity TEXT,
        type TEXT,
        message TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        target TEXT,
        timestamp TEXT,
        properties TEXT  -- JSON
    );

    -- Codenames (for consistency across sessions)
    CREATE TABLE IF NOT EXISTS codenames (
        ip TEXT PRIMARY KEY,
        codename TEXT,
        category TEXT,
        color TEXT
    );

    -- Indexes
    CREATE INDEX IF NOT EXISTS idx_hosts_compromised ON hosts(is_compromised);
    CREATE INDEX IF NOT EXISTS idx_creds_target ON credentials(target_ip);
    CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src);
    CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        encryption_key: Optional[str] = None,
        auto_save_interval: int = 30
    ):
        """
        Initialize session storage.

        Args:
            db_path: Path to SQLite database (default: ~/.pcap-intel/sessions/)
            encryption_key: Optional encryption key for sensitive data
            auto_save_interval: Seconds between auto-saves (0 to disable)
        """
        self.db_path = db_path or self._default_db_path()
        self.auto_save_interval = auto_save_interval
        self._ensure_dir()

        # Setup encryption
        self._fernet = None
        if encryption_key and HAS_CRYPTO:
            self._fernet = self._create_fernet(encryption_key)

        # Database connection
        self.conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._init_schema()

        # Session tracking
        self.session_id = self._generate_session_id()
        self._last_save = datetime.now()
        self._dirty = False

    def _default_db_path(self) -> str:
        """Get default database path."""
        base = Path.home() / ".pcap-intel" / "sessions"
        base.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return str(base / f"session_{timestamp}.db")

    def _ensure_dir(self):
        """Ensure database directory exists."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        return hashlib.md5(
            f"{datetime.now().isoformat()}{os.getpid()}".encode()
        ).hexdigest()[:12]

    def _create_fernet(self, key: str) -> 'Fernet':
        """Create Fernet cipher from password."""
        # Derive key from password using PBKDF2
        salt = b'pcap-intel-v1'  # Static salt for consistency
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        return Fernet(derived_key)

    def _encrypt(self, data: str) -> str:
        """Encrypt string data."""
        if self._fernet:
            return self._fernet.encrypt(data.encode()).decode()
        return data

    def _decrypt(self, data: str) -> str:
        """Decrypt string data."""
        if self._fernet:
            try:
                return self._fernet.decrypt(data.encode()).decode()
            except Exception:
                return data  # Return as-is if decryption fails
        return data

    def _connect(self):
        """Connect to database."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")  # Better concurrent access

    def _init_schema(self):
        """Initialize database schema."""
        self.conn.executescript(self.SCHEMA)
        self.conn.commit()

    @contextmanager
    def transaction(self):
        """Context manager for transactions."""
        try:
            yield
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    # ===================
    # Metadata Operations
    # ===================

    def set_metadata(self, key: str, value: Any):
        """Set metadata value."""
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, json.dumps(value) if not isinstance(value, str) else value)
        )
        self._dirty = True

    def get_metadata(self, key: str) -> Optional[str]:
        """Get metadata value."""
        row = self.conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def save_session_metadata(self, source_type: str, source_name: str,
                              packets: int, creds: int, hosts: int, alerts: int):
        """Save session metadata."""
        now = datetime.now().isoformat()
        self.set_metadata("session_id", self.session_id)
        self.set_metadata("created_at", self.get_metadata("created_at") or now)
        self.set_metadata("updated_at", now)
        self.set_metadata("source_type", source_type)
        self.set_metadata("source_name", source_name)
        self.set_metadata("packets_processed", str(packets))
        self.set_metadata("credential_count", str(creds))
        self.set_metadata("host_count", str(hosts))
        self.set_metadata("alert_count", str(alerts))
        self.set_metadata("version", "1.0.0")

    # ===================
    # Host Operations
    # ===================

    def save_hosts(self, hosts: Dict[str, Dict], compromised: Set[str]):
        """Save all hosts."""
        with self.transaction():
            for ip, data in hosts.items():
                services = list(data.get("services", set()))
                self.conn.execute("""
                    INSERT OR REPLACE INTO hosts
                    (ip, os, services, dns, first_seen, alert_count, is_compromised, properties)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip,
                    data.get("os", "?"),
                    json.dumps(services),
                    data.get("dns"),
                    data.get("first_seen", datetime.now()).isoformat() if data.get("first_seen") else None,
                    data.get("alert_count", 0),
                    1 if ip in compromised else 0,
                    json.dumps({k: v for k, v in data.items()
                               if k not in ("os", "services", "dns", "first_seen", "creds", "flows", "alert_count")})
                ))
        self._dirty = True

    def load_hosts(self) -> tuple:
        """Load hosts and compromised set."""
        hosts = {}
        compromised = set()

        rows = self.conn.execute("SELECT * FROM hosts").fetchall()
        for row in rows:
            ip = row["ip"]
            hosts[ip] = {
                "os": row["os"],
                "services": set(json.loads(row["services"] or "[]")),
                "dns": row["dns"],
                "first_seen": datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None,
                "alert_count": row["alert_count"],
                "creds": [],  # Will be populated separately
                "flows": [],  # Will be populated separately
            }
            # Merge additional properties
            if row["properties"]:
                hosts[ip].update(json.loads(row["properties"]))

            if row["is_compromised"]:
                compromised.add(ip)

        return hosts, compromised

    # ===================
    # Credential Operations
    # ===================

    def save_credentials(self, credentials: List[Any]):
        """Save credentials (encrypted)."""
        with self.transaction():
            # Clear existing and re-save
            self.conn.execute("DELETE FROM credentials")
            for cred in credentials:
                # Encrypt sensitive fields
                hashcat = self._encrypt(cred.hashcat_format) if cred.hashcat_format else None
                raw_data = self._encrypt(json.dumps({
                    "password": getattr(cred, "password", None),
                    "hash": getattr(cred, "hash", None),
                    "ntlm_hash": getattr(cred, "ntlm_hash", None),
                }))

                self.conn.execute("""
                    INSERT INTO credentials
                    (protocol, username, domain, target_ip, target_port, hashcat_format, raw_data, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cred.protocol,
                    cred.username,
                    cred.domain,
                    cred.target_ip,
                    cred.target_port,
                    hashcat,
                    raw_data,
                    datetime.now().isoformat()
                ))
        self._dirty = True

    def load_credentials(self) -> List[Dict]:
        """Load credentials (decrypted)."""
        creds = []
        rows = self.conn.execute("SELECT * FROM credentials ORDER BY id").fetchall()
        for row in rows:
            cred = {
                "protocol": row["protocol"],
                "username": row["username"],
                "domain": row["domain"],
                "target_ip": row["target_ip"],
                "target_port": row["target_port"],
                "hashcat_format": self._decrypt(row["hashcat_format"]) if row["hashcat_format"] else None,
                "timestamp": row["timestamp"],
            }
            # Decrypt raw data
            if row["raw_data"]:
                try:
                    raw = json.loads(self._decrypt(row["raw_data"]))
                    cred.update(raw)
                except:
                    pass
            creds.append(cred)
        return creds

    # ===================
    # Flow Operations
    # ===================

    def save_flows(self, flows: Dict[str, Dict]):
        """Save all flows."""
        with self.transaction():
            for flow_key, data in flows.items():
                first_seen = data.get("first_seen")
                last_seen = data.get("last_seen")
                self.conn.execute("""
                    INSERT OR REPLACE INTO flows
                    (flow_key, src, dst, port, proto, count, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flow_key,
                    data.get("src"),
                    data.get("dst"),
                    data.get("port"),
                    data.get("proto"),
                    data.get("count", 1),
                    first_seen.isoformat() if isinstance(first_seen, datetime) else first_seen,
                    last_seen.isoformat() if isinstance(last_seen, datetime) else last_seen,
                ))
        self._dirty = True

    def load_flows(self) -> Dict[str, Dict]:
        """Load all flows."""
        flows = {}
        rows = self.conn.execute("SELECT * FROM flows").fetchall()
        for row in rows:
            flows[row["flow_key"]] = {
                "src": row["src"],
                "dst": row["dst"],
                "port": row["port"],
                "proto": row["proto"],
                "count": row["count"],
                "first_seen": datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None,
                "last_seen": datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
            }
        return flows

    # ===================
    # DNS Operations
    # ===================

    def save_dns(self, dns_resolutions: Dict[str, List]):
        """Save DNS resolutions."""
        with self.transaction():
            for domain, answers in dns_resolutions.items():
                self.conn.execute("""
                    INSERT OR REPLACE INTO dns (domain, answers)
                    VALUES (?, ?)
                """, (domain, json.dumps([str(a) for a in answers])))
        self._dirty = True

    def load_dns(self) -> Dict[str, List]:
        """Load DNS resolutions."""
        dns = {}
        rows = self.conn.execute("SELECT * FROM dns").fetchall()
        for row in rows:
            dns[row["domain"]] = json.loads(row["answers"] or "[]")
        return dns

    # ===================
    # Alert Operations
    # ===================

    def save_alerts(self, alerts: List[Dict]):
        """Save alerts."""
        with self.transaction():
            # Clear and re-save
            self.conn.execute("DELETE FROM alerts")
            for alert in alerts:
                timestamp = alert.get("time")
                self.conn.execute("""
                    INSERT INTO alerts
                    (severity, type, message, src_ip, dst_ip, target, timestamp, properties)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.get("severity"),
                    alert.get("type"),
                    alert.get("message"),
                    alert.get("src_ip"),
                    alert.get("dst_ip"),
                    alert.get("target"),
                    timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp,
                    json.dumps({k: str(v) for k, v in alert.items()
                               if k not in ("severity", "type", "message", "src_ip", "dst_ip", "target", "time")})
                ))
        self._dirty = True

    def load_alerts(self) -> List[Dict]:
        """Load alerts."""
        alerts = []
        rows = self.conn.execute("SELECT * FROM alerts ORDER BY id").fetchall()
        for row in rows:
            alert = {
                "severity": row["severity"],
                "type": row["type"],
                "message": row["message"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "target": row["target"],
                "time": datetime.fromisoformat(row["timestamp"]) if row["timestamp"] else None,
            }
            if row["properties"]:
                try:
                    alert.update(json.loads(row["properties"]))
                except:
                    pass
            alerts.append(alert)
        return alerts

    # ===================
    # Codename Operations
    # ===================

    def save_codenames(self, codenames: Dict[str, tuple]):
        """Save codenames for consistency."""
        with self.transaction():
            for ip, (name, category, color) in codenames.items():
                self.conn.execute("""
                    INSERT OR REPLACE INTO codenames (ip, codename, category, color)
                    VALUES (?, ?, ?, ?)
                """, (ip, name, category, color))
        self._dirty = True

    def load_codenames(self) -> Dict[str, tuple]:
        """Load codenames."""
        codenames = {}
        rows = self.conn.execute("SELECT * FROM codenames").fetchall()
        for row in rows:
            codenames[row["ip"]] = (row["codename"], row["category"], row["color"])
        return codenames

    # ===================
    # Bulk Operations
    # ===================

    def save_all(
        self,
        source_type: str,
        source_name: str,
        packets: int,
        hosts: Dict[str, Dict],
        flows: Dict[str, Dict],
        credentials: List[Any],
        dns_resolutions: Dict[str, List],
        alerts: List[Dict],
        compromised_hosts: Set[str],
        codenames: Dict[str, tuple]
    ):
        """Save complete session state."""
        self.save_session_metadata(source_type, source_name, packets,
                                   len(credentials), len(hosts), len(alerts))
        self.save_hosts(hosts, compromised_hosts)
        self.save_flows(flows)
        self.save_credentials(credentials)
        self.save_dns(dns_resolutions)
        self.save_alerts(alerts)
        self.save_codenames(codenames)
        self.conn.commit()
        self._last_save = datetime.now()
        self._dirty = False

    def load_all(self) -> Dict[str, Any]:
        """Load complete session state."""
        hosts, compromised = self.load_hosts()
        return {
            "hosts": hosts,
            "flows": self.load_flows(),
            "credentials": self.load_credentials(),
            "dns_resolutions": self.load_dns(),
            "alerts": self.load_alerts(),
            "compromised_hosts": compromised,
            "codenames": self.load_codenames(),
            "metadata": {
                "session_id": self.get_metadata("session_id"),
                "created_at": self.get_metadata("created_at"),
                "updated_at": self.get_metadata("updated_at"),
                "source_type": self.get_metadata("source_type"),
                "source_name": self.get_metadata("source_name"),
                "packets_processed": int(self.get_metadata("packets_processed") or 0),
            }
        }

    def should_auto_save(self) -> bool:
        """Check if auto-save should trigger."""
        if self.auto_save_interval <= 0:
            return False
        elapsed = (datetime.now() - self._last_save).total_seconds()
        return elapsed >= self.auto_save_interval and self._dirty

    def mark_dirty(self):
        """Mark session as having unsaved changes."""
        self._dirty = True

    # ===================
    # Session Discovery
    # ===================

    @staticmethod
    def list_sessions(base_path: Optional[str] = None) -> List[Dict]:
        """List available session files with metadata."""
        base = Path(base_path) if base_path else Path.home() / ".pcap-intel" / "sessions"
        if not base.exists():
            return []

        sessions = []
        for db_file in base.glob("*.db"):
            try:
                conn = sqlite3.connect(str(db_file))
                conn.row_factory = sqlite3.Row

                # Get metadata
                metadata = {}
                rows = conn.execute("SELECT key, value FROM metadata").fetchall()
                for row in rows:
                    metadata[row["key"]] = row["value"]

                sessions.append({
                    "path": str(db_file),
                    "filename": db_file.name,
                    "size_mb": db_file.stat().st_size / (1024 * 1024),
                    **metadata
                })
                conn.close()
            except Exception:
                continue

        # Sort by updated_at descending
        sessions.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
        return sessions

    @staticmethod
    def load_session(db_path: str, encryption_key: Optional[str] = None) -> 'SessionStorage':
        """Load an existing session file."""
        storage = SessionStorage(db_path=db_path, encryption_key=encryption_key)
        return storage


# Convenience function for TUI integration
def create_session_storage(
    source_type: str = "interface",
    source_name: str = "unknown",
    encryption_key: Optional[str] = None
) -> SessionStorage:
    """Create a new session storage instance."""
    return SessionStorage(encryption_key=encryption_key)
