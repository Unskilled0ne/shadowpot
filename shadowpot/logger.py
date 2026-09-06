import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger("shadowpot.logger")

MITRE_MAPPINGS = {
    "auth_attempt": {"id": "T1110.001", "tactic": "Credential Access", "technique": "Password Guessing"},
    "auth_success": {"id": "T1078.003", "tactic": "Initial Access", "technique": "Local Accounts"},
    "auth_failure": {"id": "T1110.001", "tactic": "Credential Access", "technique": "Password Guessing"},
    "command_exec": {"id": "T1059.004", "tactic": "Execution", "technique": "Unix Shell"},
    "payload_download": {"id": "T1105", "tactic": "Command and Control", "technique": "Ingress Tool Transfer"},
    "recon_discovery": {"id": "T1082", "tactic": "Discovery", "technique": "System Information Discovery"},
    "account_discovery": {"id": "T1087.001", "tactic": "Discovery", "technique": "Local Accounts Discovery"},
    "network_discovery": {"id": "T1016", "tactic": "Discovery", "technique": "System Network Configuration Discovery"}
}

class EventLogger:
    def __init__(self, json_log_path: str = "logs/shadowpot.json", db_path: str = "data/shadowpot.db"):
        self.json_log_path = json_log_path
        self.db_path = db_path
        self._lock = threading.Lock()
        self._listeners: List[Callable[[Dict[str, Any]], None]] = []

        os.makedirs(os.path.dirname(self.json_log_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp TEXT,
                event_type TEXT,
                src_ip TEXT,
                src_port INTEGER,
                username TEXT,
                password TEXT,
                command TEXT,
                country TEXT,
                city TEXT,
                org TEXT,
                mitre_id TEXT,
                mitre_tactic TEXT,
                raw_json TEXT
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                start_time TEXT,
                last_activity TEXT,
                src_ip TEXT,
                src_port INTEGER,
                username TEXT,
                password TEXT,
                authenticated INTEGER,
                country TEXT,
                city TEXT,
                command_count INTEGER DEFAULT 0
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp TEXT,
                src_ip TEXT,
                url TEXT,
                sha256 TEXT,
                md5 TEXT,
                size_bytes INTEGER,
                quarantine_path TEXT
            )
            """)
            conn.commit()

    def register_listener(self, callback: Callable[[Dict[str, Any]], None]):
        self._listeners.append(callback)

    def log_event(self, event_type: str, session_id: str, src_ip: str, src_port: int,
                  username: Optional[str] = None, password: Optional[str] = None,
                  command: Optional[str] = None, threat_intel: Optional[Dict[str, Any]] = None,
                  extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Emits structured JSON for SIEM/Wazuh and stores in SQLite.
        """
        now = datetime.now(timezone.utc).isoformat()
        threat_intel = threat_intel or {}
        extra = extra or {}

        # Classify MITRE ATT&CK
        mitre_info = MITRE_MAPPINGS.get(event_type, {"id": "T1059", "tactic": "Execution", "technique": "Command Execution"})
        if command:
            cmd_lower = command.lower().strip()
            if any(x in cmd_lower for x in ["uname", "uptime", "cat /etc/issue", "cat /etc/os-release"]):
                mitre_info = MITRE_MAPPINGS["recon_discovery"]
            elif any(x in cmd_lower for x in ["cat /etc/passwd", "whoami", "id", "groups"]):
                mitre_info = MITRE_MAPPINGS["account_discovery"]
            elif any(x in cmd_lower for x in ["ifconfig", "ip a", "netstat", "ss ", "route"]):
                mitre_info = MITRE_MAPPINGS["network_discovery"]
            elif any(x in cmd_lower for x in ["curl", "wget", "ftpget", "tftp"]):
                mitre_info = MITRE_MAPPINGS["payload_download"]

        event = {
            "timestamp": now,
            "honeypot": "ShadowPot",
            "event_type": event_type,
            "session_id": session_id,
            "source": {
                "ip": src_ip,
                "port": src_port,
                "country": threat_intel.get("country", "Unknown"),
                "country_code": threat_intel.get("country_code", "XX"),
                "city": threat_intel.get("city", "Unknown"),
                "org": threat_intel.get("org", "Unknown")
            },
            "auth": {
                "username": username,
                "password": password
            } if username or password else None,
            "command": command,
            "mitre": {
                "id": mitre_info["id"],
                "tactic": mitre_info["tactic"],
                "technique": mitre_info["technique"]
            },
            "extra": extra
        }

        # Write to JSON file for Wazuh / SIEM
        with self._lock:
            with open(self.json_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")

            # Store in SQLite
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                    INSERT INTO events (session_id, timestamp, event_type, src_ip, src_port,
                                        username, password, command, country, city, org,
                                        mitre_id, mitre_tactic, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        session_id, now, event_type, src_ip, src_port,
                        username, password, command,
                        threat_intel.get("country"), threat_intel.get("city"), threat_intel.get("org"),
                        mitre_info["id"], mitre_info["tactic"], json.dumps(event)
                    ))

                    # Track session
                    if event_type in ("auth_success", "auth_attempt"):
                        is_auth = 1 if event_type == "auth_success" else 0
                        cursor.execute("""
                        INSERT INTO sessions (session_id, start_time, last_activity, src_ip, src_port,
                                             username, password, authenticated, country, city)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(session_id) DO UPDATE SET
                            last_activity = excluded.last_activity,
                            authenticated = max(sessions.authenticated, excluded.authenticated),
                            username = coalesce(sessions.username, excluded.username),
                            password = coalesce(sessions.password, excluded.password)
                        """, (
                            session_id, now, now, src_ip, src_port,
                            username, password, is_auth,
                            threat_intel.get("country"), threat_intel.get("city")
                        ))
                    elif event_type == "command_exec":
                        cursor.execute("""
                        UPDATE sessions
                        SET command_count = command_count + 1, last_activity = ?
                        WHERE session_id = ?
                        """, (now, session_id))

                    # Track payloads
                    if "captured_files" in extra:
                        for item in extra["captured_files"]:
                            if item.get("downloaded"):
                                cursor.execute("""
                                INSERT INTO payloads (session_id, timestamp, src_ip, url, sha256, md5, size_bytes, quarantine_path)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    session_id, now, src_ip, item.get("url"), item.get("sha256"),
                                    item.get("md5"), item.get("size_bytes"), item.get("quarantine_path")
                                ))

                    conn.commit()
            except Exception as e:
                logger.error(f"Error persisting event to SQLite: {e}")

        # Notify active streaming listeners (for Web Dashboard)
        for listener in self._listeners:
            try:
                listener(event)
            except Exception as e:
                logger.debug(f"Listener notification error: {e}")

        return event

    def get_stats(self) -> Dict[str, Any]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            c.execute("SELECT COUNT(*) FROM events")
            total_events = c.fetchone()[0]

            c.execute("SELECT COUNT(DISTINCT src_ip) FROM events")
            unique_ips = c.fetchone()[0]

            c.execute("SELECT COUNT(*) FROM sessions WHERE authenticated = 1")
            successful_logins = c.fetchone()[0]

            c.execute("SELECT COUNT(*) FROM payloads")
            total_payloads = c.fetchone()[0]

            c.execute("""
            SELECT username, count(*) as count
            FROM events WHERE username IS NOT NULL and username != ''
            GROUP BY username ORDER BY count DESC LIMIT 5
            """)
            top_users = [dict(row) for row in c.fetchall()]

            c.execute("""
            SELECT password, count(*) as count
            FROM events WHERE password IS NOT NULL and password != ''
            GROUP BY password ORDER BY count DESC LIMIT 5
            """)
            top_passwords = [dict(row) for row in c.fetchall()]

            c.execute("""
            SELECT country, count(*) as count
            FROM events WHERE country IS NOT NULL and country != ''
            GROUP BY country ORDER BY count DESC LIMIT 5
            """)
            top_countries = [dict(row) for row in c.fetchall()]

            c.execute("""
            SELECT command, count(*) as count
            FROM events WHERE command IS NOT NULL and command != ''
            GROUP BY command ORDER BY count DESC LIMIT 5
            """)
            top_commands = [dict(row) for row in c.fetchall()]

            return {
                "total_events": total_events,
                "unique_ips": unique_ips,
                "successful_logins": successful_logins,
                "captured_payloads": total_payloads,
                "top_usernames": top_users,
                "top_passwords": top_passwords,
                "top_countries": top_countries,
                "top_commands": top_commands
            }

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
            SELECT id, session_id, timestamp, event_type, src_ip, username, password, command,
                   country, city, org, mitre_id, mitre_tactic
            FROM events ORDER BY id DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in c.fetchall()]

    def get_payloads(self, limit: int = 20) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
            SELECT id, session_id, timestamp, src_ip, url, sha256, md5, size_bytes, quarantine_path
            FROM payloads ORDER BY id DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in c.fetchall()]
