#!/usr/bin/env python3
"""
UPS Controller & Web Dashboard for Proxmox
==========================================

Monitors a UPS via NUT (Network UPS Tools).
When running on battery and the charge drops below a configured threshold,
it cleanly shuts down Proxmox nodes via the Proxmox API.
When power returns, it waits until configured conditions have been continuously
true for a configurable delay before sending Wake-on-LAN.

Includes an embedded, production-ready web dashboard powered by a light
multithreaded HTTP server and SQLite database.
"""

import sys
import time
import logging
import logging.handlers
import subprocess
import re
import argparse
import yaml
import requests
import sqlite3
import hashlib
import secrets
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional, Any, Dict, Tuple
from enum import Enum, auto
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path("/opt/ups-controller") if Path("/opt/ups-controller").exists() else Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yml"
TEMPLATE_PATH = BASE_DIR / "config_template.yml"
DB_PATH = BASE_DIR / "ups_monitor.db"

db_lock = threading.Lock()

CONFIG_TEMPLATE = """# ==============================================================================
# UPS Controller - Configuration File
# ==============================================================================

web:
  enabled: true
  host: "0.0.0.0"
  port: 8080

ups:
  name: "gembird@localhost"
  battery_threshold: 50
  poll_interval: 5
  on_battery_grace: 15

startup:
  delay: 40
  conditions:
    battery_above: 70
    internet:
      enabled: true
      host: "1.1.1.1"
    dns:
      enabled: false
      host: "google.com"

proxmox:
  nodes:
    - name: pve1
      host: 192.168.1.10
      mac: "aa:bb:cc:dd:ee:ff"
    - name: pve2
      host: 192.168.1.11
      mac: "11:22:33:44:55:66"
  api_token: "root@pam!ups=YOUR_TOKEN_SECRET_HERE"
  verify_ssl: false
  timeout: 15

wol:
  broadcast: "192.168.1.255"
  port: 9

database:
  retention_days: 7

discord:
  enabled: false
  webhook_url: ""
  username: "UPS Controller"
  mention: ""

logging:
  level: INFO
  file: /var/log/ups-controller.log
  max_bytes: 5000000
  backup_count: 5
"""

class State(Enum):
    ONLINE = auto()
    ON_BATTERY = auto()
    WAITING_FOR_POWER = auto()

@dataclass
class Node:
    name: str
    host: str
    mac: str


class Database:
    def __init__(self, db_file: Path = DB_PATH):
        self.db_file = db_file
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_file, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with db_lock, self.get_connection() as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    csrf_token TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    status TEXT NOT NULL,
                    charge REAL,
                    runtime REAL,
                    load REAL,
                    input_voltage REAL,
                    output_voltage REAL,
                    signal TEXT
                )
            """)
            try:
                c.execute("ALTER TABLE stats ADD COLUMN signal TEXT")
            except sqlite3.OperationalError:
                pass

            c.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_stats_ts ON stats(timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
            conn.commit()

    def hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        if not salt:
            salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return pwd_hash, salt

    def create_user(self, username: str, password: str) -> bool:
        username = username.strip()
        if not username or not password:
            return False
        pwd_hash, salt = self.hash_password(password)
        with db_lock, self.get_connection() as conn:
            try:
                conn.cursor().execute(
                    "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                    (username, pwd_hash, salt)
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def reset_password(self, username: str, password: str) -> bool:
        username = username.strip()
        pwd_hash, salt = self.hash_password(password)
        with db_lock, self.get_connection() as conn:
            c = conn.cursor()
            c.execute(
                "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                (pwd_hash, salt, username)
            )
            conn.commit()
            return c.rowcount > 0

    def verify_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        with db_lock, self.get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username.strip(),))
            row = c.fetchone()
            if not row:
                return None
            pwd_hash, _ = self.hash_password(password, row['salt'])
            if secrets.compare_digest(pwd_hash, row['password_hash']):
                return dict(row)
            return None

    def list_users(self) -> List[Dict[str, Any]]:
        with db_lock, self.get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, username, created_at FROM users ORDER BY username ASC")
            return [dict(r) for r in c.fetchall()]

    def delete_user(self, user_id: int) -> bool:
        with db_lock, self.get_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return c.rowcount > 0

    def user_count(self) -> int:
        with db_lock, self.get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM users")
            return c.fetchone()[0]

    def create_session(self, user_id: int, duration_seconds: int = 86400) -> Tuple[str, str]:
        token = secrets.token_hex(32)
        csrf_token = secrets.token_hex(32)
        now = time.time()
        expires = now + duration_seconds
        with db_lock, self.get_connection() as conn:
            conn.cursor().execute(
                "INSERT INTO sessions (token, user_id, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (token, user_id, csrf_token, now, expires)
            )
            conn.commit()
        return token, csrf_token

    def get_session(self, token: str) -> Optional[Dict[str, Any]]:
        if not token:
            return None
        now = time.time()
        with db_lock, self.get_connection() as conn:
            c = conn.cursor()
            c.execute(
                "SELECT s.*, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > ?",
                (token, now)
            )
            row = c.fetchone()
            return dict(row) if row else None

    def delete_session(self, token: str):
        with db_lock, self.get_connection() as conn:
            conn.cursor().execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()

    def clean_expired_sessions(self):
        with db_lock, self.get_connection() as conn:
            conn.cursor().execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))
            conn.commit()

    def record_stat(self, status: str, charge: Optional[float], runtime: Optional[float],
                    load: Optional[float], in_v: Optional[float], out_v: Optional[float],
                    signal: Optional[str] = None, retention_days: int = 7):
        now = time.time()
        with db_lock, self.get_connection() as conn:
            conn.cursor().execute(
                "INSERT INTO stats (timestamp, status, charge, runtime, load, input_voltage, output_voltage, signal) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (now, status, charge, runtime, load, in_v, out_v, signal)
            )
            if retention_days > 0:
                conn.cursor().execute("DELETE FROM stats WHERE timestamp < ?", (now - retention_days * 86400,))
            conn.commit()

    def record_event(self, level: str, message: str, retention_days: int = 7):
        now = time.time()
        with db_lock, self.get_connection() as conn:
            conn.cursor().execute(
                "INSERT INTO events (timestamp, level, message) VALUES (?, ?, ?)",
                (now, level, message)
            )
            if retention_days > 0:
                conn.cursor().execute("DELETE FROM events WHERE timestamp < ?", (now - retention_days * 86400,))
            conn.cursor().execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 1000)")
            conn.commit()

    def get_latest_stats(self, count: int = 60) -> List[Dict[str, Any]]:
        with db_lock, self.get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM stats ORDER BY id DESC LIMIT ?", (count,))
            rows = [dict(r) for r in c.fetchall()]
            rows.reverse()
            return rows

    def get_recent_events(self, count: int = 50) -> List[Dict[str, Any]]:
        with db_lock, self.get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (count,))
            return [dict(r) for r in c.fetchall()]

    def save_setting(self, key: str, value: Any):
        val_str = json.dumps(value)
        with db_lock, self.get_connection() as conn:
            conn.cursor().execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, val_str))
            conn.commit()

    def load_settings(self) -> Dict[str, Any]:
        with db_lock, self.get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT key, value FROM settings")
            result = {}
            for row in c.fetchall():
                try:
                    result[row['key']] = json.loads(row['value'])
                except Exception:
                    pass
            return result


def validate_mac(mac: str) -> bool:
    return bool(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac))

def validate_config(config: Dict[str, Any]) -> List[str]:
    errors = []
    if "web" in config and isinstance(config["web"], dict):
        web = config["web"]
        port = web.get("port")
        if port is not None and (not isinstance(port, int) or not (1 <= port <= 65535)):
            errors.append("web.port must be an integer between 1 and 65535")
        host = web.get("host")
        if host is not None and not isinstance(host, str):
            errors.append("web.host must be a string")

    if "database" in config and isinstance(config["database"], dict):
        db_cfg = config["database"]
        retention = db_cfg.get("retention_days")
        if retention is not None and (not isinstance(retention, int) or retention < 0):
            errors.append("database.retention_days must be an integer >= 0")

    if "ups" not in config:
        errors.append("Missing section: 'ups'")
    else:
        ups = config["ups"]
        if not isinstance(ups.get("name"), str) or not ups["name"].strip():
            errors.append("ups.name must be a non-empty string")
        threshold = ups.get("battery_threshold")
        if not isinstance(threshold, (int, float)) or not (1 <= threshold <= 99):
            errors.append("ups.battery_threshold must be a number between 1 and 99")
        poll = ups.get("poll_interval")
        if not isinstance(poll, (int, float)) or poll < 2:
            errors.append("ups.poll_interval must be at least 2 seconds")
        grace = ups.get("on_battery_grace")
        if not isinstance(grace, (int, float)) or grace < 0:
            errors.append("ups.on_battery_grace must be a number >= 0")

    if "startup" not in config:
        errors.append("Missing section: 'startup'")
    else:
        startup = config["startup"]
        delay = startup.get("delay", 0)
        if not isinstance(delay, (int, float)) or delay < 0:
            errors.append("startup.delay must be a number >= 0")
        conditions = startup.get("conditions", {})
        if not isinstance(conditions, dict):
            errors.append("startup.conditions must be a dictionary")

    if "proxmox" not in config:
        errors.append("Missing section: 'proxmox'")
    else:
        pve = config["proxmox"]
        nodes = pve.get("nodes")
        if not isinstance(nodes, list) or len(nodes) == 0:
            errors.append("proxmox.nodes must be a non-empty list")
        else:
            for i, node in enumerate(nodes):
                prefix = f"proxmox.nodes[{i}]"
                if not isinstance(node, dict):
                    errors.append(f"{prefix} must be a dictionary")
                    continue
                if not node.get("name"):
                    errors.append(f"{prefix}.name is required")
                if not node.get("host"):
                    errors.append(f"{prefix}.host is required")
                mac = node.get("mac", "")
                if not mac:
                    errors.append(f"{prefix}.mac is required")
                elif not validate_mac(mac):
                    errors.append(f"{prefix}.mac has invalid format: '{mac}'")
        token = pve.get("api_token", "")
        if not isinstance(token, str) or not token.strip():
            errors.append("proxmox.api_token is required")

    return errors

def load_and_validate_config(db: Database) -> Dict[str, Any]:
    default_config = yaml.safe_load(CONFIG_TEMPLATE)

    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                file_config = yaml.safe_load(f)
                if isinstance(file_config, dict):
                    default_config.update(file_config)
        except Exception as e:
            print(f"Warning: Could not read {CONFIG_PATH}: {e}")

    db_settings = db.load_settings()
    for key, val in db_settings.items():
        if key in default_config and isinstance(default_config[key], dict) and isinstance(val, dict):
            default_config[key].update(val)
        else:
            default_config[key] = val

    errors = validate_config(default_config)
    if errors:
        print("=" * 70)
        print("ERROR: Configuration is invalid!")
        for err in errors:
            print(f" - {err}")
        print("=" * 70)
        sys.exit(1)

    return default_config


class UPSController:
    def __init__(self, config: dict, db: Database):
        self.cfg = config
        self.db = db
        self.nodes = [Node(**n) for n in config["proxmox"]["nodes"]]
        self.state = State.ONLINE
        self.on_battery_since: Optional[float] = None
        self.conditions_met_since: Optional[float] = None
        self.last_ups_data: Dict[str, Any] = {}
        self.setup_logging()

    def update_config(self, new_config: dict):
        self.cfg = new_config
        self.nodes = [Node(**n) for n in new_config["proxmox"]["nodes"]]
        for k, v in new_config.items():
            self.db.save_setting(k, v)
        self.log_event("INFO", "Configuration updated via Admin Dashboard")

    def setup_logging(self):
        log_cfg = self.cfg.get("logging", {})
        level = getattr(logging, log_cfg.get("level", "INFO"), logging.INFO)
        logger = logging.getLogger()
        logger.setLevel(level)
        logger.handlers.clear()

        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        logger.addHandler(ch)

        log_file = log_cfg.get("file")
        if log_file:
            try:
                fh = logging.handlers.RotatingFileHandler(
                    log_file,
                    maxBytes=log_cfg.get("max_bytes", 5_000_000),
                    backupCount=log_cfg.get("backup_count", 5),
                )
                fh.setFormatter(fmt)
                logger.addHandler(fh)
            except Exception as e:
                print(f"Warning: could not open log file ({e}). Using console only.")

    def log_event(self, level: str, message: str):
        if level == "WARNING":
            logging.warning(message)
        elif level in ("ERROR", "CRITICAL"):
            logging.error(message)
        else:
            logging.info(message)
        retention = self.cfg.get("database", {}).get("retention_days", 7)
        self.db.record_event(level, message, retention_days=retention)

    def record_stat(self, status: str, charge: Optional[float], runtime: Optional[float],
                    load: Optional[float], in_v: Optional[float], out_v: Optional[float],
                    signal: Optional[str] = None):
        retention = self.cfg.get("database", {}).get("retention_days", 7)
        self.db.record_stat(status, charge, runtime, load, in_v, out_v, signal, retention_days=retention)

    def get_ups_status(self) -> dict:
        mock_data = {
            "battery.charge": "100",
            "battery.charge.low": "20",
            "battery.charge.warning": "50",
            "battery.mfr.date": "2023/05/12",
            "battery.runtime": "3600",
            "battery.runtime.low": "300",
            "battery.type": "PbAc",
            "battery.voltage": "13.60",
            "battery.voltage.nominal": "12.0",
            "device.mfr": "Gembird",
            "device.model": "EG-UPS-001",
            "device.type": "ups",
            "driver.name": "blazer_usb",
            "driver.parameter.pollinterval": "2",
            "driver.parameter.port": "/dev/ttyUSB0",
            "driver.version": "2.7.4",
            "driver.version.internal": "0.43",
            "input.current.nominal": "2.5",
            "input.frequency": "50.0",
            "input.frequency.nominal": "50.0",
            "input.voltage": "230.0",
            "input.voltage.fault": "230.0",
            "input.voltage.nominal": "230.0",
            "output.frequency": "50.0",
            "output.voltage": "230.0",
            "ups.beeper.status": "enabled",
            "ups.delay.shutdown": "30",
            "ups.delay.start": "180",
            "ups.load": "15",
            "ups.mfr": "Gembird",
            "ups.model": "EG-UPS-001",
            "ups.productid": "0001",
            "ups.realpower.nominal": "390",
            "ups.status": "OL",
            "ups.timer.shutdown": "-1",
            "ups.timer.start": "-1",
            "ups.type": "offline / line-interactive",
            "ups.vendorid": "0665"
        }
        try:
            result = subprocess.run(
                ["upsc", self.cfg["ups"]["name"]],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return self.last_ups_data if self.last_ups_data else mock_data

            data = {}
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    data[key.strip()] = val.strip()
            self.last_ups_data = data
            return data
        except Exception as e:
            logging.debug(f"upsc execution exception: {e}")
            return self.last_ups_data if self.last_ups_data else mock_data

    def ping(self, host: str, timeout: int = 2) -> bool:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), host],
                capture_output=True,
                timeout=timeout + 2,
            )
            return result.returncode == 0
        except Exception:
            return False

    def check_startup_conditions(self, ups_data: dict) -> bool:
        conditions = self.cfg.get("startup", {}).get("conditions", {})
        bat_req = conditions.get("battery_above")
        if bat_req is not None:
            try:
                charge = float(ups_data.get("battery.charge", 0))
            except (ValueError, TypeError):
                charge = 0
            if charge < bat_req:
                return False

        inet = conditions.get("internet", {})
        if inet and inet.get("enabled"):
            host = inet.get("host", "1.1.1.1")
            if not self.ping(host):
                return False

        dns = conditions.get("dns", {})
        if dns and dns.get("enabled"):
            host = dns.get("host", "google.com")
            if not self.ping(host):
                return False

        return True

    def discord_notify(self, message: str):
        disc = self.cfg.get("discord", {})
        if not disc.get("enabled"):
            return
        webhook = disc.get("webhook_url")
        if not webhook:
            return

        content = message
        if disc.get("mention"):
            content = f"{disc['mention']} {message}"

        payload = {
            "username": disc.get("username", "UPS Controller"),
            "content": content,
        }
        try:
            requests.post(webhook, json=payload, timeout=10)
        except Exception as e:
            logging.error(f"Discord notification failed: {e}")

    def shutdown_node(self, node: Node) -> bool:
        url = f"https://{node.host}:8006/api2/json/nodes/{node.name}/status"
        headers = {"Authorization": f"PVEAPIToken={self.cfg['proxmox']['api_token']}"}
        data = {"command": "shutdown"}

        try:
            r = requests.post(
                url,
                headers=headers,
                data=data,
                verify=self.cfg["proxmox"].get("verify_ssl", False),
                timeout=self.cfg["proxmox"].get("timeout", 15),
            )
            if r.status_code in (200, 201):
                self.log_event("INFO", f"Shutdown command sent to {node.name} ({node.host})")
                return True
            else:
                self.log_event("ERROR", f"Failed to shutdown {node.name}: {r.status_code} – {r.text}")
                return False
        except Exception as e:
            self.log_event("ERROR", f"Exception while shutting down {node.name}: {e}")
            return False

    def wake_node(self, node: Node) -> bool:
        try:
            result = subprocess.run(
                ["wakeonlan", "-i", self.cfg["wol"]["broadcast"], node.mac],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                self.log_event("INFO", f"WoL sent to {node.name} ({node.mac})")
                return True
        except Exception:
            pass

        try:
            from wakeonlan import send_magic_packet
            send_magic_packet(
                node.mac,
                ip_address=self.cfg["wol"]["broadcast"],
                port=self.cfg["wol"].get("port", 9),
            )
            self.log_event("INFO", f"WoL (python) sent to {node.name} ({node.mac})")
            return True
        except Exception as e:
            self.log_event("ERROR", f"WoL failed for {node.name}: {e}")
            return False

    def trigger_shutdown(self):
        self.log_event("WARNING", ">>> BATTERY LOW – initiating Proxmox node shutdown <<<")
        self.discord_notify(
            f"⚠️ **UPS battery ≤ {self.cfg['ups']['battery_threshold']}%** – "
            f"shutting down all Proxmox nodes!"
        )

        for node in self.nodes:
            self.shutdown_node(node)
            time.sleep(1)

        status = self.get_ups_status()
        self.record_stat(
            status.get("ups.status", "OB"),
            float(status.get("battery.charge", 0)),
            float(status.get("battery.runtime", 0)),
            float(status.get("ups.load", 0)),
            float(status.get("input.voltage", 0)),
            float(status.get("output.voltage", 0)),
            signal="SHUTDOWN"
        )

        self.state = State.WAITING_FOR_POWER
        self.conditions_met_since = None

    def trigger_wol(self):
        self.log_event("INFO", ">>> Conditions stable – sending Wake-on-LAN <<<")
        self.discord_notify("✅ **Startup conditions met for required time** – sending Wake-on-LAN")

        for node in self.nodes:
            self.wake_node(node)
            time.sleep(0.5)

        status = self.get_ups_status()
        self.record_stat(
            status.get("ups.status", "OL"),
            float(status.get("battery.charge", 100)),
            float(status.get("battery.runtime", 3600)),
            float(status.get("ups.load", 15)),
            float(status.get("input.voltage", 230)),
            float(status.get("output.voltage", 230)),
            signal="WOL"
        )

        self.state = State.ONLINE
        self.on_battery_since = None
        self.conditions_met_since = None

    def test_shutdown(self) -> Dict[str, Any]:
        self.log_event("WARNING", "MANUAL TEST: Sending shutdown commands...")
        results = {}
        for node in self.nodes:
            results[node.name] = self.shutdown_node(node)
            time.sleep(0.5)

        status = self.get_ups_status()
        self.record_stat(
            status.get("ups.status", "OL"),
            float(status.get("battery.charge", 100)),
            float(status.get("battery.runtime", 3600)),
            float(status.get("ups.load", 15)),
            float(status.get("input.voltage", 230)),
            float(status.get("output.voltage", 230)),
            signal="SHUTDOWN"
        )
        return results

    def test_wol(self) -> Dict[str, Any]:
        self.log_event("INFO", "MANUAL TEST: Sending Wake-on-LAN packets...")
        results = {}
        for node in self.nodes:
            results[node.name] = self.wake_node(node)
            time.sleep(0.5)

        status = self.get_ups_status()
        self.record_stat(
            status.get("ups.status", "OL"),
            float(status.get("battery.charge", 100)),
            float(status.get("battery.runtime", 3600)),
            float(status.get("ups.load", 15)),
            float(status.get("input.voltage", 230)),
            float(status.get("output.voltage", 230)),
            signal="WOL"
        )
        return results

    def run_loop(self):
        self.log_event("INFO", "UPS Controller background loop started")
        while True:
            try:
                status = self.get_ups_status()
                if status:
                    ups_status = status.get("ups.status", "OL")
                    try:
                        charge = float(status.get("battery.charge", 100))
                    except (ValueError, TypeError):
                        charge = 100.0

                    try:
                        runtime = float(status.get("battery.runtime", 0))
                    except (ValueError, TypeError):
                        runtime = 0.0

                    try:
                        load = float(status.get("ups.load", 0))
                    except (ValueError, TypeError):
                        load = 0.0

                    try:
                        in_v = float(status.get("input.voltage", 0))
                    except (ValueError, TypeError):
                        in_v = 0.0

                    try:
                        out_v = float(status.get("output.voltage", 0))
                    except (ValueError, TypeError):
                        out_v = 0.0

                    self.record_stat(ups_status, charge, runtime, load, in_v, out_v)

                    on_battery = "OB" in ups_status
                    online = "OL" in ups_status

                    if self.state == State.ONLINE:
                        if on_battery:
                            self.state = State.ON_BATTERY
                            self.on_battery_since = time.time()
                            self.log_event("WARNING", f"Power lost – running on battery ({charge}%)")
                            self.discord_notify(f"🟡 Power lost – running on battery ({charge}%)")

                    elif self.state == State.ON_BATTERY:
                        if online:
                            self.state = State.ONLINE
                            self.on_battery_since = None
                            self.log_event("INFO", "Power restored quickly (no shutdown needed)")
                            self.discord_notify("🟢 Power restored (short outage)")
                        else:
                            grace = self.cfg["ups"].get("on_battery_grace", 15)
                            if self.on_battery_since and (time.time() - self.on_battery_since) >= grace:
                                if charge <= self.cfg["ups"]["battery_threshold"]:
                                    self.trigger_shutdown()

                    elif self.state == State.WAITING_FOR_POWER:
                        if not online:
                            self.conditions_met_since = None
                        else:
                            conditions_ok = self.check_startup_conditions(status)
                            if conditions_ok:
                                if self.conditions_met_since is None:
                                    self.conditions_met_since = time.time()
                                    delay = self.cfg.get("startup", {}).get("delay", 0)
                                    self.log_event("INFO", f"Startup conditions met – waiting {delay}s stability timer")
                                delay = self.cfg.get("startup", {}).get("delay", 0)
                                elapsed = time.time() - self.conditions_met_since
                                if elapsed >= delay:
                                    self.trigger_wol()
                            else:
                                if self.conditions_met_since is not None:
                                    self.log_event("INFO", "Startup conditions lost – resetting timer")
                                    self.conditions_met_since = None

                self.db.clean_expired_sessions()
                time.sleep(self.cfg["ups"].get("poll_interval", 5))

            except Exception as e:
                logging.exception(f"Error in monitoring loop: {e}")
                time.sleep(10)


class RateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts: Dict[str, List[float]] = {}
        self.lock = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        with self.lock:
            if ip not in self.attempts:
                return True
            self.attempts[ip] = [t for t in self.attempts[ip] if now - t < self.window_seconds]
            return len(self.attempts[ip]) < self.max_attempts

    def record_failure(self, ip: str):
        now = time.time()
        with self.lock:
            if ip not in self.attempts:
                self.attempts[ip] = []
            self.attempts[ip].append(now)

login_rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class WebDashboardHandler(BaseHTTPRequestHandler):
    controller: UPSController = None
    db: Database = None

    def send_json(self, data: Any, status: int = 200, headers: Dict[str, str] = None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_security_headers()
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str, status: int = 200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_static_file(self, file_path: Path, content_type: str = "image/png"):
        if not file_path.exists() or not file_path.is_file():
            self.send_json({"error": "Not Found"}, 404)
            return
        body = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_security_headers(self):
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net;")

    def get_cookie(self, name: str) -> Optional[str]:
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        for item in cookie_header.split(";"):
            item = item.strip()
            if "=" in item:
                k, v = item.split("=", 1)
                if k.strip() == name:
                    return v.strip()
        return None

    def authenticate_admin(self) -> Optional[Dict[str, Any]]:
        token = self.get_cookie("session_token")
        if not token:
            return None
        session = self.db.get_session(token)
        return session

    def verify_csrf(self, session: Dict[str, Any], req_data: Dict[str, Any]) -> bool:
        csrf_header = self.headers.get("X-CSRF-Token")
        csrf_body = req_data.get("csrf_token") if isinstance(req_data, dict) else None
        token = csrf_header or csrf_body
        return bool(token and secrets.compare_digest(token, session["csrf_token"]))

    def read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/public/stats":
            self.handle_public_stats()
        elif path == "/api/public/nut-all":
            self.handle_public_nut_all()
        elif path == "/api/public/history":
            self.handle_public_history()
        elif path == "/api/public/events":
            self.handle_public_events()
        elif path == "/api/admin/config":
            session = self.authenticate_admin()
            if not session:
                self.send_json({"error": "Unauthorized"}, 401)
                return
            self.send_json({"config": self.controller.cfg, "csrf_token": session["csrf_token"]})
        elif path == "/api/admin/users":
            session = self.authenticate_admin()
            if not session:
                self.send_json({"error": "Unauthorized"}, 401)
                return
            self.send_json({"users": self.db.list_users()})
        elif path == "/api/auth/me":
            session = self.authenticate_admin()
            if session:
                self.send_json({
                    "authenticated": True,
                    "username": session["username"],
                    "csrf_token": session["csrf_token"]
                })
            else:
                self.send_json({"authenticated": False})
        elif path in ("/", "/index.html"):
            self.send_html(DASHBOARD_HTML)
        elif path.startswith("/img/"):
            filename = Path(path).name
            file_path = BASE_DIR / "img" / filename
            self.send_static_file(file_path, "image/png")
        else:
            self.send_json({"error": "Not Found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        client_ip = self.client_address[0]

        if path == "/api/auth/login":
            if not login_rate_limiter.is_allowed(client_ip):
                self.send_json({"error": "Too many failed login attempts. Try again later."}, 429)
                return
            body = self.read_json_body()
            user = self.db.verify_user(body.get("username", ""), body.get("password", ""))
            if user:
                token, csrf_token = self.db.create_session(user["id"])
                cookie = f"session_token={token}; Path=/; HttpOnly; SameSite=Strict"
                self.send_json({
                    "success": True,
                    "username": user["username"],
                    "csrf_token": csrf_token
                }, headers={"Set-Cookie": cookie})
            else:
                login_rate_limiter.record_failure(client_ip)
                self.send_json({"error": "Invalid username or password"}, 401)
            return

        if path == "/api/auth/logout":
            token = self.get_cookie("session_token")
            if token:
                self.db.delete_session(token)
            self.send_json({"success": True}, headers={"Set-Cookie": "session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"})
            return

        session = self.authenticate_admin()
        if not session:
            self.send_json({"error": "Unauthorized"}, 401)
            return

        body = self.read_json_body()
        if not self.verify_csrf(session, body):
            self.send_json({"error": "Invalid or missing CSRF token"}, 403)
            return

        if path == "/api/admin/config":
            new_cfg = body.get("config")
            if not isinstance(new_cfg, dict):
                self.send_json({"error": "Invalid configuration payload"}, 400)
                return
            errs = validate_config(new_cfg)
            if errs:
                self.send_json({"error": "Invalid configuration", "details": errs}, 400)
                return
            self.controller.update_config(new_cfg)
            self.send_json({"success": True})

        elif path == "/api/admin/actions/test-shutdown":
            res = self.controller.test_shutdown()
            self.send_json({"success": True, "results": res})

        elif path == "/api/admin/actions/test-wol":
            res = self.controller.test_wol()
            self.send_json({"success": True, "results": res})

        elif path == "/api/admin/users/create":
            username = body.get("username", "").strip()
            password = body.get("password", "").strip()
            if not username or not password:
                self.send_json({"error": "Username and password required"}, 400)
                return
            if self.db.create_user(username, password):
                self.send_json({"success": True})
            else:
                self.send_json({"error": "User creation failed (username may exist)"}, 400)

        elif path == "/api/admin/users/delete":
            user_id = body.get("user_id")
            if user_id == session["user_id"]:
                self.send_json({"error": "Cannot delete your own active account"}, 400)
                return
            if self.db.delete_user(user_id):
                self.send_json({"success": True})
            else:
                self.send_json({"error": "Failed to delete user"}, 400)

        else:
            self.send_json({"error": "Not Found"}, 404)

    def handle_public_stats(self):
        ups_raw = self.controller.get_ups_status()
        safe_nodes = [{"name": n.name, "host": n.host, "mac": n.mac} for n in self.controller.nodes]

        status_code = ups_raw.get("ups.status", "UNKNOWN")
        charge = ups_raw.get("battery.charge", "N/A")
        runtime = ups_raw.get("battery.runtime", "N/A")
        load = ups_raw.get("ups.load", "N/A")
        in_v = ups_raw.get("input.voltage", "N/A")
        out_v = ups_raw.get("output.voltage", "N/A")

        res = {
            "state": self.controller.state.name,
            "ups": {
                "name": self.controller.cfg["ups"]["name"],
                "status": status_code,
                "charge_percent": charge,
                "runtime_seconds": runtime,
                "load_percent": load,
                "input_voltage": in_v,
                "output_voltage": out_v,
                "battery_threshold": self.controller.cfg["ups"]["battery_threshold"]
            },
            "nut_all": ups_raw,
            "nodes_summary": safe_nodes,
            "startup_delay": self.controller.cfg["startup"]["delay"],
            "server_time": time.time()
        }
        self.send_json(res)

    def handle_public_nut_all(self):
        ups_raw = self.controller.get_ups_status()
        self.send_json({"nut_variables": ups_raw})

    def handle_public_history(self):
        stats = self.db.get_latest_stats(60)
        self.send_json({"history": stats})

    def handle_public_events(self):
        events = self.db.get_recent_events(30)
        self.send_json({"events": events})


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UPS Monitor & Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background-color: #0b1329; color: #f8fafc; font-family: system-ui, -apple-system, sans-serif; font-size: 0.95rem; line-height: 1.5; }
        .card { background-color: #1e293b; border: 1px solid #475569; color: #f8fafc; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3); }
        .card-header { border-bottom: 1px solid #475569; font-weight: 600; font-size: 1.05rem; background-color: rgba(15, 23, 42, 0.4); }
        .text-muted { color: #cbd5e1 !important; }
        .text-subtle { color: #94a3b8 !important; }
        .badge-online { background-color: #059669; color: #ffffff; font-weight: 600; font-size: 0.9rem; padding: 0.45em 0.8em; border-radius: 6px; }
        .badge-battery { background-color: #d97706; color: #ffffff; font-weight: 600; font-size: 0.9rem; padding: 0.45em 0.8em; border-radius: 6px; }
        .badge-waiting { background-color: #2563eb; color: #ffffff; font-weight: 600; font-size: 0.9rem; padding: 0.45em 0.8em; border-radius: 6px; }
        .stat-value { font-size: 2.3rem; font-weight: 700; color: #38bdf8; letter-spacing: -0.5px; }
        .nav-tabs { border-bottom: 2px solid #334155; }
        .nav-tabs .nav-link { color: #cbd5e1; border: none; font-weight: 600; font-size: 0.95rem; padding: 0.65rem 1.1rem; }
        .nav-tabs .nav-link.active { color: #38bdf8; background-color: transparent; border-bottom: 3px solid #38bdf8; }
        .nav-tabs .nav-link:hover:not(.active) { color: #f8fafc; }
        .form-control, .form-select { background-color: #0f172a; border: 1px solid #475569; color: #f8fafc; font-size: 0.95rem; }
        .form-control:focus, .form-select:focus { background-color: #0f172a; color: #f8fafc; border-color: #38bdf8; box-shadow: 0 0 0 0.25rem rgba(56, 189, 248, 0.25); }
        .form-label { font-weight: 600; color: #e2e8f0; margin-bottom: 0.35rem; }
        .table { color: #f8fafc; font-size: 0.95rem; }
        .table-dark { --bs-table-bg: #1e293b; --bs-table-border-color: #334155; }
        .table-dark th { color: #38bdf8; font-weight: 600; background-color: #0f172a; border-bottom: 2px solid #475569; }
        .chart-legend-badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 20px; font-size: 0.82rem; font-weight: 600; }
        .signal-indicator-shutdown { background-color: #ef4444; color: #ffffff; }
        .signal-indicator-wol { background-color: #10b981; color: #ffffff; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark border-bottom border-secondary mb-4 px-4">
        <div class="container-fluid">
            <a class="navbar-brand d-flex align-items-center gap-2" href="#">
                <i class="bi bi-lightning-charge-fill text-warning fs-4"></i>
                <span class="fw-bold fs-4">UPS Controller</span>
            </a>
            <div class="d-flex align-items-center gap-3">
                <div class="dropdown">
                    <button class="btn btn-dark btn-sm dropdown-toggle border-secondary d-flex align-items-center gap-2" type="button" id="langDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                        <img id="current-lang-flag" src="img/netherlands.png" alt="Flag" style="width: 20px; height: 14px; object-fit: cover; border-radius: 2px;">
                        <span id="current-lang-text">Nederlands</span>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-dark dropdown-menu-end shadow" aria-labelledby="langDropdown">
                        <li>
                            <a class="dropdown-item d-flex align-items-center gap-2" href="#" onclick="setLanguage('nl'); return false;">
                                <img src="img/netherlands.png" alt="NL" style="width: 20px; height: 14px; object-fit: cover; border-radius: 2px;"> Nederlands
                            </a>
                        </li>
                        <li>
                            <a class="dropdown-item d-flex align-items-center gap-2" href="#" onclick="setLanguage('en'); return false;">
                                <img src="img/uk.png" alt="EN" style="width: 20px; height: 14px; object-fit: cover; border-radius: 2px;"> English
                            </a>
                        </li>
                    </ul>
                </div>
                <span id="user-status-text" class="text-muted small">Public View</span>
                <button id="btn-login-modal" class="btn btn-outline-info btn-sm" onclick="openLoginModal()">
                    <i class="bi bi-box-arrow-in-right"></i> <span data-i18n="login">Admin Login</span>
                </button>
                <button id="btn-logout" class="btn btn-outline-danger btn-sm d-none" onclick="logout()">
                    <i class="bi bi-box-arrow-right"></i> <span data-i18n="logout">Logout</span>
                </button>
            </div>
        </div>
    </nav>

    <div class="container-fluid px-4">
        <!-- Tab Navigation -->
        <ul class="nav nav-tabs mb-4" id="mainTabs" role="tablist">
            <li class="nav-item">
                <button class="nav-link active" id="tab-overview-btn" data-bs-toggle="tab" data-bs-target="#tab-overview">
                    <i class="bi bi-speedometer2"></i> <span data-i18n="tab_overview">Dashboard Overview</span>
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" id="tab-history-btn" data-bs-toggle="tab" data-bs-target="#tab-history">
                    <i class="bi bi-graph-up"></i> <span data-i18n="tab_history">History & Logs</span>
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" id="tab-nut-btn" data-bs-toggle="tab" data-bs-target="#tab-nut">
                    <i class="bi bi-cpu"></i> <span data-i18n="tab_nut">NUT Variables</span>
                </button>
            </li>
            <li class="nav-item admin-only d-none">
                <button class="nav-link" id="tab-settings-btn" data-bs-toggle="tab" data-bs-target="#tab-settings">
                    <i class="bi bi-gear-fill"></i> <span data-i18n="tab_settings">Settings & Control</span>
                </button>
            </li>
            <li class="nav-item admin-only d-none">
                <button class="nav-link" id="tab-users-btn" data-bs-toggle="tab" data-bs-target="#tab-users">
                    <i class="bi bi-people-fill"></i> <span data-i18n="tab_users">User Accounts</span>
                </button>
            </li>
        </ul>

        <div class="tab-content" id="mainTabsContent">
            <!-- OVERVIEW TAB -->
            <div class="tab-pane fade show active" id="tab-overview">
                <div class="row g-4 mb-4">
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-muted small fw-semibold" data-i18n="stat_sys_status">SYSTEM STATUS</div>
                            <div class="d-flex align-items-center justify-content-between mt-2">
                                <span id="stat-state" class="badge badge-online">ONLINE</span>
                                <i id="state-icon" class="bi bi-shield-check fs-2 text-success"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-muted small fw-semibold" data-i18n="stat_battery_charge">BATTERY CHARGE</div>
                            <div class="stat-value mt-1" id="stat-charge">-- %</div>
                            <div class="progress mt-2" style="height: 6px;">
                                <div id="progress-charge" class="progress-bar bg-info" style="width: 0%"></div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-muted small fw-semibold" data-i18n="stat_est_runtime">ESTIMATED RUNTIME</div>
                            <div class="stat-value mt-1" id="stat-runtime">-- min</div>
                            <div class="text-muted small mt-1"><span data-i18n="threshold">Threshold</span>: <span id="stat-threshold">--</span>%</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-muted small fw-semibold" data-i18n="stat_load_voltage">UPS LOAD & VOLTAGE</div>
                            <div class="stat-value mt-1" id="stat-load">-- %</div>
                            <div class="text-muted small mt-1"><span data-i18n="input_v">Input</span>: <span id="stat-in-v">--</span>V</div>
                        </div>
                    </div>
                </div>

                <div class="row g-4">
                    <div class="col-lg-8">
                        <div class="card p-3">
                            <div class="card-header bg-transparent px-0 pt-0 text-info d-flex justify-content-between align-items-center">
                                <span><i class="bi bi-activity"></i> <span data-i18n="chart_title">Live Battery & Load Chart</span></span>
                                <div class="d-flex gap-2">
                                    <span class="chart-legend-badge signal-indicator-shutdown"><i class="bi bi-triangle-fill fs-6"></i> <span data-i18n="signal_shutdown_legend">Shutdown Packets</span></span>
                                    <span class="chart-legend-badge signal-indicator-wol"><i class="bi bi-square-fill fs-6"></i> <span data-i18n="signal_wol_legend">WoL Packets</span></span>
                                </div>
                            </div>
                            <div style="height: 280px;">
                                <canvas id="liveChart"></canvas>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="card p-3 h-100">
                            <div class="card-header bg-transparent px-0 pt-0 text-info">
                                <i class="bi bi-hdd-network"></i> <span data-i18n="monitored_nodes">Monitored Proxmox Nodes</span>
                            </div>
                            <div id="nodes-list" class="mt-3">
                                <div class="text-muted">Loading nodes...</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- HISTORY & LOGS TAB -->
            <div class="tab-pane fade" id="tab-history">
                <div class="card p-3">
                    <div class="card-header bg-transparent px-0 pt-0 text-info">
                        <i class="bi bi-journal-text"></i> <span data-i18n="event_logs_title">System Event Logs</span>
                    </div>
                    <div class="table-responsive mt-3">
                        <table class="table table-dark table-hover align-middle">
                            <thead>
                                <tr>
                                    <th data-i18n="col_timestamp">Timestamp</th>
                                    <th data-i18n="col_level">Level</th>
                                    <th data-i18n="col_message">Message</th>
                                </tr>
                            </thead>
                            <tbody id="events-table-body">
                                <tr><td colspan="3" class="text-muted text-center">Loading events...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- NUT VARIABLES TAB -->
            <div class="tab-pane fade" id="tab-nut">
                <div class="card p-4">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h5 class="text-info mb-0"><i class="bi bi-cpu"></i> <span data-i18n="nut_variables_title">ALL NUT UPS Variables</span></h5>
                        <input type="text" id="nut-search-input" class="form-control" style="max-width: 300px;" placeholder="Search NUT variables..." oninput="filterNutVariables()">
                    </div>
                    <div class="table-responsive">
                        <table class="table table-dark table-striped align-middle">
                            <thead>
                                <tr>
                                    <th style="width: 45%;" data-i18n="col_nut_variable">Variable Name</th>
                                    <th style="width: 55%;" data-i18n="col_nut_value">Value</th>
                                </tr>
                            </thead>
                            <tbody id="nut-table-body">
                                <tr><td colspan="2" class="text-muted text-center">Loading NUT variables...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- SETTINGS & CONTROL TAB (ADMIN ONLY) -->
            <div class="tab-pane fade" id="tab-settings">
                <div class="row g-4">
                    <div class="col-lg-8">
                        <div class="card p-4">
                            <h5 class="text-info mb-3"><i class="bi bi-sliders"></i> <span data-i18n="settings_title">System Configuration</span></h5>
                            <form id="settings-form" onsubmit="saveSettings(event)">

                                <!-- Web Server Settings -->
                                <h6 class="text-warning mt-2 mb-3"><i class="bi bi-globe"></i> <span data-i18n="sec_web_settings">Web Server Settings</span></h6>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_web_host">Server Host / Bind IP</label>
                                        <input type="text" id="cfg-web-host" class="form-control" required>
                                        <div class="form-text text-muted small" data-i18n="help_web_host">IP address the web server listens on. '0.0.0.0' allows access from any network interface.</div>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_web_port">Web Port</label>
                                        <input type="number" id="cfg-web-port" class="form-control" min="1" max="65535" required>
                                        <div class="form-text text-muted small" data-i18n="help_web_port">Network port used by the web dashboard (default: 8080).</div>
                                    </div>
                                </div>

                                <!-- UPS Settings -->
                                <h6 class="text-warning mt-4 mb-3"><i class="bi bi-battery-charging"></i> <span data-i18n="sec_ups_settings">UPS Settings (NUT)</span></h6>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_ups_name">NUT UPS Name</label>
                                        <input type="text" id="cfg-ups-name" class="form-control" required>
                                        <div class="form-text text-muted small" data-i18n="help_ups_name">UPS identifier configured in Network UPS Tools (NUT), e.g. gembird@localhost.</div>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_ups_threshold">Battery Threshold (%)</label>
                                        <input type="number" id="cfg-ups-threshold" class="form-control" min="1" max="99" required>
                                        <div class="form-text text-muted small" data-i18n="help_ups_threshold">When battery charge drops below this percentage during an outage, Proxmox servers will shut down automatically.</div>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_ups_poll">Poll Interval (seconds)</label>
                                        <input type="number" id="cfg-ups-poll" class="form-control" min="2" required>
                                        <div class="form-text text-muted small" data-i18n="help_ups_poll">Number of seconds between each UPS status check.</div>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_ups_grace">On-Battery Grace Period (seconds)</label>
                                        <input type="number" id="cfg-ups-grace" class="form-control" min="0" required>
                                        <div class="form-text text-muted small" data-i18n="help_ups_grace">Delay in seconds after power loss before checking shutdown conditions (prevents triggers on brief dips).</div>
                                    </div>
                                </div>

                                <!-- Startup & Conditions Settings -->
                                <h6 class="text-warning mt-4 mb-3"><i class="bi bi-hourglass-split"></i> <span data-i18n="sec_startup_settings">Startup & Conditions</span></h6>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_startup_delay">Startup Stability Delay (seconds)</label>
                                        <input type="number" id="cfg-startup-delay" class="form-control" min="0" required>
                                        <div class="form-text text-muted small" data-i18n="help_startup_delay">Wait time in seconds after mains power returns and all conditions are met, before sending Wake-on-LAN packets.</div>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_battery_above">Required Battery Above (%)</label>
                                        <input type="number" id="cfg-battery-above" class="form-control" min="0" max="100">
                                        <div class="form-text text-muted small" data-i18n="help_battery_above">Minimum battery percentage required before powering Proxmox servers back on.</div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="form-check mt-2">
                                            <input class="form-check-input" type="checkbox" id="cfg-inet-enabled">
                                            <label class="form-check-label fw-bold" data-i18n="cfg_inet_enable">Enable Internet Ping Check</label>
                                        </div>
                                        <input type="text" id="cfg-inet-host" class="form-control mt-2" placeholder="e.g. 1.1.1.1">
                                        <div class="form-text text-muted small" data-i18n="help_inet">Verifies an external IP (e.g. 1.1.1.1) is reachable. Ensures servers only wake when network/internet connection is up.</div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="form-check mt-2">
                                            <input class="form-check-input" type="checkbox" id="cfg-dns-enabled">
                                            <label class="form-check-label fw-bold" data-i18n="cfg_dns_enable">Enable DNS Ping Check</label>
                                        </div>
                                        <input type="text" id="cfg-dns-host" class="form-control mt-2" placeholder="e.g. google.com">
                                        <div class="form-text text-muted small" data-i18n="help_dns">Verifies domain name resolution and connectivity (e.g. google.com) to confirm working DNS.</div>
                                    </div>
                                </div>

                                <!-- Proxmox & Dynamic Nodes Settings -->
                                <h6 class="text-warning mt-4 mb-3"><i class="bi bi-hdd-stack"></i> <span data-i18n="sec_proxmox_settings">Proxmox Cluster & Nodes</span></h6>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-12">
                                        <label class="form-label" data-i18n="cfg_proxmox_token">Proxmox API Token</label>
                                        <input type="text" id="cfg-proxmox-token" class="form-control" required>
                                        <div class="form-text text-muted small" data-i18n="help_proxmox_token">Proxmox VE API Token identifier and secret (format: USER@REALM!TOKENID=UUID_SECRET).</div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="form-check mt-2">
                                            <input class="form-check-input" type="checkbox" id="cfg-proxmox-ssl">
                                            <label class="form-check-label fw-bold" data-i18n="cfg_proxmox_ssl">Verify SSL Certificate</label>
                                        </div>
                                        <div class="form-text text-muted small" data-i18n="help_proxmox_ssl">Enable to validate HTTPS certificates of Proxmox VE nodes (disable if using self-signed certificates).</div>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_proxmox_timeout">API Timeout (seconds)</label>
                                        <input type="number" id="cfg-proxmox-timeout" class="form-control" min="1" required>
                                        <div class="form-text text-muted small" data-i18n="help_proxmox_timeout">Maximum timeout in seconds for Proxmox API requests.</div>
                                    </div>
                                </div>

                                <div class="mb-3">
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <label class="form-label mb-0" data-i18n="cfg_proxmox_nodes_list">Proxmox Monitored Nodes</label>
                                        <button type="button" class="btn btn-outline-success btn-sm" onclick="addNodeRow()">
                                            <i class="bi bi-plus-circle"></i> <span data-i18n="btn_add_node">Add Node</span>
                                        </button>
                                    </div>
                                    <div class="form-text text-muted small mb-2" data-i18n="help_proxmox_nodes">List of Proxmox servers to shut down on low battery and boot via Wake-on-LAN.</div>
                                    <div id="nodes-editor-container">
                                        <!-- Node rows populated via JS -->
                                    </div>
                                </div>

                                <!-- WoL Settings -->
                                <h6 class="text-warning mt-4 mb-3"><i class="bi bi-broadcast"></i> <span data-i18n="sec_wol_settings">Wake-on-LAN Settings</span></h6>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_wol_broadcast">WoL Broadcast IP</label>
                                        <input type="text" id="cfg-wol-broadcast" class="form-control" required>
                                        <div class="form-text text-muted small" data-i18n="help_wol_broadcast">Subnet broadcast IP address where Wake-on-LAN magic packets are sent (e.g. 192.168.1.255).</div>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_wol_port">WoL Port</label>
                                        <input type="number" id="cfg-wol-port" class="form-control" min="1" max="65535" required>
                                        <div class="form-text text-muted small" data-i18n="help_wol_port">UDP port used for Wake-on-LAN magic packets (default: port 9).</div>
                                    </div>
                                </div>

                                <!-- Discord Settings -->
                                <h6 class="text-warning mt-4 mb-3"><i class="bi bi-discord"></i> <span data-i18n="sec_discord_settings">Discord Notifications</span></h6>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-4">
                                        <div class="form-check mt-2">
                                            <input class="form-check-input" type="checkbox" id="cfg-discord-enabled">
                                            <label class="form-check-label fw-bold" data-i18n="cfg_discord_enable">Enable Discord Alerts</label>
                                        </div>
                                        <div class="form-text text-muted small" data-i18n="help_discord">Send automated alerts to a Discord channel on power loss, server shutdown, or Wake-on-LAN startup.</div>
                                    </div>
                                    <div class="col-md-8">
                                        <label class="form-label" data-i18n="cfg_discord_url">Webhook URL</label>
                                        <input type="text" id="cfg-discord-url" class="form-control">
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_discord_user">Bot Username</label>
                                        <input type="text" id="cfg-discord-username" class="form-control">
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_discord_mention">Mention String</label>
                                        <input type="text" id="cfg-discord-mention" class="form-control" placeholder="e.g. @everyone">
                                    </div>
                                </div>

                                <!-- Database Settings -->
                                <h6 class="text-warning mt-4 mb-3"><i class="bi bi-database"></i> <span data-i18n="sec_database_settings">Database & Storage Settings</span></h6>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_db_retention">Database Retention Policy (days)</label>
                                        <input type="number" id="cfg-db-retention" class="form-control" min="0" required>
                                        <div class="form-text text-muted small" data-i18n="help_db_retention">Number of days historical stats and event logs are kept in the SQLite database. Set to 0 for unlimited retention.</div>
                                    </div>
                                </div>

                                <!-- Logging Settings -->
                                <h6 class="text-warning mt-4 mb-3"><i class="bi bi-file-earmark-text"></i> <span data-i18n="sec_logging_settings">Logging Settings</span></h6>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_log_level">Log Level</label>
                                        <select id="cfg-log-level" class="form-select">
                                            <option value="DEBUG">DEBUG</option>
                                            <option value="INFO">INFO</option>
                                            <option value="WARNING">WARNING</option>
                                            <option value="ERROR">ERROR</option>
                                        </select>
                                        <div class="form-text text-muted small" data-i18n="help_logging">Configuration for storing system event logs in a local log file.</div>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_log_file">Log File Path</label>
                                        <input type="text" id="cfg-log-file" class="form-control">
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_log_bytes">Max File Bytes</label>
                                        <input type="number" id="cfg-log-bytes" class="form-control" min="1000">
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label" data-i18n="cfg_log_backup">Backup Count</label>
                                        <input type="number" id="cfg-log-backup" class="form-control" min="0">
                                    </div>
                                </div>

                                <div class="d-flex justify-content-end mt-4">
                                    <button type="submit" class="btn btn-info px-4 py-2 fw-bold">
                                        <i class="bi bi-save"></i> <span data-i18n="btn_save_config">Save Configuration</span>
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>

                    <div class="col-lg-4">
                        <div class="card p-4">
                            <h5 class="text-warning mb-3"><i class="bi bi-tools"></i> <span data-i18n="admin_actions_title">Admin Manual Actions</span></h5>
                            <p class="text-muted small" data-i18n="admin_actions_desc">Execute test triggers on configured Proxmox nodes.</p>
                            <div class="d-grid gap-3 mt-3">
                                <button class="btn btn-outline-warning text-start" onclick="triggerTestAction('test-wol')">
                                    <i class="bi bi-broadcast me-2"></i> <span data-i18n="btn_test_wol">Send Test Wake-on-LAN</span>
                                </button>
                                <button class="btn btn-outline-danger text-start" onclick="triggerTestAction('test-shutdown')">
                                    <i class="bi bi-power me-2"></i> <span data-i18n="btn_test_shutdown">Send Test Shutdown API</span>
                                </button>
                            </div>
                            <div id="action-results" class="mt-3 small"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- USER MANAGEMENT TAB (ADMIN ONLY) -->
            <div class="tab-pane fade" id="tab-users">
                <div class="row g-4">
                    <div class="col-md-7">
                        <div class="card p-4">
                            <h5 class="text-info mb-3"><i class="bi bi-shield-lock"></i> <span data-i18n="users_title">Admin Accounts</span></h5>
                            <div class="table-responsive">
                                <table class="table table-dark align-middle">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th data-i18n="col_username">Username</th>
                                            <th data-i18n="col_created">Created</th>
                                            <th data-i18n="col_action">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody id="users-table-body">
                                        <tr><td colspan="4" class="text-muted">Loading users...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-5">
                        <div class="card p-4">
                            <h5 class="text-info mb-3"><i class="bi bi-person-plus"></i> <span data-i18n="create_user_title">Create Admin User</span></h5>
                            <form onsubmit="createAdminUser(event)">
                                <div class="mb-3">
                                    <label class="form-label" data-i18n="label_username">Username</label>
                                    <input type="text" id="new-username" class="form-control" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label" data-i18n="label_password">Password</label>
                                    <input type="password" id="new-password" class="form-control" required>
                                </div>
                                <button type="submit" class="btn btn-success w-100 fw-bold">
                                    <i class="bi bi-check-circle"></i> <span data-i18n="btn_create_account">Create Account</span>
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- LOGIN MODAL -->
    <div class="modal fade" id="loginModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content card p-3">
                <div class="modal-header border-0">
                    <h5 class="modal-title text-info"><i class="bi bi-shield-lock-fill"></i> <span data-i18n="login_modal_title">Admin Login</span></h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="login-error" class="alert alert-danger d-none"></div>
                    <form onsubmit="handleLogin(event)">
                        <div class="mb-3">
                            <label class="form-label" data-i18n="label_username">Username</label>
                            <input type="text" id="login-username" class="form-control" required autocomplete="username">
                        </div>
                        <div class="mb-3">
                            <label class="form-label" data-i18n="label_password">Password</label>
                            <input type="password" id="login-password" class="form-control" required autocomplete="current-password">
                        </div>
                        <button type="submit" class="btn btn-info w-100 mt-2 fw-bold" data-i18n="btn_login_submit">Login</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let csrfToken = "";
        let authUser = null;
        let chart = null;
        let fullConfig = null;
        let rawNutData = {};
        let currentLang = localStorage.getItem('ups_lang') || 'nl';

        const i18n = {
            nl: {
                login: "Admin Inloggen",
                logout: "Uitloggen",
                public_view: "Publieke Weergave",
                logged_in_as: "Ingelogd als: ",
                tab_overview: "Dashboard Overzicht",
                tab_history: "Historie & Logboek",
                tab_nut: "NUT Variabelen",
                tab_settings: "Instellingen & Beheer",
                tab_users: "Gebruikersaccounts",
                stat_sys_status: "SYSTEEMSTATUS",
                stat_battery_charge: "ACCULADING",
                stat_est_runtime: "GESCHATTE RUNTIME",
                stat_load_voltage: "UPS BELASTING & SPANNING",
                threshold: "Drempelwaarde",
                input_v: "Ingang",
                chart_title: "Live Accu & Belasting Grafiek",
                signal_shutdown_legend: "Shutdown Signaal",
                signal_wol_legend: "WoL Signaal",
                monitored_nodes: "Gemonitorde Proxmox Nodes",
                registered: "Geregistreerd",
                event_logs_title: "Systeem Logboek",
                col_timestamp: "Tijdstip",
                col_level: "Niveau",
                col_message: "Bericht",
                nut_variables_title: "Alle NUT UPS Variabelen",
                col_nut_variable: "Variabele Naam",
                col_nut_value: "Waarde",
                search_nut_placeholder: "Zoek NUT variabelen...",
                settings_title: "Systeem Configuratie",
                sec_web_settings: "Web Server Instellingen",
                cfg_web_host: "Server Host / Bind IP",
                cfg_web_port: "Web Poort",
                sec_ups_settings: "UPS Instellingen (NUT)",
                cfg_ups_name: "NUT UPS Naam",
                cfg_ups_threshold: "Accu Drempelwaarde (%)",
                cfg_ups_poll: "Poll Interval (seconden)",
                cfg_ups_grace: "Accu Genadewacht (seconden)",
                sec_startup_settings: "Opstart & Voorwaarden",
                cfg_startup_delay: "Opstart Vertraging (seconden)",
                cfg_battery_above: "Vereiste Acculading Boven (%)",
                cfg_inet_enable: "Internet Ping Controle Inschakelen",
                cfg_dns_enable: "DNS Ping Controle Inschakelen",
                sec_proxmox_settings: "Proxmox Cluster & Nodes",
                cfg_proxmox_token: "Proxmox API Token",
                cfg_proxmox_ssl: "Verifieer SSL Certificaat",
                cfg_proxmox_timeout: "API Timeout (seconden)",
                cfg_proxmox_nodes_list: "Proxmox Gemonitorde Nodes",
                btn_add_node: "Node Toevoegen",
                sec_wol_settings: "Wake-on-LAN Instellingen",
                cfg_wol_broadcast: "WoL Broadcast IP",
                cfg_wol_port: "WoL Poort",
                sec_discord_settings: "Discord Notificaties",
                cfg_discord_enable: "Discord Meldingen Inschakelen",
                cfg_discord_url: "Webhook URL",
                cfg_discord_user: "Bot Gebruikersnaam",
                cfg_discord_mention: "Mention Rol/Gebruiker",
                sec_database_settings: "Database & Opslag Instellingen",
                cfg_db_retention: "Database Retentie Beleid (dagen)",
                help_db_retention: "Aantal dagen dat historische statistieken en logboekevents in de SQLite database bewaard blijven. Vul 0 in voor onbeperkte bewaartermijn.",
                sec_logging_settings: "Logboek Instellingen",
                cfg_log_level: "Log Niveau",
                cfg_log_file: "Log Bestands pad",
                cfg_log_bytes: "Max Bestandsgrootte (Bytes)",
                cfg_log_backup: "Aantal Backups",
                btn_save_config: "Configuratie Opslaan",
                admin_actions_title: "Handmatige Beheerdersacties",
                admin_actions_desc: "Voer test-triggers uit op geconfigureerde Proxmox nodes.",
                btn_test_wol: "Test Wake-on-LAN Versturen",
                btn_test_shutdown: "Test Shutdown API Versturen",
                users_title: "Beheerdersaccounts",
                col_username: "Gebruikersnaam",
                col_created: "Aangemaakt op",
                col_action: "Actie",
                create_user_title: "Beheerder Account Aanmaken",
                label_username: "Gebruikersnaam",
                label_password: "Wachtwoord",
                btn_create_account: "Account Aanmaken",
                login_modal_title: "Admin Inloggen",
                btn_login_submit: "Inloggen",
                btn_delete: "Verwijderen",
                node_name: "Node Naam",
                node_host: "Host/IP",
                node_mac: "MAC Adres",
                help_web_host: "IP-adres waarop de webserver luistert. '0.0.0.0' staat toegang vanaf elke netwerkinterface toe.",
                help_web_port: "Netwerkpoort voor het web-dashboard (standaard: 8080).",
                help_ups_name: "Naam van de UPS in Network UPS Tools (NUT), bijv. gembird@localhost.",
                help_ups_threshold: "Wanneer de accu bij stroomuitval onder dit percentage zakt, worden Proxmox-servers automatisch uitgeschakeld.",
                help_ups_poll: "Aantal seconden tussen elke statuscontrole van de UPS.",
                help_ups_grace: "Wachttijd in seconden na stroomuitval voordat shutdowns worden overwogen (voorkomt actie bij korte dippen).",
                help_startup_delay: "Wachttijd in seconden nadat netspanning is teruggekeerd en alle voorwaarden voldaan zijn, voordat Wake-on-LAN wordt gestuurd.",
                help_battery_above: "Minimaal vereist accupercentage voordat Proxmox-servers weer mogen inschakelen.",
                help_inet: "Controleert of een extern IP (bijv. 1.1.1.1) bereikbaar is. Zorgt dat servers pas opstarten als het netwerk/internet online is.",
                help_dns: "Controleert domeinnaamresolutie en verbinding (bijv. google.com) om te verifiëren dat DNS werkt.",
                help_proxmox_token: "Proxmox VE API Token identificatie en geheim (formaat: GEBRUIKER@REALM!TOKENID=UUID_SECRET).",
                help_proxmox_ssl: "Schakel in om HTTPS-certificaten van Proxmox VE nodes te valideren (uitschakelen bij zelfondertekende certificaten).",
                help_proxmox_timeout: "Maximale wachttijd in seconden voor Proxmox API-aanvragen.",
                help_proxmox_nodes: "Lijst met Proxmox-servers die bij lage accu worden uitgeschakeld en via Wake-on-LAN weer worden ingeschakeld.",
                help_wol_broadcast: "Subnet broadcast IP-adres waarnaar Wake-on-LAN magic packets worden verzonden (bijv. 192.168.1.255).",
                help_wol_port: "UDP-poort voor Wake-on-LAN magic packets (standaard: poort 9).",
                help_discord: "Stuur automatische meldingen naar een Discord-kanaal bij stroomuitval, server-shutdown of Wake-on-LAN opstart.",
                help_logging: "Instellingen voor het opslaan van logboeken in een lokaal logbestand."
            },
            en: {
                login: "Admin Login",
                logout: "Logout",
                public_view: "Public View",
                logged_in_as: "Logged in as: ",
                tab_overview: "Dashboard Overview",
                tab_history: "History & Logs",
                tab_nut: "NUT Variables",
                tab_settings: "Settings & Control",
                tab_users: "User Accounts",
                stat_sys_status: "SYSTEM STATUS",
                stat_battery_charge: "BATTERY CHARGE",
                stat_est_runtime: "ESTIMATED RUNTIME",
                stat_load_voltage: "UPS LOAD & VOLTAGE",
                threshold: "Threshold",
                input_v: "Input",
                chart_title: "Live Battery & Load Chart",
                signal_shutdown_legend: "Shutdown Signal",
                signal_wol_legend: "WoL Signal",
                monitored_nodes: "Monitored Proxmox Nodes",
                registered: "Registered",
                event_logs_title: "System Event Logs",
                col_timestamp: "Timestamp",
                col_level: "Level",
                col_message: "Message",
                nut_variables_title: "ALL NUT UPS Variables",
                col_nut_variable: "Variable Name",
                col_nut_value: "Value",
                search_nut_placeholder: "Search NUT variables...",
                settings_title: "System Configuration",
                sec_web_settings: "Web Server Settings",
                cfg_web_host: "Server Host / Bind IP",
                cfg_web_port: "Web Port",
                sec_ups_settings: "UPS Settings (NUT)",
                cfg_ups_name: "NUT UPS Name",
                cfg_ups_threshold: "Battery Threshold (%)",
                cfg_ups_poll: "Poll Interval (seconds)",
                cfg_ups_grace: "On-Battery Grace Period (seconds)",
                sec_startup_settings: "Startup & Conditions",
                cfg_startup_delay: "Startup Stability Delay (seconds)",
                cfg_battery_above: "Required Battery Above (%)",
                cfg_inet_enable: "Enable Internet Ping Check",
                cfg_dns_enable: "Enable DNS Ping Check",
                sec_proxmox_settings: "Proxmox Cluster & Nodes",
                cfg_proxmox_token: "Proxmox API Token",
                cfg_proxmox_ssl: "Verify SSL Certificate",
                cfg_proxmox_timeout: "API Timeout (seconds)",
                cfg_proxmox_nodes_list: "Proxmox Monitored Nodes",
                btn_add_node: "Add Node",
                sec_wol_settings: "Wake-on-LAN Settings",
                cfg_wol_broadcast: "WoL Broadcast IP",
                cfg_wol_port: "WoL Port",
                sec_discord_settings: "Discord Notifications",
                cfg_discord_enable: "Enable Discord Alerts",
                cfg_discord_url: "Webhook URL",
                cfg_discord_user: "Bot Username",
                cfg_discord_mention: "Mention String",
                sec_database_settings: "Database & Storage Settings",
                cfg_db_retention: "Database Retention Policy (days)",
                help_db_retention: "Number of days historical stats and event logs are kept in the SQLite database. Set to 0 for unlimited retention.",
                sec_logging_settings: "Logging Settings",
                cfg_log_level: "Log Level",
                cfg_log_file: "Log File Path",
                cfg_log_bytes: "Max File Bytes",
                cfg_log_backup: "Backup Count",
                btn_save_config: "Save Configuration",
                admin_actions_title: "Admin Manual Actions",
                admin_actions_desc: "Execute test triggers on configured Proxmox nodes.",
                btn_test_wol: "Send Test Wake-on-LAN",
                btn_test_shutdown: "Send Test Shutdown API",
                users_title: "Admin Accounts",
                col_username: "Username",
                col_created: "Created",
                col_action: "Action",
                create_user_title: "Create Admin User",
                label_username: "Username",
                label_password: "Password",
                btn_create_account: "Create Account",
                login_modal_title: "Admin Login",
                btn_login_submit: "Login",
                btn_delete: "Delete",
                node_name: "Node Name",
                node_host: "Host/IP",
                node_mac: "MAC Address",
                help_web_host: "IP address the web server listens on. '0.0.0.0' allows access from any network interface.",
                help_web_port: "Network port used by the web dashboard (default: 8080).",
                help_ups_name: "UPS identifier configured in Network UPS Tools (NUT), e.g. gembird@localhost.",
                help_ups_threshold: "When battery charge drops below this percentage during an outage, Proxmox servers will shut down automatically.",
                help_ups_poll: "Number of seconds between each UPS status check.",
                help_ups_grace: "Delay in seconds after power loss before checking shutdown conditions (prevents triggers on brief dips).",
                help_startup_delay: "Wait time in seconds after mains power returns and all conditions are met, before sending Wake-on-LAN packets.",
                help_battery_above: "Minimum battery percentage required before powering Proxmox servers back on.",
                help_inet: "Verifies an external IP (e.g. 1.1.1.1) is reachable. Ensures servers only wake when network/internet connection is up.",
                help_dns: "Verifies domain name resolution and connectivity (e.g. google.com) to confirm working DNS.",
                help_proxmox_token: "Proxmox VE API Token identifier and secret (format: USER@REALM!TOKENID=UUID_SECRET).",
                help_proxmox_ssl: "Enable to validate HTTPS certificates of Proxmox VE nodes (disable if using self-signed certificates).",
                help_proxmox_timeout: "Maximum timeout in seconds for Proxmox API requests.",
                help_proxmox_nodes: "List of Proxmox servers to shut down on low battery and boot via Wake-on-LAN.",
                help_wol_broadcast: "Subnet broadcast IP address where Wake-on-LAN magic packets are sent (e.g. 192.168.1.255).",
                help_wol_port: "UDP port used for Wake-on-LAN magic packets (default: port 9).",
                help_discord: "Send automated alerts to a Discord channel on power loss, server shutdown, or Wake-on-LAN startup.",
                help_logging: "Configuration for storing system event logs in a local log file."
            }
        };

        document.addEventListener("DOMContentLoaded", () => {
            setLanguage(currentLang);
            initChart();
            checkAuth();
            fetchPublicStats();
            fetchPublicEvents();
            setInterval(fetchPublicStats, 3000);
            setInterval(fetchPublicEvents, 10000);
        });

        function setLanguage(lang) {
            currentLang = lang;
            localStorage.setItem('ups_lang', lang);
            const flagImg = document.getElementById('current-lang-flag');
            const flagText = document.getElementById('current-lang-text');
            if (flagImg && flagText) {
                if (lang === 'en') {
                    flagImg.src = 'img/uk.png';
                    flagText.innerText = 'English';
                } else {
                    flagImg.src = 'img/netherlands.png';
                    flagText.innerText = 'Nederlands';
                }
            }
            document.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.getAttribute('data-i18n');
                if (i18n[lang] && i18n[lang][key]) {
                    el.innerText = i18n[lang][key];
                }
            });
            const searchInput = document.getElementById('nut-search-input');
            if (searchInput && i18n[lang] && i18n[lang].search_nut_placeholder) {
                searchInput.placeholder = i18n[lang].search_nut_placeholder;
            }
            if (authUser) {
                document.getElementById('user-status-text').innerText = i18n[lang].logged_in_as + authUser;
            } else {
                document.getElementById('user-status-text').innerText = i18n[lang].public_view;
            }
        }

        function initChart() {
            const ctx = document.getElementById('liveChart').getContext('2d');
            chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Charge %',
                            data: [],
                            borderColor: '#38bdf8',
                            backgroundColor: 'rgba(56,189,248,0.12)',
                            fill: true,
                            tension: 0.3,
                            pointBackgroundColor: [],
                            pointStyle: [],
                            pointRadius: [],
                            pointBorderColor: '#ffffff',
                            pointBorderWidth: 2,
                            pointHoverRadius: 10
                        },
                        {
                            label: 'Load %',
                            data: [],
                            borderColor: '#f59e0b',
                            backgroundColor: 'transparent',
                            borderDash: [5,5],
                            tension: 0.3,
                            pointRadius: 0
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { labels: { color: '#cbd5e1', font: { weight: '600' } } },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    let label = context.dataset.label || '';
                                    if (label) label += ': ';
                                    if (context.parsed.y !== null) label += context.parsed.y + '%';
                                    const rawPoint = context.dataset.rawHistory ? context.dataset.rawHistory[context.dataIndex] : null;
                                    if (rawPoint && rawPoint.signal) {
                                        if (rawPoint.signal === 'SHUTDOWN') {
                                            label += ' ⚠️ [SHUTDOWN PACKETS SENT]';
                                        } else if (rawPoint.signal === 'WOL') {
                                            label += ' ⚡ [WAKE-ON-LAN PACKETS SENT]';
                                        } else {
                                            label += ` [${rawPoint.signal} SIGNAL SENT]`;
                                        }
                                    }
                                    return label;
                                }
                            }
                        }
                    },
                    scales: {
                        x: { ticks: { color: '#cbd5e1' }, grid: { color: '#334155' } },
                        y: { min: 0, max: 100, ticks: { color: '#cbd5e1' }, grid: { color: '#334155' } }
                    }
                }
            });
        }

        async function checkAuth() {
            try {
                const res = await fetch('/api/auth/me');
                const data = await res.json();
                if (data.authenticated) {
                    setLoggedIn(data.username, data.csrf_token);
                } else {
                    setLoggedOut();
                }
            } catch(e) { console.error(e); }
        }

        function setLoggedIn(username, csrf) {
            authUser = username;
            csrfToken = csrf;
            const langDict = i18n[currentLang] || i18n.nl;
            document.getElementById('user-status-text').innerText = langDict.logged_in_as + username;
            document.getElementById('btn-login-modal').classList.add('d-none');
            document.getElementById('btn-logout').classList.remove('d-none');
            document.querySelectorAll('.admin-only').forEach(el => el.classList.remove('d-none'));
            loadAdminData();
        }

        function setLoggedOut() {
            authUser = null;
            csrfToken = "";
            const langDict = i18n[currentLang] || i18n.nl;
            document.getElementById('user-status-text').innerText = langDict.public_view;
            document.getElementById('btn-login-modal').classList.remove('d-none');
            document.getElementById('btn-logout').classList.add('d-none');
            document.querySelectorAll('.admin-only').forEach(el => el.classList.add('d-none'));
        }

        function openLoginModal() {
            const modal = new bootstrap.Modal(document.getElementById('loginModal'));
            document.getElementById('login-error').classList.add('d-none');
            modal.show();
        }

        async function handleLogin(e) {
            e.preventDefault();
            const u = document.getElementById('login-username').value;
            const p = document.getElementById('login-password').value;
            const errDiv = document.getElementById('login-error');
            errDiv.classList.add('d-none');

            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: u, password: p })
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('loginModal')).hide();
                    setLoggedIn(data.username, data.csrf_token);
                } else {
                    errDiv.innerText = data.error || 'Login failed';
                    errDiv.classList.remove('d-none');
                }
            } catch(err) {
                errDiv.innerText = 'Network error during login';
                errDiv.classList.remove('d-none');
            }
        }

        async function logout() {
            await fetch('/api/auth/logout', { method: 'POST' });
            setLoggedOut();
            bootstrap.Tab.getInstance(document.getElementById('tab-overview-btn')).show();
        }

        async function fetchPublicStats() {
            try {
                const res = await fetch('/api/public/stats');
                const data = await res.json();

                document.getElementById('stat-charge').innerText = `${data.ups.charge_percent}%`;
                document.getElementById('progress-charge').style.width = `${Math.min(100, Math.max(0, parseFloat(data.ups.charge_percent) || 0))}%`;

                const rtSeconds = parseFloat(data.ups.runtime_seconds) || 0;
                document.getElementById('stat-runtime').innerText = `${Math.round(rtSeconds / 60)} min`;
                document.getElementById('stat-threshold').innerText = data.ups.battery_threshold;
                document.getElementById('stat-load').innerText = `${data.ups.load_percent}%`;
                document.getElementById('stat-in-v').innerText = data.ups.input_voltage;

                const stateEl = document.getElementById('stat-state');
                const stateIcon = document.getElementById('state-icon');
                stateEl.innerText = data.state;
                if (data.state === 'ONLINE') {
                    stateEl.className = 'badge badge-online';
                    if (stateIcon) stateIcon.className = 'bi bi-shield-check fs-2 text-success';
                } else if (data.state === 'ON_BATTERY') {
                    stateEl.className = 'badge badge-battery';
                    if (stateIcon) stateIcon.className = 'bi bi-exclamation-triangle-fill fs-2 text-warning';
                } else {
                    stateEl.className = 'badge badge-waiting';
                    if (stateIcon) stateIcon.className = 'bi bi-hourglass-split fs-2 text-info';
                }

                // Render Nodes Summary
                const langDict = i18n[currentLang] || i18n.nl;
                const nodesContainer = document.getElementById('nodes-list');
                nodesContainer.innerHTML = data.nodes_summary.map(n => `
                    <div class="d-flex align-items-center justify-content-between p-2 mb-2 bg-dark rounded border border-secondary">
                        <div>
                            <span class="fw-bold text-light">${n.name}</span>
                            <div class="text-muted small">${n.host} (${n.mac})</div>
                        </div>
                        <span class="badge bg-success"><i class="bi bi-check-circle"></i> ${langDict.registered}</span>
                    </div>
                `).join('');

                if (data.nut_all) {
                    rawNutData = data.nut_all;
                    renderNutTable(rawNutData);
                }

                fetchChartHistory();
            } catch(e) { console.error(e); }
        }

        function renderNutTable(nutObj) {
            const tbody = document.getElementById('nut-table-body');
            const keys = Object.keys(nutObj).sort();
            if (keys.length === 0) {
                tbody.innerHTML = '<tr><td colspan="2" class="text-muted text-center">No NUT variables found</td></tr>';
                return;
            }
            tbody.innerHTML = keys.map(k => `
                <tr>
                    <td class="fw-bold text-info">${k}</td>
                    <td><code class="text-light fs-6">${nutObj[k]}</code></td>
                </tr>
            `).join('');
        }

        function filterNutVariables() {
            const query = document.getElementById('nut-search-input').value.toLowerCase();
            const filtered = {};
            for (const [k, v] of Object.entries(rawNutData)) {
                if (k.toLowerCase().includes(query) || String(v).toLowerCase().includes(query)) {
                    filtered[k] = v;
                }
            }
            renderNutTable(filtered);
        }

        async function fetchChartHistory() {
            try {
                const res = await fetch('/api/public/history');
                const data = await res.json();
                const labels = data.history.map(item => new Date(item.timestamp * 1000).toLocaleTimeString());
                const charges = data.history.map(item => item.charge);
                const loads = data.history.map(item => item.load);

                const colors = [];
                const styles = [];
                const radii = [];

                data.history.forEach(item => {
                    if (item.signal === 'SHUTDOWN') {
                        colors.push('#ef4444');
                        styles.push('triangle');
                        radii.push(10);
                    } else if (item.signal === 'WOL') {
                        colors.push('#10b981');
                        styles.push('rectRot');
                        radii.push(10);
                    } else {
                        colors.push('#38bdf8');
                        styles.push('circle');
                        radii.push(2);
                    }
                });

                chart.data.labels = labels;
                chart.data.datasets[0].data = charges;
                chart.data.datasets[0].pointBackgroundColor = colors;
                chart.data.datasets[0].pointStyle = styles;
                chart.data.datasets[0].pointRadius = radii;
                chart.data.datasets[0].rawHistory = data.history;
                chart.data.datasets[1].data = loads;
                chart.update('none');
            } catch(e) { console.error(e); }
        }

        async function fetchPublicEvents() {
            try {
                const res = await fetch('/api/public/events');
                const data = await res.json();
                const tbody = document.getElementById('events-table-body');
                tbody.innerHTML = data.events.map(ev => {
                    let lvlBadge = 'bg-secondary';
                    if (ev.level === 'WARNING') lvlBadge = 'bg-warning text-dark';
                    if (ev.level === 'ERROR' || ev.level === 'CRITICAL') lvlBadge = 'bg-danger';
                    if (ev.level === 'INFO') lvlBadge = 'bg-info text-dark';
                    return `
                        <tr>
                            <td class="text-muted small">${new Date(ev.timestamp * 1000).toLocaleString()}</td>
                            <td><span class="badge ${lvlBadge}">${ev.level}</span></td>
                            <td>${ev.message}</td>
                        </tr>
                    `;
                }).join('');
            } catch(e) { console.error(e); }
        }

        async function loadAdminData() {
            if (!authUser) return;
            try {
                const res = await fetch('/api/admin/config');
                const data = await res.json();
                if (data.config) {
                    fullConfig = data.config;

                    document.getElementById('cfg-web-host').value = fullConfig.web ? fullConfig.web.host : '0.0.0.0';
                    document.getElementById('cfg-web-port').value = fullConfig.web ? fullConfig.web.port : 8080;

                    document.getElementById('cfg-ups-name').value = fullConfig.ups.name;
                    document.getElementById('cfg-ups-threshold').value = fullConfig.ups.battery_threshold;
                    document.getElementById('cfg-ups-poll').value = fullConfig.ups.poll_interval;
                    document.getElementById('cfg-ups-grace').value = fullConfig.ups.on_battery_grace;

                    document.getElementById('cfg-startup-delay').value = fullConfig.startup.delay;
                    const cond = fullConfig.startup.conditions || {};
                    document.getElementById('cfg-battery-above').value = cond.battery_above !== null ? cond.battery_above : '';
                    document.getElementById('cfg-inet-enabled').checked = cond.internet ? cond.internet.enabled : false;
                    document.getElementById('cfg-inet-host').value = cond.internet ? (cond.internet.host || '') : '';
                    document.getElementById('cfg-dns-enabled').checked = cond.dns ? cond.dns.enabled : false;
                    document.getElementById('cfg-dns-host').value = cond.dns ? (cond.dns.host || '') : '';

                    document.getElementById('cfg-proxmox-token').value = fullConfig.proxmox.api_token || '';
                    document.getElementById('cfg-proxmox-ssl').checked = fullConfig.proxmox.verify_ssl || false;
                    document.getElementById('cfg-proxmox-timeout').value = fullConfig.proxmox.timeout || 15;

                    renderNodeEditorRows(fullConfig.proxmox.nodes || []);

                    document.getElementById('cfg-wol-broadcast').value = fullConfig.wol ? fullConfig.wol.broadcast : '192.168.1.255';
                    document.getElementById('cfg-wol-port').value = fullConfig.wol ? (fullConfig.wol.port || 9) : 9;

                    document.getElementById('cfg-discord-enabled').checked = fullConfig.discord ? fullConfig.discord.enabled : false;
                    document.getElementById('cfg-discord-url').value = fullConfig.discord ? (fullConfig.discord.webhook_url || '') : '';
                    document.getElementById('cfg-discord-username').value = fullConfig.discord ? (fullConfig.discord.username || '') : '';
                    document.getElementById('cfg-discord-mention').value = fullConfig.discord ? (fullConfig.discord.mention || '') : '';

                    const dbCfg = fullConfig.database || {};
                    document.getElementById('cfg-db-retention').value = dbCfg.retention_days !== undefined ? dbCfg.retention_days : 7;

                    const logCfg = fullConfig.logging || {};
                    document.getElementById('cfg-log-level').value = logCfg.level || 'INFO';
                    document.getElementById('cfg-log-file').value = logCfg.file || '';
                    document.getElementById('cfg-log-bytes').value = logCfg.max_bytes || 5000000;
                    document.getElementById('cfg-log-backup').value = logCfg.backup_count || 5;
                }

                loadUsersList();
            } catch(e) { console.error(e); }
        }

        function renderNodeEditorRows(nodes) {
            const container = document.getElementById('nodes-editor-container');
            const langDict = i18n[currentLang] || i18n.nl;
            container.innerHTML = nodes.map((node, index) => `
                <div class="row g-2 mb-2 align-items-center node-row">
                    <div class="col-md-3">
                        <input type="text" class="form-control node-name" placeholder="${langDict.node_name}" value="${node.name}" required>
                    </div>
                    <div class="col-md-4">
                        <input type="text" class="form-control node-host" placeholder="${langDict.node_host}" value="${node.host}" required>
                    </div>
                    <div class="col-md-4">
                        <input type="text" class="form-control node-mac" placeholder="${langDict.node_mac}" value="${node.mac}" required>
                    </div>
                    <div class="col-md-1">
                        <button type="button" class="btn btn-outline-danger btn-sm w-100" onclick="removeNodeRow(this)">
                            <i class="bi bi-trash"></i>
                        </button>
                    </div>
                </div>
            `).join('');
        }

        function addNodeRow() {
            const container = document.getElementById('nodes-editor-container');
            const langDict = i18n[currentLang] || i18n.nl;
            const div = document.createElement('div');
            div.className = 'row g-2 mb-2 align-items-center node-row';
            div.innerHTML = `
                <div class="col-md-3">
                    <input type="text" class="form-control node-name" placeholder="${langDict.node_name}" value="pve-new" required>
                </div>
                <div class="col-md-4">
                    <input type="text" class="form-control node-host" placeholder="${langDict.node_host}" value="192.168.1.50" required>
                </div>
                <div class="col-md-4">
                    <input type="text" class="form-control node-mac" placeholder="${langDict.node_mac}" value="00:11:22:33:44:55" required>
                </div>
                <div class="col-md-1">
                    <button type="button" class="btn btn-outline-danger btn-sm w-100" onclick="removeNodeRow(this)">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
            `;
            container.appendChild(div);
        }

        function removeNodeRow(btn) {
            const row = btn.closest('.node-row');
            if (row) row.remove();
        }

        function collectNodesFromUI() {
            const rows = document.querySelectorAll('.node-row');
            const nodes = [];
            rows.forEach(r => {
                const name = r.querySelector('.node-name').value.trim();
                const host = r.querySelector('.node-host').value.trim();
                const mac = r.querySelector('.node-mac').value.trim();
                if (name && host && mac) {
                    nodes.push({ name, host, mac });
                }
            });
            return nodes;
        }

        async function saveSettings(e) {
            e.preventDefault();
            if (!fullConfig) fullConfig = {};

            fullConfig.web = {
                enabled: true,
                host: document.getElementById('cfg-web-host').value.trim(),
                port: parseInt(document.getElementById('cfg-web-port').value)
            };

            fullConfig.ups = {
                name: document.getElementById('cfg-ups-name').value.trim(),
                battery_threshold: parseFloat(document.getElementById('cfg-ups-threshold').value),
                poll_interval: parseFloat(document.getElementById('cfg-ups-poll').value),
                on_battery_grace: parseFloat(document.getElementById('cfg-ups-grace').value)
            };

            const batAboveVal = document.getElementById('cfg-battery-above').value;
            fullConfig.startup = {
                delay: parseFloat(document.getElementById('cfg-startup-delay').value),
                conditions: {
                    battery_above: batAboveVal !== '' ? parseFloat(batAboveVal) : null,
                    internet: {
                        enabled: document.getElementById('cfg-inet-enabled').checked,
                        host: document.getElementById('cfg-inet-host').value.trim()
                    },
                    dns: {
                        enabled: document.getElementById('cfg-dns-enabled').checked,
                        host: document.getElementById('cfg-dns-host').value.trim()
                    }
                }
            };

            const nodesList = collectNodesFromUI();
            if (nodesList.length === 0) {
                alert('At least one Proxmox node is required!');
                return;
            }

            fullConfig.proxmox = {
                nodes: nodesList,
                api_token: document.getElementById('cfg-proxmox-token').value.trim(),
                verify_ssl: document.getElementById('cfg-proxmox-ssl').checked,
                timeout: parseInt(document.getElementById('cfg-proxmox-timeout').value)
            };

            fullConfig.wol = {
                broadcast: document.getElementById('cfg-wol-broadcast').value.trim(),
                port: parseInt(document.getElementById('cfg-wol-port').value)
            };

            fullConfig.discord = {
                enabled: document.getElementById('cfg-discord-enabled').checked,
                webhook_url: document.getElementById('cfg-discord-url').value.trim(),
                username: document.getElementById('cfg-discord-username').value.trim(),
                mention: document.getElementById('cfg-discord-mention').value.trim()
            };

            fullConfig.database = {
                retention_days: parseInt(document.getElementById('cfg-db-retention').value) || 0
            };

            fullConfig.logging = {
                level: document.getElementById('cfg-log-level').value,
                file: document.getElementById('cfg-log-file').value.trim(),
                max_bytes: parseInt(document.getElementById('cfg-log-bytes').value),
                backup_count: parseInt(document.getElementById('cfg-log-backup').value)
            };

            try {
                const res = await fetch('/api/admin/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                    body: JSON.stringify({ config: fullConfig, csrf_token: csrfToken })
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    alert(currentLang === 'nl' ? 'Configuratie succesvol opgeslagen!' : 'Configuration saved successfully!');
                    fetchPublicStats();
                } else {
                    alert((currentLang === 'nl' ? 'Fout bij opslaan: ' : 'Error saving config: ') + (data.error || 'Unknown error'));
                }
            } catch(err) { alert('Network error'); }
        }

        async function triggerTestAction(action) {
            const msg = currentLang === 'nl' ? `Weet u zeker dat u ${action} wilt uitvoeren?` : `Are you sure you want to run ${action}?`;
            if (!confirm(msg)) return;
            const resDiv = document.getElementById('action-results');
            resDiv.innerHTML = '<span class="text-warning">Running test action...</span>';
            try {
                const res = await fetch(`/api/admin/actions/${action}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                    body: JSON.stringify({ csrf_token: csrfToken })
                });
                const data = await res.json();
                resDiv.innerHTML = `<pre class="bg-dark text-success p-2 rounded mt-2">${JSON.stringify(data.results, null, 2)}</pre>`;
                fetchChartHistory();
            } catch(e) { resDiv.innerHTML = '<span class="text-danger">Action failed</span>'; }
        }

        async function loadUsersList() {
            try {
                const res = await fetch('/api/admin/users');
                const data = await res.json();
                const tbody = document.getElementById('users-table-body');
                const langDict = i18n[currentLang] || i18n.nl;
                tbody.innerHTML = data.users.map(u => `
                    <tr>
                        <td>${u.id}</td>
                        <td class="fw-bold">${u.username}</td>
                        <td class="text-muted small">${u.created_at}</td>
                        <td>
                            <button class="btn btn-outline-danger btn-sm" onclick="deleteUser(${u.id})">
                                <i class="bi bi-trash"></i> ${langDict.btn_delete}
                            </button>
                        </td>
                    </tr>
                `).join('');
            } catch(e) { console.error(e); }
        }

        async function createAdminUser(e) {
            e.preventDefault();
            const u = document.getElementById('new-username').value;
            const p = document.getElementById('new-password').value;
            try {
                const res = await fetch('/api/admin/users/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                    body: JSON.stringify({ username: u, password: p, csrf_token: csrfToken })
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    alert(currentLang === 'nl' ? 'Gebruiker aangemaakt!' : 'User created successfully');
                    document.getElementById('new-username').value = '';
                    document.getElementById('new-password').value = '';
                    loadUsersList();
                } else {
                    alert('Error: ' + (data.error || 'Failed to create user'));
                }
            } catch(e) { alert('Network error'); }
        }

        async function deleteUser(userId) {
            const msg = currentLang === 'nl' ? 'Weet u zeker dat u deze gebruiker wilt verwijderen?' : 'Are you sure you want to delete this user?';
            if (!confirm(msg)) return;
            try {
                const res = await fetch('/api/admin/users/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                    body: JSON.stringify({ user_id: userId, csrf_token: csrfToken })
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    loadUsersList();
                } else {
                    alert('Error: ' + (data.error || 'Failed to delete user'));
                }
            } catch(e) { alert('Network error'); }
        }
    </script>
</body>
</html>
'''
"""

def main():
    parser = argparse.ArgumentParser(
        description="UPS Controller & Production-Ready Web Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--test-shutdown", action="store_true", help="Send real shutdown commands to all nodes and exit")
    parser.add_argument("--test-wol", action="store_true", help="Send Wake-on-LAN packets to all nodes and exit")
    parser.add_argument("--create-admin", nargs=2, metavar=("USERNAME", "PASSWORD"), help="Create a new admin user account")
    parser.add_argument("--reset-password", nargs=2, metavar=("USERNAME", "PASSWORD"), help="Reset password for an admin user")
    parser.add_argument("--port", type=int, help="Override Web server port")
    parser.add_argument("--host", type=str, help="Override Web server host")
    args = parser.parse_args()

    db = Database(DB_PATH)

    if args.create_admin:
        username, password = args.create_admin
        if db.create_user(username, password):
            print(f"Admin user '{username}' created successfully.")
        else:
            print(f"Error: Could not create user '{username}' (may already exist).")
        return

    if args.reset_password:
        username, password = args.reset_password
        if db.reset_password(username, password):
            print(f"Password for user '{username}' reset successfully.")
        else:
            print(f"Error: User '{username}' not found.")
        return

    if db.user_count() == 0:
        default_pass = "admin123"
        db.create_user("admin", default_pass)
        print("=" * 70)
        print("INITIAL SETUP: Created default admin account!")
        print("  Username: admin")
        print("  Password: " + default_pass)
        print("  PLEASE CHANGE THIS PASSWORD IMMEDIATELY AFTER LOGIN!")
        print("=" * 70)

    config = load_and_validate_config(db)
    controller = UPSController(config, db)

    if args.test_shutdown or args.test_wol:
        if args.test_shutdown:
            controller.test_shutdown()
        if args.test_wol:
            controller.test_wol()
        print("\nTest finished. Exiting.")
        return

    web_cfg = config.get("web", {})
    host = args.host or web_cfg.get("host", "0.0.0.0")
    port = args.port or web_cfg.get("port", 8080)

    WebDashboardHandler.controller = controller
    WebDashboardHandler.db = db

    server = ThreadedHTTPServer((host, port), WebDashboardHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    logging.info("Web Dashboard running at http://" + str(host) + ":" + str(port) + "/")

    controller.run_loop()

if __name__ == "__main__":
    main()
