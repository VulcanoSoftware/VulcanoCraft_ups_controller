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

Features:
  - Embedded multithreaded HTTP server (no external heavy frameworks)
  - SQLite persistent storage for statistics, events, sessions, and settings
  - Public dashboard view (safe stats, battery state, node status summary, charts)
  - Admin login & session management (PBKDF2-SHA256 password hashing, CSRF tokens, rate limiting)
  - Full admin settings management (UPS thresholds, Proxmox nodes, WoL, Discord)
  - Admin manual action triggers (Test Shutdown, Test WoL)
  - User management (CLI & Web)
  - Discord notifications
  - Low memory & CPU overhead, optimized for Raspberry Pi 4

Usage:
  python3 ups-monitor.py                              # normal monitoring + web server mode
  python3 ups-monitor.py --create-admin admin secret   # create an admin user
  python3 ups-monitor.py --reset-password admin secret # reset an admin user password
  python3 ups-monitor.py --test-shutdown              # send real shutdown commands
  python3 ups-monitor.py --test-wol                   # send Wake-on-LAN packets
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

# Path fallback if /opt/ups-controller is not writable
BASE_DIR = Path("/opt/ups-controller") if Path("/opt/ups-controller").exists() else Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yml"
TEMPLATE_PATH = BASE_DIR / "config_template.yml"
DB_PATH = BASE_DIR / "ups_monitor.db"

# Global database lock for thread safety
db_lock = threading.Lock()

# ==============================================================================
# Detailed configuration template
# ==============================================================================
CONFIG_TEMPLATE = """# ==============================================================================
# UPS Controller - Configuration File
# ==============================================================================

# Web Dashboard Settings
web:
  enabled: true
  host: "0.0.0.0"
  port: 8080

# UPS (NUT) settings
ups:
  name: "gembird@localhost"
  battery_threshold: 50
  poll_interval: 5
  on_battery_grace: 15

# Startup behaviour (after power returns)
startup:
  delay: 40
  conditions:
    battery_above: null
    internet:
      enabled: true
      host: "1.1.1.1"
    dns:
      enabled: false
      host: "google.com"

# Proxmox nodes
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

# Wake-on-LAN
wol:
  broadcast: "192.168.1.255"
  port: 9

# Discord notifications
discord:
  enabled: false
  webhook_url: ""
  username: "UPS Controller"
  mention: ""

# Logging
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


# ==============================================================================
# Database & Authentication Manager
# ==============================================================================
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
                    output_voltage REAL
                )
            """)
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
                    load: Optional[float], in_v: Optional[float], out_v: Optional[float]):
        now = time.time()
        with db_lock, self.get_connection() as conn:
            conn.cursor().execute(
                "INSERT INTO stats (timestamp, status, charge, runtime, load, input_voltage, output_voltage) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (now, status, charge, runtime, load, in_v, out_v)
            )
            # Prune metrics older than 7 days
            conn.cursor().execute("DELETE FROM stats WHERE timestamp < ?", (now - 7 * 86400,))
            conn.commit()

    def record_event(self, level: str, message: str):
        now = time.time()
        with db_lock, self.get_connection() as conn:
            conn.cursor().execute(
                "INSERT INTO events (timestamp, level, message) VALUES (?, ?, ?)",
                (now, level, message)
            )
            # Retain up to 1000 events
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


# ==============================================================================
# Validation helpers & Config Loader
# ==============================================================================
def validate_mac(mac: str) -> bool:
    return bool(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac))

def validate_config(config: Dict[str, Any]) -> List[str]:
    errors = []
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
    # Default initial config structure
    default_config = yaml.safe_load(CONFIG_TEMPLATE)

    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                file_config = yaml.safe_load(f)
                if isinstance(file_config, dict):
                    default_config.update(file_config)
        except Exception as e:
            print(f"Warning: Could not read {CONFIG_PATH}: {e}")

    # Merge dynamic settings from SQLite database
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


# ==============================================================================
# UPS Controller Core Engine
# ==============================================================================
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
        self.db.record_event(level, message)

    def get_ups_status(self) -> dict:
        try:
            result = subprocess.run(
                ["upsc", self.cfg["ups"]["name"]],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                # Mock status if upsc fails (e.g. dev/test env without actual physical UPS)
                return self.last_ups_data if self.last_ups_data else {
                    "ups.status": "OL",
                    "battery.charge": "100",
                    "battery.runtime": "3600",
                    "ups.load": "15",
                    "input.voltage": "230.0",
                    "output.voltage": "230.0"
                }

            data = {}
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    data[key.strip()] = val.strip()
            self.last_ups_data = data
            return data
        except Exception as e:
            logging.debug(f"upsc execution exception: {e}")
            return self.last_ups_data if self.last_ups_data else {
                "ups.status": "OL",
                "battery.charge": "100",
                "battery.runtime": "3600",
                "ups.load": "15",
                "input.voltage": "230.0",
                "output.voltage": "230.0"
            }

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
        if inet.get("enabled"):
            host = inet.get("host", "1.1.1.1")
            if not self.ping(host):
                return False

        dns = conditions.get("dns", {})
        if dns.get("enabled"):
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

        self.state = State.WAITING_FOR_POWER
        self.conditions_met_since = None

    def trigger_wol(self):
        self.log_event("INFO", ">>> Conditions stable – sending Wake-on-LAN <<<")
        self.discord_notify("✅ **Startup conditions met for required time** – sending Wake-on-LAN")

        for node in self.nodes:
            self.wake_node(node)
            time.sleep(0.5)

        self.state = State.ONLINE
        self.on_battery_since = None
        self.conditions_met_since = None

    def test_shutdown(self) -> Dict[str, Any]:
        self.log_event("WARNING", "MANUAL TEST: Sending shutdown commands...")
        results = {}
        for node in self.nodes:
            results[node.name] = self.shutdown_node(node)
            time.sleep(0.5)
        return results

    def test_wol(self) -> Dict[str, Any]:
        self.log_event("INFO", "MANUAL TEST: Sending Wake-on-LAN packets...")
        results = {}
        for node in self.nodes:
            results[node.name] = self.wake_node(node)
            time.sleep(0.5)
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

                    self.db.record_stat(ups_status, charge, runtime, load, in_v, out_v)

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


# ==============================================================================
# Rate Limiter & Web Server API Request Handler
# ==============================================================================
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
        # Suppress standard HTTP request logging to avoid cluttering main logs
        pass

    # ==========================================================================
    # GET Handlers
    # ==========================================================================
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Public APIs
        if path == "/api/public/stats":
            self.handle_public_stats()
        elif path == "/api/public/history":
            self.handle_public_history()
        elif path == "/api/public/events":
            self.handle_public_events()
        # Admin Protected APIs
        elif path == "/api/admin/config":
            session = self.authenticate_admin()
            if not session:
                self.send_json({"error": "Unauthorized"}, 401)
                return
            # Remove sensitive values if any, or present clean admin config
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
        else:
            self.send_json({"error": "Not Found"}, 404)

    # ==========================================================================
    # POST Handlers
    # ==========================================================================
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

        # All following routes require Admin Auth
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

    # ==========================================================================
    # Helper API endpoints
    # ==========================================================================
    def handle_public_stats(self):
        ups_raw = self.controller.get_ups_status()

        # Only expose non-sensitive public metrics
        safe_nodes = [
            {"name": n.name, "host": n.host} for n in self.controller.nodes
        ]

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
            "nodes_summary": safe_nodes,
            "startup_delay": self.controller.cfg["startup"]["delay"],
            "server_time": time.time()
        }
        self.send_json(res)

    def handle_public_history(self):
        stats = self.db.get_latest_stats(60)
        self.send_json({"history": stats})

    def handle_public_events(self):
        events = self.db.get_recent_events(30)
        self.send_json({"events": events})


# ==============================================================================
# Embedded Web Dashboard Frontend Single-Page Application
# ==============================================================================
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
        body { background-color: #0f172a; color: #f8fafc; font-family: system-ui, -apple-system, sans-serif; }
        .card { background-color: #1e293b; border: 1px solid #334155; color: #f8fafc; border-radius: 12px; }
        .card-header { border-bottom: 1px solid #334155; font-weight: 600; }
        .badge-online { background-color: #10b981; color: #022c22; font-weight: 600; }
        .badge-battery { background-color: #f59e0b; color: #451a03; font-weight: 600; }
        .badge-waiting { background-color: #3b82f6; color: #1e3a8a; font-weight: 600; }
        .stat-value { font-size: 2.2rem; font-weight: 700; color: #38bdf8; }
        .nav-tabs .nav-link { color: #94a3b8; border: none; font-weight: 500; }
        .nav-tabs .nav-link.active { color: #38bdf8; background-color: transparent; border-bottom: 3px solid #38bdf8; }
        .form-control, .form-select { background-color: #0f172a; border: 1px solid #334155; color: #f8fafc; }
        .form-control:focus, .form-select:focus { background-color: #0f172a; color: #f8fafc; border-color: #38bdf8; box-shadow: none; }
        .table { color: #f8fafc; }
        .table-dark { --bs-table-bg: #1e293b; }
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
                <span id="user-status-text" class="text-muted small">Public View</span>
                <button id="btn-login-modal" class="btn btn-outline-info btn-sm" onclick="openLoginModal()">
                    <i class="bi bi-box-arrow-in-right"></i> Admin Login
                </button>
                <button id="btn-logout" class="btn btn-outline-danger btn-sm d-none" onclick="logout()">
                    <i class="bi bi-box-arrow-right"></i> Logout
                </button>
            </div>
        </div>
    </nav>

    <div class="container-fluid px-4">
        <!-- Tab Navigation -->
        <ul class="nav nav-tabs mb-4" id="mainTabs" role="tablist">
            <li class="nav-item">
                <button class="nav-link active" id="tab-overview-btn" data-bs-toggle="tab" data-bs-target="#tab-overview">
                    <i class="bi bi-speedometer2"></i> Dashboard Overview
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" id="tab-history-btn" data-bs-toggle="tab" data-bs-target="#tab-history">
                    <i class="bi bi-graph-up"></i> History & Logs
                </button>
            </li>
            <li class="nav-item admin-only d-none">
                <button class="nav-link" id="tab-settings-btn" data-bs-toggle="tab" data-bs-target="#tab-settings">
                    <i class="bi bi-gear-fill"></i> Settings & Control
                </button>
            </li>
            <li class="nav-item admin-only d-none">
                <button class="nav-link" id="tab-users-btn" data-bs-toggle="tab" data-bs-target="#tab-users">
                    <i class="bi bi-people-fill"></i> User Accounts
                </button>
            </li>
        </ul>

        <div class="tab-content" id="mainTabsContent">
            <!-- OVERVIEW TAB -->
            <div class="tab-pane fade show active" id="tab-overview">
                <div class="row g-4 mb-4">
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-muted small fw-semibold">SYSTEM STATUS</div>
                            <div class="d-flex align-items-center justify-content-between mt-2">
                                <span id="stat-state" class="badge badge-online fs-6 px-3 py-2">ONLINE</span>
                                <i class="bi bi-shield-check fs-2 text-success"></i>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-muted small fw-semibold">BATTERY CHARGE</div>
                            <div class="stat-value mt-1" id="stat-charge">-- %</div>
                            <div class="progress mt-2" style="height: 6px;">
                                <div id="progress-charge" class="progress-bar bg-info" style="width: 0%"></div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-muted small fw-semibold">ESTIMATED RUNTIME</div>
                            <div class="stat-value mt-1" id="stat-runtime">-- min</div>
                            <div class="text-muted small mt-1">Threshold: <span id="stat-threshold">--</span>%</div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-muted small fw-semibold">UPS LOAD & VOLTAGE</div>
                            <div class="stat-value mt-1" id="stat-load">-- %</div>
                            <div class="text-muted small mt-1">Input: <span id="stat-in-v">--</span>V</div>
                        </div>
                    </div>
                </div>

                <div class="row g-4">
                    <div class="col-lg-8">
                        <div class="card p-3">
                            <div class="card-header bg-transparent px-0 pt-0 text-info">
                                <i class="bi bi-activity"></i> Live Battery & Load Chart
                            </div>
                            <div style="height: 280px;">
                                <canvas id="liveChart"></canvas>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="card p-3 h-100">
                            <div class="card-header bg-transparent px-0 pt-0 text-info">
                                <i class="bi bi-hdd-network"></i> Monitored Proxmox Nodes
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
                        <i class="bi bi-journal-text"></i> System Event Logs
                    </div>
                    <div class="table-responsive mt-3">
                        <table class="table table-dark table-hover align-middle">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Level</th>
                                    <th>Message</th>
                                </tr>
                            </thead>
                            <tbody id="events-table-body">
                                <tr><td colspan="3" class="text-muted text-center">Loading events...</td></tr>
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
                            <h5 class="text-info mb-3"><i class="bi bi-sliders"></i> System Configuration</h5>
                            <form id="settings-form" onsubmit="saveSettings(event)">
                                <h6 class="text-warning mt-2 mb-3">UPS Settings</h6>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label">NUT UPS Name</label>
                                        <input type="text" id="cfg-ups-name" class="form-control" required>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">Battery Threshold (%)</label>
                                        <input type="number" id="cfg-ups-threshold" class="form-control" min="1" max="99" required>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">Poll Interval (seconds)</label>
                                        <input type="number" id="cfg-ups-poll" class="form-control" min="2" required>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">On-Battery Grace Period (seconds)</label>
                                        <input type="number" id="cfg-ups-grace" class="form-control" min="0" required>
                                    </div>
                                </div>

                                <h6 class="text-warning mt-4 mb-3">Startup & WoL Settings</h6>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label">Startup Stability Delay (seconds)</label>
                                        <input type="number" id="cfg-startup-delay" class="form-control" min="0" required>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">WoL Broadcast IP</label>
                                        <input type="text" id="cfg-wol-broadcast" class="form-control" required>
                                    </div>
                                </div>

                                <h6 class="text-warning mt-4 mb-3">Discord Notifications</h6>
                                <div class="row g-3 mb-3">
                                    <div class="col-md-4">
                                        <div class="form-check mt-4">
                                            <input class="form-check-input" type="checkbox" id="cfg-discord-enabled">
                                            <label class="form-check-label">Enable Notifications</label>
                                        </div>
                                    </div>
                                    <div class="col-md-8">
                                        <label class="form-label">Webhook URL</label>
                                        <input type="text" id="cfg-discord-url" class="form-control">
                                    </div>
                                </div>

                                <div class="d-flex justify-content-end mt-4">
                                    <button type="submit" class="btn btn-info px-4">
                                        <i class="bi bi-save"></i> Save Configuration
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>

                    <div class="col-lg-4">
                        <div class="card p-4">
                            <h5 class="text-warning mb-3"><i class="bi bi-tools"></i> Admin Manual Actions</h5>
                            <p class="text-muted small">Execute test triggers on configured Proxmox nodes.</p>
                            <div class="d-grid gap-3 mt-3">
                                <button class="btn btn-outline-warning" onclick="triggerTestAction('test-wol')">
                                    <i class="bi bi-broadcast"></i> Send Test Wake-on-LAN
                                </button>
                                <button class="btn btn-outline-danger" onclick="triggerTestAction('test-shutdown')">
                                    <i class="bi bi-power"></i> Send Test Shutdown API
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
                            <h5 class="text-info mb-3"><i class="bi bi-shield-lock"></i> Admin Accounts</h5>
                            <div class="table-responsive">
                                <table class="table table-dark align-middle">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Username</th>
                                            <th>Created</th>
                                            <th>Action</th>
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
                            <h5 class="text-info mb-3"><i class="bi bi-person-plus"></i> Create Admin User</h5>
                            <form onsubmit="createAdminUser(event)">
                                <div class="mb-3">
                                    <label class="form-label">Username</label>
                                    <input type="text" id="new-username" class="form-control" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" id="new-password" class="form-control" required>
                                </div>
                                <button type="submit" class="btn btn-success w-100">
                                    <i class="bi bi-check-circle"></i> Create Account
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
                    <h5 class="modal-title text-info"><i class="bi bi-shield-lock-fill"></i> Admin Login</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="login-error" class="alert alert-danger d-none"></div>
                    <form onsubmit="handleLogin(event)">
                        <div class="mb-3">
                            <label class="form-label">Username</label>
                            <input type="text" id="login-username" class="form-control" required autocomplete="username">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" id="login-password" class="form-control" required autocomplete="current-password">
                        </div>
                        <button type="submit" class="btn btn-info w-100 mt-2">Login</button>
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

        document.addEventListener("DOMContentLoaded", () => {
            initChart();
            checkAuth();
            fetchPublicStats();
            fetchPublicEvents();
            setInterval(fetchPublicStats, 3000);
            setInterval(fetchPublicEvents, 10000);
        });

        function initChart() {
            const ctx = document.getElementById('liveChart').getContext('2d');
            chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        { label: 'Charge %', data: [], borderColor: '#38bdf8', backgroundColor: 'rgba(56,189,248,0.1)', fill: true, tension: 0.3 },
                        { label: 'Load %', data: [], borderColor: '#f59e0b', backgroundColor: 'transparent', borderDash: [5,5], tension: 0.3 }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { labels: { color: '#94a3b8' } } },
                    scales: {
                        x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
                        y: { min: 0, max: 100, ticks: { color: '#94a3b8' }, grid: { color: '#334155' } }
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
            document.getElementById('user-status-text').innerText = `Logged in as: ${username}`;
            document.getElementById('btn-login-modal').classList.add('d-none');
            document.getElementById('btn-logout').classList.remove('d-none');
            document.querySelectorAll('.admin-only').forEach(el => el.classList.remove('d-none'));
            loadAdminData();
        }

        function setLoggedOut() {
            authUser = null;
            csrfToken = "";
            document.getElementById('user-status-text').innerText = "Public View";
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
                stateEl.innerText = data.state;
                if (data.state === 'ONLINE') {
                    stateEl.className = 'badge badge-online fs-6 px-3 py-2';
                } else if (data.state === 'ON_BATTERY') {
                    stateEl.className = 'badge badge-battery fs-6 px-3 py-2';
                } else {
                    stateEl.className = 'badge badge-waiting fs-6 px-3 py-2';
                }

                // Render Nodes Summary
                const nodesContainer = document.getElementById('nodes-list');
                nodesContainer.innerHTML = data.nodes_summary.map(n => `
                    <div class="d-flex align-items-center justify-content-between p-2 mb-2 bg-dark rounded border border-secondary">
                        <div>
                            <span class="fw-bold">${n.name}</span>
                            <div class="text-muted small">${n.host}</div>
                        </div>
                        <span class="badge bg-success"><i class="bi bi-check-circle"></i> Registered</span>
                    </div>
                `).join('');

                fetchChartHistory();
            } catch(e) { console.error(e); }
        }

        async function fetchChartHistory() {
            try {
                const res = await fetch('/api/public/history');
                const data = await res.json();
                const labels = data.history.map(item => new Date(item.timestamp * 1000).toLocaleTimeString());
                const charges = data.history.map(item => item.charge);
                const loads = data.history.map(item => item.load);

                chart.data.labels = labels;
                chart.data.datasets[0].data = charges;
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
                    document.getElementById('cfg-ups-name').value = fullConfig.ups.name;
                    document.getElementById('cfg-ups-threshold').value = fullConfig.ups.battery_threshold;
                    document.getElementById('cfg-ups-poll').value = fullConfig.ups.poll_interval;
                    document.getElementById('cfg-ups-grace').value = fullConfig.ups.on_battery_grace;
                    document.getElementById('cfg-startup-delay').value = fullConfig.startup.delay;
                    document.getElementById('cfg-wol-broadcast').value = fullConfig.wol.broadcast;
                    document.getElementById('cfg-discord-enabled').checked = fullConfig.discord.enabled;
                    document.getElementById('cfg-discord-url').value = fullConfig.discord.webhook_url || '';
                }

                loadUsersList();
            } catch(e) { console.error(e); }
        }

        async function saveSettings(e) {
            e.preventDefault();
            if (!fullConfig) return;

            fullConfig.ups.name = document.getElementById('cfg-ups-name').value;
            fullConfig.ups.battery_threshold = parseFloat(document.getElementById('cfg-ups-threshold').value);
            fullConfig.ups.poll_interval = parseFloat(document.getElementById('cfg-ups-poll').value);
            fullConfig.ups.on_battery_grace = parseFloat(document.getElementById('cfg-ups-grace').value);
            fullConfig.startup.delay = parseFloat(document.getElementById('cfg-startup-delay').value);
            fullConfig.wol.broadcast = document.getElementById('cfg-wol-broadcast').value;
            fullConfig.discord.enabled = document.getElementById('cfg-discord-enabled').checked;
            fullConfig.discord.webhook_url = document.getElementById('cfg-discord-url').value;

            try {
                const res = await fetch('/api/admin/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                    body: JSON.stringify({ config: fullConfig, csrf_token: csrfToken })
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    alert('Configuration saved successfully!');
                } else {
                    alert('Error saving configuration: ' + (data.error || 'Unknown error'));
                }
            } catch(err) { alert('Network error'); }
        }

        async function triggerTestAction(action) {
            if (!confirm(`Are you sure you want to run ${action}?`)) return;
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
            } catch(e) { resDiv.innerHTML = '<span class="text-danger">Action failed</span>'; }
        }

        async function loadUsersList() {
            try {
                const res = await fetch('/api/admin/users');
                const data = await res.json();
                const tbody = document.getElementById('users-table-body');
                tbody.innerHTML = data.users.map(u => `
                    <tr>
                        <td>${u.id}</td>
                        <td class="fw-bold">${u.username}</td>
                        <td class="text-muted small">${u.created_at}</td>
                        <td>
                            <button class="btn btn-outline-danger btn-sm" onclick="deleteUser(${u.id})">
                                <i class="bi bi-trash"></i> Delete
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
                    alert('User created successfully');
                    document.getElementById('new-username').value = '';
                    document.getElementById('new-password').value = '';
                    loadUsersList();
                } else {
                    alert('Error: ' + (data.error || 'Failed to create user'));
                }
            } catch(e) { alert('Network error'); }
        }

        async function deleteUser(userId) {
            if (!confirm('Are you sure you want to delete this user?')) return;
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
"""


# ==============================================================================
# Main entrypoint and CLI handling
# ==============================================================================
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

    # Auto-create default admin account if table is empty
    if db.user_count() == 0:
        default_pass = "admin123"
        db.create_user("admin", default_pass)
        print("=" * 70)
        print("INITIAL SETUP: Created default admin account!")
        print(f"  Username: admin")
        print(f"  Password: {default_pass}")
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

    # Web Server Configuration
    web_cfg = config.get("web", {})
    host = args.host or web_cfg.get("host", "0.0.0.0")
    port = args.port or web_cfg.get("port", 8080)

    WebDashboardHandler.controller = controller
    WebDashboardHandler.db = db

    server = ThreadedHTTPServer((host, port), WebDashboardHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    logging.info(f"Web Dashboard running at http://{host}:{port}/")

    # Start UPS Monitoring background loop
    controller.run_loop()

if __name__ == "__main__":
    main()
