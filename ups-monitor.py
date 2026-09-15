#!/usr/bin/env python3
"""
UPS Controller for Proxmox
==========================

Monitors a UPS via NUT (Network UPS Tools).
When running on battery and the charge drops below a configured threshold,
it cleanly shuts down Proxmox nodes via the Proxmox API.
When power returns, it waits until configured conditions have been continuously
true for a configurable delay before sending Wake-on-LAN.

The machine running this script (usually a Raspberry Pi) is never shut down.

Features:
  - Fully configurable via config.yml
  - Startup delay that only starts counting once conditions are met
  - Discord notifications
  - Manual test modes for shutdown and Wake-on-LAN
  - Strict config validation with clear error messages
  - Automatic generation of a detailed config template

Usage:
  python3 ups-monitor.py                     # normal monitoring mode
  python3 ups-monitor.py --test-shutdown     # send real shutdown commands (dangerous!)
  python3 ups-monitor.py --test-wol          # send Wake-on-LAN packets
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
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Any, Dict
from enum import Enum, auto

BASE_DIR = Path("/opt/ups-controller")
CONFIG_PATH = BASE_DIR / "config.yml"
TEMPLATE_PATH = BASE_DIR / "config_template.yml"


# ==============================================================================
# Detailed configuration template
# ==============================================================================
CONFIG_TEMPLATE = """# ==============================================================================
# UPS Controller - Configuration File
# ==============================================================================
#
# Copy this file to config.yml and edit it:
#
#   cp config_template.yml config.yml
#   nano config.yml
#
# After editing, restart the service:
#   sudo systemctl restart ups-controller
#
# ==============================================================================


# ------------------------------------------------------------------------------
# UPS (NUT) settings
# ------------------------------------------------------------------------------
ups:
  # Name of the UPS as defined in /etc/nut/ups.conf
  name: "gembird@localhost"

  # Battery percentage at which shutdown of Proxmox nodes is triggered
  battery_threshold: 50

  # How often (in seconds) the script checks the UPS status
  poll_interval: 5

  # After the UPS switches to battery, wait this many seconds before
  # checking the battery percentage (filters short power dips)
  on_battery_grace: 15


# ------------------------------------------------------------------------------
# Startup behaviour (after power returns)
# ------------------------------------------------------------------------------
# The script will only send Wake-on-LAN when the configured conditions have
# been CONTINUOUSLY true for the full "delay" period.
#
# Example:
#   delay: 40
#   internet.enabled: true
#
# → Once internet becomes available, a 40-second timer starts.
# → If internet drops during those 40 seconds, the timer is reset.
# → Only when internet has been stable for 40 seconds is WoL sent.
#
# You can enable multiple conditions – they are all required (AND logic).
# ------------------------------------------------------------------------------
startup:
  # How long the conditions must remain true before sending Wake-on-LAN (seconds)
  # Set to 0 if you want to send WoL as soon as the conditions are true.
  delay: 40

  conditions:
    # Require UPS battery charge to be at least this percentage.
    # Set to null to disable.
    battery_above: null          # e.g. 70

    # Require basic internet connectivity
    internet:
      enabled: true
      host: "1.1.1.1"            # Cloudflare DNS

    # Require DNS resolution (ping a domain name)
    dns:
      enabled: false
      host: "google.com"


# ------------------------------------------------------------------------------
# Proxmox nodes
# ------------------------------------------------------------------------------
proxmox:
  nodes:
    - name: pve1
      host: 192.168.1.10
      mac: "aa:bb:cc:dd:ee:ff"

    - name: pve2
      host: 192.168.1.11
      mac: "11:22:33:44:55:66"

  # Format: user@realm!tokenid=secret
  api_token: "root@pam!ups=YOUR_TOKEN_SECRET_HERE"
  verify_ssl: false
  timeout: 15


# ------------------------------------------------------------------------------
# Wake-on-LAN
# ------------------------------------------------------------------------------
wol:
  broadcast: "192.168.1.255"
  port: 9


# ------------------------------------------------------------------------------
# Discord notifications
# ------------------------------------------------------------------------------
discord:
  enabled: true
  webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"
  username: "UPS Controller"
  mention: ""


# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
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
# Configuration validation
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
        else:
            bat = conditions.get("battery_above")
            if bat is not None and (not isinstance(bat, (int, float)) or not (1 <= bat <= 100)):
                errors.append("startup.conditions.battery_above must be null or a number 1-100")

            for key in ("internet", "dns"):
                block = conditions.get(key)
                if block is not None:
                    if not isinstance(block, dict):
                        errors.append(f"startup.conditions.{key} must be a dictionary")
                    else:
                        if "enabled" in block and not isinstance(block["enabled"], bool):
                            errors.append(f"startup.conditions.{key}.enabled must be true or false")
                        if block.get("enabled") and not block.get("host"):
                            errors.append(f"startup.conditions.{key}.host is required when enabled")

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
        elif "!" not in token or "=" not in token:
            errors.append("proxmox.api_token has invalid format (user@realm!tokenid=secret)")

        if "verify_ssl" in pve and not isinstance(pve["verify_ssl"], bool):
            errors.append("proxmox.verify_ssl must be true or false")

        timeout = pve.get("timeout", 15)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            errors.append("proxmox.timeout must be a positive number")

    if "wol" not in config:
        errors.append("Missing section: 'wol'")
    else:
        wol = config["wol"]
        if not wol.get("broadcast"):
            errors.append("wol.broadcast is required")
        port = wol.get("port", 9)
        if not isinstance(port, int) or not (1 <= port <= 65535):
            errors.append("wol.port must be a valid port number")

    if "discord" in config:
        disc = config["discord"]
        if disc.get("enabled") is True:
            webhook = disc.get("webhook_url", "")
            if not webhook or "YOUR_WEBHOOK" in webhook or not webhook.startswith("https://"):
                errors.append("discord.webhook_url is required when discord.enabled is true")

    if "logging" in config:
        log = config["logging"]
        level = log.get("level", "INFO")
        if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            errors.append(f"logging.level '{level}' is invalid")

    return errors


def load_and_validate_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        print("=" * 70)
        print("ERROR: config.yml not found!")
        print("=" * 70)
        print()
        print(f"A detailed template has been created at:\n  {TEMPLATE_PATH}")
        print()
        print("Next steps:")
        print(f"  1. cp {TEMPLATE_PATH} {CONFIG_PATH}")
        print(f"  2. nano {CONFIG_PATH}")
        print("  3. Fill in your values")
        print("  4. sudo systemctl restart ups-controller")
        print()
        try:
            TEMPLATE_PATH.write_text(CONFIG_TEMPLATE, encoding="utf-8")
            print(f"Template written to {TEMPLATE_PATH}")
        except Exception as e:
            print(f"Could not write template: {e}")
        sys.exit(1)

    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print("=" * 70)
        print("ERROR: config.yml contains invalid YAML!")
        print("=" * 70)
        print(f"Details: {e}")
        sys.exit(1)
    except Exception as e:
        print("=" * 70)
        print(f"ERROR: Could not read config.yml: {e}")
        print("=" * 70)
        sys.exit(1)

    if not isinstance(config, dict):
        print("=" * 70)
        print("ERROR: config.yml is empty or not a valid YAML object")
        print("=" * 70)
        sys.exit(1)

    errors = validate_config(config)
    if errors:
        print("=" * 70)
        print("ERROR: config.yml is invalid!")
        print("=" * 70)
        print()
        for i, err in enumerate(errors, 1):
            print(f"  {i}. {err}")
        print()
        sys.exit(1)

    return config


# ==============================================================================
# Main controller
# ==============================================================================
class UPSController:
    def __init__(self, config: dict):
        self.cfg = config
        self.nodes = [Node(**n) for n in config["proxmox"]["nodes"]]
        self.state = State.ONLINE
        self.on_battery_since: Optional[float] = None
        self.conditions_met_since: Optional[float] = None
        self.setup_logging()

    def setup_logging(self):
        log_cfg = self.cfg.get("logging", {})
        level = getattr(logging, log_cfg.get("level", "INFO"))
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

    def get_ups_status(self) -> dict:
        try:
            result = subprocess.run(
                ["upsc", self.cfg["ups"]["name"]],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logging.error(f"upsc failed: {result.stderr.strip()}")
                return {}

            data = {}
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    data[key.strip()] = val.strip()
            return data
        except Exception as e:
            logging.error(f"Error reading UPS status: {e}")
            return {}

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
        """Return True only if every enabled condition is currently true."""
        conditions = self.cfg.get("startup", {}).get("conditions", {})

        # Battery level
        bat_req = conditions.get("battery_above")
        if bat_req is not None:
            try:
                charge = float(ups_data.get("battery.charge", 0))
            except (ValueError, TypeError):
                charge = 0
            if charge < bat_req:
                return False

        # Internet
        inet = conditions.get("internet", {})
        if inet.get("enabled"):
            host = inet.get("host", "1.1.1.1")
            if not self.ping(host):
                return False

        # DNS
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
                logging.info(f"Shutdown command sent to {node.name} ({node.host})")
                return True
            else:
                logging.error(f"Failed to shutdown {node.name}: {r.status_code} – {r.text}")
                return False
        except Exception as e:
            logging.error(f"Exception while shutting down {node.name}: {e}")
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
                logging.info(f"WoL sent to {node.name} ({node.mac})")
                return True
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.debug(f"wakeonlan command failed: {e}")

        try:
            from wakeonlan import send_magic_packet
            send_magic_packet(
                node.mac,
                ip_address=self.cfg["wol"]["broadcast"],
                port=self.cfg["wol"].get("port", 9),
            )
            logging.info(f"WoL (python) sent to {node.name} ({node.mac})")
            return True
        except Exception as e:
            logging.error(f"WoL failed for {node.name}: {e}")
            return False

    def trigger_shutdown(self):
        logging.warning(">>> BATTERY LOW – initiating Proxmox node shutdown <<<")
        self.discord_notify(
            f"⚠️ **UPS battery ≤ {self.cfg['ups']['battery_threshold']}%** – "
            f"shutting down all Proxmox nodes!"
        )

        for node in self.nodes:
            self.shutdown_node(node)
            time.sleep(1)

        self.state = State.WAITING_FOR_POWER
        self.conditions_met_since = None
        logging.info("All shutdown commands sent. Waiting for power + conditions...")

    def trigger_wol(self):
        logging.info(">>> Conditions stable – sending Wake-on-LAN <<<")
        self.discord_notify("✅ **Startup conditions met for required time** – sending Wake-on-LAN")

        for node in self.nodes:
            self.wake_node(node)
            time.sleep(0.5)

        self.state = State.ONLINE
        self.on_battery_since = None
        self.conditions_met_since = None

    def test_shutdown(self):
        print("=" * 70)
        print("TEST MODE: --test-shutdown")
        print("=" * 70)
        print()
        print("This will send REAL shutdown commands to:")
        for node in self.nodes:
            print(f"  • {node.name}  ({node.host})")
        print()
        answer = input("Are you sure? Type 'YES' to continue: ")
        if answer.strip() != "YES":
            print("Aborted.")
            return

        logging.warning("TEST: Sending shutdown commands...")
        self.discord_notify("🧪 **TEST**: Sending shutdown commands")

        success = 0
        for node in self.nodes:
            if self.shutdown_node(node):
                success += 1
            time.sleep(1)

        print(f"\nDone. {success}/{len(self.nodes)} nodes contacted.")
        logging.info(f"TEST shutdown finished: {success}/{len(self.nodes)} ok")

    def test_wol(self):
        print("=" * 70)
        print("TEST MODE: --test-wol")
        print("=" * 70)
        print()
        print("This will send Wake-on-LAN packets to:")
        for node in self.nodes:
            print(f"  • {node.name}  MAC={node.mac}")
        print()
        answer = input("Continue? Type 'YES' to confirm: ")
        if answer.strip() != "YES":
            print("Aborted.")
            return

        logging.info("TEST: Sending Wake-on-LAN packets...")
        self.discord_notify("🧪 **TEST**: Sending Wake-on-LAN packets")

        success = 0
        for node in self.nodes:
            if self.wake_node(node):
                success += 1
            time.sleep(0.5)

        print(f"\nDone. {success}/{len(self.nodes)} WoL packets sent.")
        logging.info(f"TEST WoL finished: {success}/{len(self.nodes)} ok")

    def run(self):
        logging.info("UPS Controller started")
        self.discord_notify("🟢 UPS Controller started and monitoring")

        while True:
            try:
                status = self.get_ups_status()
                if not status:
                    time.sleep(self.cfg["ups"]["poll_interval"])
                    continue

                ups_status = status.get("ups.status", "")
                try:
                    charge = float(status.get("battery.charge", 100))
                except (ValueError, TypeError):
                    charge = 100.0

                on_battery = "OB" in ups_status
                online = "OL" in ups_status

                logging.debug(
                    f"Status: {ups_status} | Charge: {charge}% | State: {self.state.name}"
                )

                # -------------------- State machine --------------------
                if self.state == State.ONLINE:
                    if on_battery:
                        self.state = State.ON_BATTERY
                        self.on_battery_since = time.time()
                        logging.warning(f"Power lost – now on battery ({charge}%)")
                        self.discord_notify(f"🟡 Power lost – running on battery ({charge}%)")

                elif self.state == State.ON_BATTERY:
                    if online:
                        self.state = State.ONLINE
                        self.on_battery_since = None
                        logging.info("Power restored quickly (no shutdown needed)")
                        self.discord_notify("🟢 Power restored (short outage)")
                    else:
                        grace = self.cfg["ups"].get("on_battery_grace", 15)
                        if (
                            self.on_battery_since
                            and (time.time() - self.on_battery_since) >= grace
                        ):
                            if charge <= self.cfg["ups"]["battery_threshold"]:
                                self.trigger_shutdown()

                elif self.state == State.WAITING_FOR_POWER:
                    if not online:
                        # Power disappeared again
                        if self.conditions_met_since is not None:
                            logging.info("Power lost again – resetting condition timer")
                        self.conditions_met_since = None
                    else:
                        # Power is present → evaluate conditions
                        conditions_ok = self.check_startup_conditions(status)

                        if conditions_ok:
                            if self.conditions_met_since is None:
                                # Conditions just became true → start the delay timer
                                self.conditions_met_since = time.time()
                                delay = self.cfg.get("startup", {}).get("delay", 0)
                                logging.info(
                                    f"Startup conditions met – starting {delay}s stability timer"
                                )
                                self.discord_notify(
                                    f"🔌 Conditions met – waiting {delay}s of stability before WoL"
                                )

                            # Check if the delay has elapsed
                            delay = self.cfg.get("startup", {}).get("delay", 0)
                            elapsed = time.time() - self.conditions_met_since
                            if elapsed >= delay:
                                self.trigger_wol()
                        else:
                            # Conditions no longer true → reset timer
                            if self.conditions_met_since is not None:
                                logging.info("Startup conditions lost – resetting timer")
                                self.conditions_met_since = None

                time.sleep(self.cfg["ups"]["poll_interval"])

            except KeyboardInterrupt:
                logging.info("Stopped by user")
                break
            except Exception as e:
                logging.exception(f"Unexpected error: {e}")
                time.sleep(10)


def main():
    parser = argparse.ArgumentParser(
        description="UPS Controller for Proxmox",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Normal monitoring mode
  %(prog)s --test-shutdown        Test shutdown API (REAL shutdown!)
  %(prog)s --test-wol             Test Wake-on-LAN
        """,
    )
    parser.add_argument("--test-shutdown", action="store_true",
                        help="Send real shutdown commands to all nodes and exit")
    parser.add_argument("--test-wol", action="store_true",
                        help="Send Wake-on-LAN packets to all nodes and exit")
    args = parser.parse_args()

    config = load_and_validate_config()
    controller = UPSController(config)

    if args.test_shutdown or args.test_wol:
        if args.test_shutdown:
            controller.test_shutdown()
        if args.test_wol:
            controller.test_wol()
        print("\nTest(s) finished. Exiting.")
        return

    controller.run()


if __name__ == "__main__":
    main()
