# ⚡ UPS Controller & Web Dashboard for Proxmox VE

A lightweight, production-ready UPS monitoring solution and embedded web dashboard specifically designed for Proxmox VE hypervisors, optimized to run seamlessly on a Raspberry Pi 4 or any Linux machine.

![Status](https://img.shields.io/badge/Status-Production%20Ready-success)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![SQLite](https://img.shields.io/badge/Database-SQLite3-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🚀 Key Features

- **Zero Heavy Frameworks or Docker**: Uses Python's built-in multithreaded HTTP server and SQLite database for ultra-low CPU and RAM footprint.
- **NUT (Network UPS Tools) Integration**: Continuously tracks battery charge, estimated runtime, load percentage, input/output voltages, and status codes.
- **Automated Proxmox Shutdown**: Gracefully initiates node shutdown via the official Proxmox VE API when battery level drops below your configured threshold during a power outage.
- **Smart Wake-on-LAN (WoL)**: Automatically wakes Proxmox servers once utility power returns and configured stability conditions (e.g. required battery level, internet ping, or DNS resolution) stay continuously met for a specified delay timer.
- **Responsive Web Dashboard**:
  - **Public View**: Displays real-time status, line voltages, interactive Chart.js battery/load graphs, event logs, and monitored node status without exposing sensitive settings.
  - **Admin Control Panel**: Protected by PBKDF2-SHA256 password hashing, secure session tokens, rate limiting, and CSRF validation. Allows full config updates, admin user management, and manual test triggers directly from the UI.
- **Discord Webhook Alerts**: Real-time notifications sent to your Discord channel on power outages, node shutdowns, or WoL startup triggers.

---

## 🌐 Live Interactive Demo

Test the interactive dashboard showcase hosted on GitHub Pages:
👉 **[UPS Controller Live Demo](https://vulcanosoftware.github.io/VulcanoCraft_ups_controller/)**

> **Default Admin Credentials (for demo and initial setup):**
> - **Username**: `admin`
> - **Password**: `admin123`

---

## 📦 Installation Guide

### 1. Install Prerequisites
Install required system packages and Python libraries:
```bash
sudo apt update
sudo apt install -y python3 python3-pip nut wakeonlan
pip3 install pyyaml requests
```

### 2. Download and Set Up Application Directory
```bash
sudo mkdir -p /opt/ups-controller
sudo cp ups-monitor.py /opt/ups-controller/
cd /opt/ups-controller
```

### 3. Create Configuration File (`config.yml`)
Create a `config.yml` file in the working directory:
```bash
cp config_template.yml config.yml
nano config.yml
```

---

## ⚙️ Configuration Example (`config.yml`)

```yaml
web:
  enabled: true
  host: "0.0.0.0"
  port: 8080

ups:
  name: "gembird@localhost"     # NUT UPS identifier
  battery_threshold: 50         # Shutdown Proxmox nodes when battery drops <= 50%
  poll_interval: 5              # Poll status every 5 seconds
  on_battery_grace: 15          # Delay (seconds) after power loss before evaluating threshold

startup:
  delay: 40                     # Wait 40 seconds after power returns and conditions pass before sending WoL
  conditions:
    battery_above: 70           # Require battery >= 70% before waking servers
    internet:
      enabled: true
      host: "1.1.1.1"           # Confirm external gateway / WAN connectivity
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
  api_token: "root@pam!ups=YOUR_SECRET_API_TOKEN"
  verify_ssl: false
  timeout: 15

wol:
  broadcast: "192.168.1.255"
  port: 9

database:
  retention_days: 7              # Automatically clean up stats & logs older than 7 days

discord:
  enabled: true
  webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
  username: "UPS Controller"
  mention: ""

logging:
  level: INFO
  file: /var/log/ups-controller.log
  max_bytes: 5000000
  backup_count: 5
```

---

## 🛠️ Running as a Systemd Service

To run UPS Controller automatically on boot, create a systemd service unit:

```bash
sudo nano /etc/systemd/system/ups-controller.service
```

Paste the following content:

```ini
[Unit]
Description=UPS Controller & Web Dashboard for Proxmox
After=network.target nut-server.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ups-controller
ExecStart=/usr/bin/python3 /opt/ups-controller/ups-monitor.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ups-controller.service
```

---

## 👤 Admin User Management CLI

When started for the first time without any registered users, the system automatically initializes a default admin user (`admin` / `admin123`).

You can also manage admin accounts or reset passwords directly from the command line:

```bash
# Create a new administrator account
python3 ups-monitor.py --create-admin <username> <password>

# Reset password for an existing account
python3 ups-monitor.py --reset-password <username> <password>
```

---

## 🧪 Safe Manual Testing

Test API shutdown triggers or Wake-on-LAN packets safely via CLI or through the Admin Dashboard UI:

```bash
# Test shutdown API call on all configured Proxmox nodes
python3 ups-monitor.py --test-shutdown

# Send Wake-on-LAN magic packets to all configured Proxmox nodes
python3 ups-monitor.py --test-wol
```

---

## 🔒 Security & Architecture

- **Role Separation**: Public visitors can view real-time metrics and system health without accessing API tokens, webhooks, or admin configurations.
- **Session & CSRF Protection**: Admin state changes require HTTP-Only session cookies and `X-CSRF-Token` header verification.
- **Brute-Force Rate Limiting**: IP-based rate limiting on login attempts guards against brute-force attacks.
- **SQL Injection Prevention**: SQLite operations use parameterized SQL queries and a thread lock for database safety.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
