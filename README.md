# UPS Controller & Web Dashboard for Proxmox

Een lichtgewicht, productie-klare UPS monitoring oplossing en webgebaseerd dashboard speciaal ontworpen voor Proxmox VE servers, geoptimaliseerd om te draaien op een Raspberry Pi 4.

![UPS Controller Showcase](https://img.shields.io/badge/Status-Production%20Ready-success)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![SQLite](https://img.shields.io/badge/Database-SQLite3-lightgrey)

---

## ⚡ Key Features

- **Geen Docker of zware frameworks**: 100% ingebouwde Python multithreaded HTTP-server & SQLite database voor een minimaal geheugen- en CPU-gebruik.
- **NUT (Network UPS Tools) integratie**: Houdt continu de status, acculading, runtime en spanningen van je UPS in de gaten.
- **Automatische Proxmox Shutdown**: Schakelt netjes alle geconfigureerde Proxmox VE nodes uit via de officiële Proxmox API wanneer de UPS acculading onder een ingestelde drempel komt.
- **Slimme Wake-on-LAN (WoL)**: Stuurt pas WoL magic packets wanneer de netspanning is teruggekeerd én alle ingestelde voorwaarden (bijv. stabiele internet-/DNS-verbinding of acculading) continu zijn voldaan gedurende een instelbare vertraging.
- **Web Dashboard**:
  - **Publieke weergave (Niet ingelogd)**: Toont uitsluitend veilige statistieken (acculading %, netstatus, spanningen, historische grafieken, event-logboek, node-samenvatting).
  - **Beheerderspaneel (Admin)**: Beveiligd met PBKDF2-SHA256 wachtwoord-hashing, sessietokens en CSRF-beveiliging. Hiermee pas je instellingen aan, beheer je admin-accounts en voer je handmatig testacties uit.
- **Discord Notificaties**: Ontvang direct meldingen bij stroomuitval, het starten van shutdowns of het versturen van WoL packets.

---

## 🚀 Live Demo / Showcase

Probeer de virtuele online showcase op GitHub Pages:
👉 **[UPS Controller Live Demo](https://vulcanosoftware.github.io/VulcanoCraft_ups_controller/)**

---

## 🛠️ Installatie op Raspberry Pi 4

### 1. Vereisten installeren
```bash
sudo apt update
sudo apt install -y python3 python3-pip nut wakeonlan
pip3 install pyyaml requests
```

### 2. Bestanden plaatsen
```bash
sudo mkdir -p /opt/ups-controller
sudo cp ups-monitor.py /opt/ups-controller/
cd /opt/ups-controller
```

### 3. Configuratie aanmaken (`config.yml`)
Kopieer de template en pas deze aan naar jouw wensen:
```bash
cp config_template.yml config.yml
nano config.yml
```

---

## ⚙️ Configuratie Voorbeeld (`config.yml`)

```yaml
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

proxmox:
  nodes:
    - name: pve1
      host: 192.168.1.10
      mac: "aa:bb:cc:dd:ee:ff"
  api_token: "root@pam!ups=YOUR_SECRET_TOKEN"
  verify_ssl: false

wol:
  broadcast: "192.168.1.255"
  port: 9

discord:
  enabled: true
  webhook_url: "https://discord.com/api/webhooks/..."
```

---

## 👤 Admin Gebruikersbeheer CLI

Wanneer de software voor de eerste keer opstart zonder accounts, wordt er automatisch een standaard admin-account aangemaakt:
- **Gebruikersnaam**: `admin`
- **Wachtwoord**: `admin`

Je kunt ook rechtstreeks via de commandline beheerdersaccounts aanmaken of wachtwoorden herstellen:

```bash
# Nieuwe admin gebruiker aanmaken
python3 ups-monitor.py --create-admin adminnaam mijnwachtwoord

# Wachtwoord herstellen
python3 ups-monitor.py --reset-password adminnaam nieuwwachtwoord
```

---

## 🧪 Handmatig Testen

Test de Proxmox API shutdown of WoL functies veilig vanaf de commandline of vanuit het admin web-dashboard:

```bash
# Test shutdown API naar alle Proxmox nodes
python3 ups-monitor.py --test-shutdown

# Test Wake-on-LAN naar alle Proxmox nodes
python3 ups-monitor.py --test-wol
```

---

## 🔒 Beveiliging & Productiereedheid

- **Publiek vs Admin Scheiding**: Niet-ingelogde bezoekers kunnen geen gevoelige API tokens, webhooks, of instellingen inzien of aanpassen.
- **CSRF & Session Security**: Alle admin-acties vereisen een geldige CSRF-token header en HTTP-Only cookies met verloopdatum.
- **Rate Limiting**: Inlogpogingen worden op IP-basis gelimiteerd om brute-force aanvallen te voorkomen.
- **Database**: SQLite3 met geparametriseerde SQL-queries (geen SQL injection risico) en een thread-safe slot.

---

## 📄 Licentie
MIT License - Vrij te gebruiken en aan te passen.
