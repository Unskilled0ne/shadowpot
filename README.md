# ShadowPot 🛡️

**A Modular Hybrid SSH Honeypot, Malware Trapper & SIEM Telemetry Engine**  
*Engineered by [Vasilis Tsiamouras](https://www.linkedin.com/in/vasilis-tsiamouras/)*

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Wazuh Ready](https://img.shields.io/badge/SIEM-Wazuh%20Ready-00A4E4.svg)](https://wazuh.com)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📌 Executive Summary

**ShadowPot** is a hybrid medium-interaction SSH honeypot designed to deceive threat actors, capture automated brute-force attacks, record interactive post-exploitation commands, and intercept downloaded malware droppers.

Unlike monolithic honeypots, ShadowPot produces **native SIEM-structured JSON telemetry** mapped directly to the **MITRE ATT&CK framework**, includes pre-configured **Wazuh decoders & detection rules**, and features an integrated **real-time threat intelligence dashboard** powered by FastAPI and Server-Sent Events (SSE).

---

## 🏗️ Architecture & Data Flow

```
                                  [ External Threat Actor / Botnet ]
                                                  │
                                                  ▼
                                     ┌─────────────────────────┐
                                     │  ShadowPot SSH Engine   │
                                     │    (Paramiko / Socket)  │
                                     └────────────┬────────────┘
                                                  │
                         ┌────────────────────────┼────────────────────────┐
                         ▼                        ▼                        ▼
               ┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐
               │  Emulated Shell   │    │   Payload Trap    │    │   Threat Intel    │
               │ (Recon, FS, PTY)  │    │  (curl/wget/hash) │    │  (GeoIP / ASN)    │
               └─────────┬─────────┘    └─────────┬─────────┘    └─────────┬─────────┘
                         │                        │                        │
                         └────────────────────────┼────────────────────────┘
                                                  │
                                                  ▼
                                       ┌─────────────────────┐
                                       │  Structured Logger  │
                                       └──────────┬──────────┘
                                                  │
                         ┌────────────────────────┴────────────────────────┐
                         ▼                                                 ▼
             ┌───────────────────────┐                         ┌───────────────────────┐
             │  logs/shadowpot.json  │                         │   data/shadowpot.db   │
             │   (Wazuh / Splunk)    │                         │   (FastAPI Dashboard) │
             └───────────┬───────────┘                         └───────────┬───────────┘
                         ▼                                                 ▼
               [ Wazuh Manager/XDR ]                             [ Live Web UI (8080) ]
```

---

## ⚡ Core Features

- **Realistic SSH Service Emulation:** Configurable banners (default: `OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`), automated RSA host-key generation, and interactive PTY allocation.
- **Interactive In-Memory Linux Shell:** Simulates Ubuntu 22.04 LTS environments, accurately responding to attacker reconnaissance (`uname -a`, `id`, `whoami`, `cat /etc/passwd`, `cat /etc/shadow`, `ps aux`, `netstat -tuln`, `history`).
- **Malware Ingress Trapping (MITRE T1105):** Intercepts dropper attempts (`curl`, `wget`, base64 decoders), securely quarantines the files with size/timeout caps, and calculates SHA-256 and MD5 hashes.
- **Threat Intel Enrichment:** Automatically resolves source IP geolocations (Country, City, ASN/ISP) with built-in memory caching.
- **Direct Wazuh SIEM Integration:** Ships with production-ready `shadowpot_decoders.xml` and `shadowpot_rules.xml` covering MITRE techniques T1110, T1078, T1059, and T1105.
- **Real-Time Web Dashboard:** Dark-mode SOC dashboard powered by FastAPI, Server-Sent Events (SSE), and Chart.js for live attack monitoring.

---

## 🎯 MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Event Trigger |
| :--- | :--- | :--- | :--- |
| **T1110.001** | Password Guessing | Credential Access | Inbound SSH authentication attempts |
| **T1078.003** | Local Accounts | Initial Access | Successful honeypot login |
| **T1082** | System Information Discovery | Discovery | Execution of `uname`, `uptime`, `/etc/os-release` |
| **T1087.001** | Local Accounts Discovery | Discovery | Execution of `whoami`, `id`, `cat /etc/passwd` |
| **T1016** | System Network Config Discovery | Discovery | Execution of `ifconfig`, `ip a`, `netstat` |
| **T1059.004** | Unix Shell | Execution | Any interactive command execution |
| **T1105** | Ingress Tool Transfer | Command & Control | Detection of `curl`, `wget`, or file drop commands |

---

## 🚀 Quickstart Guide

### 1. Installation

```bash
git clone https://github.com/your-username/shadowpot.git
cd shadowpot

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Launching ShadowPot

Start both the SSH listener (Port `2222`) and Web Dashboard (Port `8080`):
```bash
./run.py
```

Options:
```bash
./run.py --ssh-port 2222 --web-port 8080   # Custom ports
./run.py --no-web                          # Headless honeypot sensor only
./run.py --no-ssh                          # Dashboard only
```

Access the dashboard in your browser:
👉 `http://localhost:8080`

### 3. Simulating an Attack

In a separate terminal, execute the automated offensive test suite:
```bash
python3 tests/simulate_attack.py
```
Watch the live events stream into your web dashboard in real time!

---

## 🛡️ Wazuh Integration Setup

1. **Deploy Decoders:**  
   Copy `wazuh/shadowpot_decoders.xml` to `/var/ossec/etc/decoders/local_decoder.xml` on your Wazuh Manager.
2. **Deploy Rules:**  
   Copy `wazuh/shadowpot_rules.xml` to `/var/ossec/etc/rules/local_rules.xml` on your Wazuh Manager.
3. **Configure Agent Monitoring:**  
   Add the following block to `/var/ossec/etc/ossec.conf` on the honeypot host:
   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/path/to/shadowpot/logs/shadowpot.json</location>
   </localfile>
   ```
4. **Restart Wazuh Manager & Agent:**
   ```bash
   systemctl restart wazuh-manager
   systemctl restart wazuh-agent
   ```

---

## 📁 Repository Structure

```
shadowpot/
├── config.yaml                    # Honeypot configuration
├── requirements.txt               # Dependencies
├── run.py                         # Unified CLI launcher
├── shadowpot/
│   ├── server.py                  # Paramiko SSH listener & connection broker
│   ├── shell.py                   # In-memory emulated Linux environment
│   ├── trap.py                    # Malware dropper interceptor & hasher
│   ├── logger.py                  # Structured SIEM JSON & SQLite storage
│   ├── threat_intel.py            # GeoIP and ASN enrichment
│   └── dashboard.py               # FastAPI backend & SSE event broker
├── static/
│   └── index.html                 # Modern SOC dashboard UI (Tailwind + Chart.js)
├── wazuh/
│   ├── shadowpot_decoders.xml     # Custom Wazuh decoders
│   ├── shadowpot_rules.xml        # Custom Wazuh detection rules
│   └── ossec.conf.snippet         # Agent log monitoring snippet
└── tests/
    └── simulate_attack.py         # Automated offensive testing harness
```

---

## 👤 Author

**Vasilis Tsiamouras**  
- LinkedIn: [linkedin.com/in/vasilis-tsiamouras](https://www.linkedin.com/in/vasilis-tsiamouras/)  
- Role: Offensive Security & Penetration Testing | Computer Science, University of Thessaly
