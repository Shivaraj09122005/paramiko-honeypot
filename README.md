# Paramiko SSH Honeypot

A fully custom-built SSH honeypot written from scratch in Python, inspired by the design ideas behind Cowrie (https://github.com/cowrie/cowrie). It fakes an entire Linux server - login, shell, filesystem, and common attacker tools - while logging every move an attacker makes, classifying their intent against the MITRE ATT&CK framework, capturing any malware they try to deploy, and alerting in real time.

WARNING: Run this only on an isolated VM/server you control (VirtualBox, cloud VM, etc.) - never on your personal machine or trusted network. It intentionally accepts fake logins from anyone who connects.

---

## What it does

- Accepts SSH connections and logs every username/password combo tried, then lets the attacker "in"
- Drops them into a fake shell backed by a real in-memory virtual filesystem (ls, cd, cat, pwd all work convincingly)
- Supports extended commands: whoami, uname, ps, ifconfig, netstat, history, touch, mkdir, rm, sudo
- Fakes wget/curl - logs the URL, and actually fetches the file in the background (size-capped, timeout-bounded) to capture real malware samples
- Every captured sample is hashed (SHA256), quarantined read-only, and checked against VirusTotal - never executed
- Classifies every command into an intent category (Reconnaissance, Persistence, Privilege Escalation, etc.) and maps it to a real MITRE ATT&CK tactic/technique ID
- Looks up attacker IPs for geolocation/ISP via a free threat-intel API
- Groups commands into sessions and lets you replay a full attacker session like a terminal recording
- A live Flask dashboard visualizes all of the above with charts
- Sends real-time Telegram alerts for logins, privilege escalation attempts, and downloads
- Fully containerized with Docker Compose - one command to run the whole stack

## Why build this instead of just deploying Cowrie?

Cowrie is a mature, production-grade honeypot - great to run for real threat intel. This project is a smaller, self-built version of the same idea, meant to demonstrate understanding of the SSH protocol, socket programming, SQLite, Flask, Docker, and security concepts (MITRE ATT&CK, malware handling, threat intel) from the ground up.

---

## Screenshots

**Dashboard overview**
![Dashboard 1](screenshots/dashboard-1.png)
![Dashboard 2](screenshots/dashboard-2.png)
![Dashboard 3](screenshots/dashboard-3.png)

**Attacker session in a real terminal**
![SSH session](screenshots/ssh-session.png)

**Session replay**
![Session replay](screenshots/session-replay.png)

**AI mitigation advisor**
![Mitigations 1](screenshots/mitigations-1.png)
![Mitigations 2](screenshots/mitigations-2.png)

**Settings (API key setup)**
![Settings](screenshots/settings.png)
---

## Project status - all milestones complete

- [x] Milestone 1 - Project scaffold
- [x] Milestone 2 - Fake SSH server, logs auth attempts + basic commands
- [x] Milestone 3 - Virtual filesystem + real command interpreter (ls, cd, cat...)
- [x] Milestone 4 - Extended commands + fake file downloads (wget/curl)
- [x] Milestone 5 - Persistent SQLite logging
- [x] Milestone 6 - Flask web dashboard (charts for top IPs/commands/credentials)
- [x] Milestone 7 - Threat intelligence API (IP geolocation/ISP lookups, cached)
- [x] Milestone 8 - Session tracking + terminal-style session replay
- [x] Milestone 9 - Rule-based command intent classifier
- [x] Milestone 10 - MITRE ATT&CK tactic/technique mapping
- [x] Milestone 11 - Real malware capture: SHA256 hashing, read-only quarantine, VirusTotal verdicts
- [x] Milestone 12 - Docker Compose deployment
- [x] Milestone 13 - Real-time Telegram alerts
- [x] Milestone 14 - Multi-user accounts, per-user home directories, expanded commands
- [x] Milestone 15 - DoS/brute-force protection: connection and auth-attempt rate limiting with automatic temporary IP bans
- [x] Milestone 16 - AI mitigation advisor: session findings analyzed by Google Gemini to generate tailored incident summaries and remediation steps (rule-based fallback when no API key is set)
- [x] Milestone 17 - Live AI chat on the mitigations page for asking follow-up questions about a session

---

## Project structure

honeypot-project/
  server.py              Core SSH honeypot (paramiko-based)
  fake_fs.py              In-memory virtual filesystem
  db.py                   SQLite persistence and analytics queries
  analyzer.py              Command intent classifier
  attck_mapping.py          MITRE ATT&CK tactic/technique mapping
  threat_intel.py           IP geolocation/ISP lookups (cached)
  malware_capture.py         Real file capture, hashing, quarantine
  vt_lookup.py               VirusTotal hash-reputation lookups
  telegram_alerts.py          Real-time Telegram notifications
  dashboard.py               Flask web dashboard
  rate_limiter.py             DoS/brute-force connection & auth rate limiting
  mitigation_advisor.py       AI mitigation advisor (Gemini) + session chat
  requirements.txt
  Dockerfile
  docker-compose.yml
  .env                    API keys (VT_API_KEY, TELEGRAM_*) - never committed
  logs/ , keys/ , quarantine/   runtime data - never committed

---

## Setup - running locally (without Docker)

    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

Set your API keys as environment variables:

    export VT_API_KEY="your_virustotal_key"
    export TELEGRAM_BOT_TOKEN="your_bot_token"
    export TELEGRAM_CHAT_ID="your_chat_id"

Run the honeypot:

    python server.py

In a separate terminal, run the dashboard:

    python dashboard.py

Test it:

    ssh -p 2222 anyuser@localhost

View the dashboard at http://localhost:5000

---

## Setup - running with Docker (recommended)

The entire project (honeypot + dashboard) runs as two containers sharing persistent volumes for logs, keys, and quarantined samples.

    echo "VT_API_KEY=your_virustotal_key_here" > .env
    echo "TELEGRAM_BOT_TOKEN=your_bot_token_here" >> .env
    echo "TELEGRAM_CHAT_ID=your_chat_id_here" >> .env

    docker compose build
    docker compose up -d

Test the honeypot:

    ssh -p 2222 anyuser@localhost

View the dashboard at http://localhost:5000

Stop everything:

    docker compose down

### Real-world deployment note

If deploying on a real cloud server, do NOT expose the dashboard (port 5000) directly to the internet - it shows attacker IPs, tried credentials, and captured malware hashes. Instead, access it through an SSH tunnel:

    ssh -L 5000:localhost:5000 youruser@your-server-ip

Then open http://localhost:5000 in your own browser - nothing is exposed publicly.

---

## Getting API keys

- VirusTotal (free): sign up at virustotal.com, grab your API key from your profile
- Telegram bot: message @BotFather, send /newbot, copy the token. Get your chat ID from @userinfobot

---

## Safety notes

- Every fake wget/curl fetch is size-capped (5MB) and timeout-bounded (8s)
- Captured files are renamed to their SHA256 hash, saved read-only, and never executed
- Investigate captured samples via hash reputation (VirusTotal) - never by opening them directly
- API keys are loaded from environment variables / .env, never hardcoded or committed to git

---

## License

This project is for educational and defensive security research purposes.
