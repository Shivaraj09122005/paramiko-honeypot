# Fake SSH Honeypot (Python)

A from-scratch SSH honeypot built with `paramiko`, inspired by the design ideas
behind [Cowrie](https://github.com/cowrie/cowrie). It logs every login attempt
(username/password/IP) and every command an attacker types, and will grow into
a full fake shell with a virtual filesystem and a web analytics dashboard.

> ⚠️ **Run this only on an isolated VM/server you control** — never on your
> personal machine or trusted network. It intentionally accepts fake logins
> from anyone who connects.

## Status

- [x] Milestone 1 — Project scaffold
- [x] Milestone 2 — Fake SSH server, logs auth attempts + basic commands
- [x] Milestone 3 — Virtual filesystem + real command interpreter (`ls`, `cd`, `cat`...)
- [x] Milestone 4 — Extended commands + fake file downloads (`wget`/`curl`)
- [x] Milestone 5 — Persistent SQLite logging
- [x] Milestone 6 — Flask web dashboard (charts for top IPs/commands/credentials)
- [x] Milestone 7 — Threat intelligence API (IP reputation/geolocation lookups)
- [x] Milestone 8 — Session replay (playback of full attacker sessions)
- [x] Milestone 9 — AI command analyzer (LLM-based intent classification)
- [x] Milestone 10 — MITRE ATT&CK technique mapping
- [ ] Milestone 11 — Malware capture (hash + metadata only, never executed)
- [ ] Milestone 12 — Docker deployment
- [ ] Milestone 13 — Telegram real-time alerts

## Architecture

Attacker connects over SSH → `paramiko`-based server accepts any credentials
while logging them → attacker dropped into a fake shell → every command is
logged to `logs/sessions.jsonl` (structured, one JSON object per line).

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python server.py
```

The server listens on port `2222` by default. Test it from another terminal:

```bash
ssh -p 2222 root@localhost
```

Any username/password will be "accepted." Watch `logs/sessions.jsonl` fill up
with structured events, and check the server's console output.

## Why build this instead of just deploying Cowrie?

Cowrie is a mature, production-grade honeypot — great to run for real threat
intel. This project is a smaller, self-built version of the same idea, meant
to demonstrate understanding of the SSH protocol, socket programming, and
security logging from the ground up.

## Roadmap / Next steps

See the Status checklist above — each milestone will be its own commit.

## Running the dashboard

In a separate terminal, with the honeypot already running:

    python dashboard.py

Visit http://localhost:5000 (or your VM's IP) to see live charts of
top attacker IPs, top commands run, credentials tried, and recent
download attempts.
