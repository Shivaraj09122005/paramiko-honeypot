"""
Telegram Real-Time Alerts - Milestone 13
---------------------------------------------
Sends a message to a Telegram chat whenever a notable honeypot event
happens (login attempt, download/malware capture, privilege escalation
attempt). Uses Telegram's free Bot API.

Requires two environment variables (never hardcoded, never committed):
  TELEGRAM_BOT_TOKEN - from @BotFather when you create a bot
  TELEGRAM_CHAT_ID   - the chat/user ID the bot should message
"""

import os

import requests

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
API_URL = "https://api.telegram.org/bot{}/sendMessage"


def send_alert(message: str):
    print("DEBUG: send_alert called:", message)
    print("DEBUG: BOT_TOKEN set?", bool(BOT_TOKEN), "CHAT_ID set?", bool(CHAT_ID))
    if not BOT_TOKEN or not CHAT_ID:
        print("DEBUG: missing token/chat_id, skipping")
        return
    try:
        r = requests.post(
            API_URL.format(BOT_TOKEN),
            data={"chat_id": CHAT_ID, "text": message},
            timeout=5,
        )
        print("DEBUG: telegram response status:", r.status_code)
        print("DEBUG: telegram response body:", r.text)
    except Exception as e:
        print("DEBUG: telegram exception:", repr(e))


def alert_login(src_ip, username, password):
    send_alert(f"🍯 Honeypot login attempt\nIP: {src_ip}\nUser: {username}\nPass: {password}")


def alert_download(src_ip, tool, url):
    send_alert(f"⬇️ Honeypot download attempt\nIP: {src_ip}\nTool: {tool}\nURL: {url}")


def alert_privilege_escalation(src_ip, command):
    send_alert(
        f"⚠️ Honeypot privilege escalation attempt\n"
        f"IP: {src_ip}\n"
        f"Command: {command}"
    )


def alert_command(src_ip, username, command):
    send_alert(
        f"💻 Honeypot command executed\n"
        f"IP: {src_ip}\n"
        f"User: {username}\n"
        f"Command: {command}"
    )
