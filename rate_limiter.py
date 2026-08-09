"""
DoS / Brute-Force Protection - Milestone 15
------------------------------------------------
Lightweight, in-memory + SQLite-backed rate limiter that protects the
honeypot itself from being knocked over by scanners and automated
attack tools that open hundreds of connections per second.
"""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import db

CONNECTION_WINDOW_SECONDS = 10
CONNECTION_MAX_IN_WINDOW = 8

AUTH_WINDOW_SECONDS = 30
AUTH_MAX_IN_WINDOW = 15

BAN_DURATION_SECONDS = 15 * 60

_connection_times = defaultdict(deque)
_auth_times = defaultdict(deque)
_lock = threading.Lock()


def init():
    db.init_bans_table()


def _prune(dq: deque, window_seconds: int, now: float):
    while dq and now - dq[0] > window_seconds:
        dq.popleft()


def _ban(ip: str, reason: str):
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=BAN_DURATION_SECONDS)
    db.ban_ip(ip, reason, expires_at.isoformat())
    db.insert_event({
        "event": "ip_banned",
        "src_ip": ip,
        "command": reason,
    })


def is_banned(ip: str) -> bool:
    return db.is_ip_banned(ip)


def check_connection(ip: str) -> bool:
    if is_banned(ip):
        return False

    now = time.time()
    with _lock:
        dq = _connection_times[ip]
        _prune(dq, CONNECTION_WINDOW_SECONDS, now)
        dq.append(now)
        count = len(dq)

    if count > CONNECTION_MAX_IN_WINDOW:
        _ban(ip, f"connection_flood: {count} connections in {CONNECTION_WINDOW_SECONDS}s")
        return False
    return True


def check_auth_attempt(ip: str) -> bool:
    if is_banned(ip):
        return False

    now = time.time()
    with _lock:
        dq = _auth_times[ip]
        _prune(dq, AUTH_WINDOW_SECONDS, now)
        dq.append(now)
        count = len(dq)

    if count > AUTH_MAX_IN_WINDOW:
        _ban(ip, f"auth_flood: {count} auth attempts in {AUTH_WINDOW_SECONDS}s")
        return False
    return True
