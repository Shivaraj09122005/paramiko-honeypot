"""
Persistent SQLite Logging - Milestone 5
-------------------------------------------
Stores every honeypot event (login attempts, commands, downloads,
privilege escalation attempts) in a local SQLite database so it can be
queried and later visualized in the Milestone 6 dashboard.
"""

import sqlite3
from datetime import datetime, timezone

DB_PATH = "logs/honeypot.db"


def init_db():
    """Create the events table if it doesn't already exist, and migrate
    in the session_id column for older databases that predate it."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            password TEXT,
            command TEXT,
            tool TEXT,
            url TEXT,
            session_id TEXT
        )
    """)
    try:
        conn.execute("ALTER TABLE events ADD COLUMN session_id TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists - fine
    conn.commit()
    conn.close()


def insert_event(event: dict):
    """
    Insert one event dict into the database. Expects the same shape of
    dict already used for the JSONL logs (event, src_ip, session_id,
    plus whichever of username/password/command/tool/url apply).
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute(
        """
        INSERT INTO events (timestamp, src_ip, event_type, username, password, command, tool, url, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            event.get("src_ip"),
            event.get("event"),
            event.get("username"),
            event.get("password"),
            event.get("command"),
            event.get("tool"),
            event.get("url"),
            event.get("session_id"),
        ),
    )
    conn.commit()
    conn.close()


def top_credentials(limit=10):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    rows = conn.execute(
        """
        SELECT username, password, COUNT(*) as attempts
        FROM events
        WHERE event_type = 'login_attempt'
        GROUP BY username, password
        ORDER BY attempts DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def top_commands(limit=10):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    rows = conn.execute(
        """
        SELECT command, COUNT(*) as count
        FROM events
        WHERE event_type = 'command'
        GROUP BY command
        ORDER BY count DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def top_ips(limit=10):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    rows = conn.execute(
        """
        SELECT src_ip, COUNT(*) as events
        FROM events
        GROUP BY src_ip
        ORDER BY events DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def recent_downloads(limit=10):
    """Return the most recent wget/curl download attempts."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    rows = conn.execute(
        """
        SELECT tool, url, timestamp
        FROM events
        WHERE event_type = 'download_attempt'
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def total_event_count():
    """Return the total number of events logged."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
    conn.close()
    return row[0]

def recent_sessions(limit=15):
    """
    Return recent sessions summarized: session_id, src_ip, start time,
    and how many commands were run - for the replay list on the dashboard.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    rows = conn.execute(
        """
        SELECT session_id, src_ip, MIN(timestamp) as started,
               SUM(CASE WHEN event_type = 'command' THEN 1 ELSE 0 END) as commands
        FROM events
        WHERE session_id IS NOT NULL
        GROUP BY session_id
        ORDER BY started DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def session_events(session_id):
    """Return every event for one session, in chronological order."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    rows = conn.execute(
        """
        SELECT event_type, username, password, command, tool, url, timestamp
        FROM events
        WHERE session_id = ?
        ORDER BY id ASC
        """,
        (session_id,),
    ).fetchall()
    conn.close()
    return rows


def all_command_counts():
    """Return every distinct command with how many times it was run -
    used to feed the Milestone 9 intent-category breakdown."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    rows = conn.execute(
        """
        SELECT command, COUNT(*) as count
        FROM events
        WHERE event_type = 'command'
        GROUP BY command
        """
    ).fetchall()
    conn.close()
    return rows

def init_bans_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            banned_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
def ban_ip(ip: str, reason: str, expires_at_iso: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO banned_ips (ip, reason, banned_at, expires_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            reason = excluded.reason, banned_at = excluded.banned_at, expires_at = excluded.expires_at
    """, (ip, reason, datetime.now(timezone.utc).isoformat(), expires_at_iso))
    conn.commit()
    conn.close()
def is_ip_banned(ip: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT expires_at FROM banned_ips WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    if not row:
        return False
    if datetime.now(timezone.utc) >= datetime.fromisoformat(row[0]):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM banned_ips WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        return False
    return True
def active_bans():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT ip, reason, banned_at, expires_at FROM banned_ips ORDER BY banned_at DESC"
    ).fetchall()
    conn.close()
    return rows
