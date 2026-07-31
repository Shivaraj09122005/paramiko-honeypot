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
    conn = sqlite3.connect(DB_PATH)
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
            url TEXT
        )
    """)
    conn.commit()
    conn.close()


def insert_event(event: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO events (timestamp, src_ip, event_type, username, password, command, tool, url)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
        ),
    )
    conn.commit()
    conn.close()


def top_credentials(limit=10):
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
    conn.close()
    return row[0]
