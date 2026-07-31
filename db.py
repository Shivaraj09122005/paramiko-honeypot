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
    conn = sqlite3.connect(DB_PATH)
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

def recent_sessions(limit=15):
    """
    Return recent sessions summarized: session_id, src_ip, start time,
    and how many commands were run - for the replay list on the dashboard.
    """
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
