"""
Threat Intelligence Lookups - Milestone 7
---------------------------------------------
Looks up geolocation/ISP info for attacker IPs using the free ip-api.com
service (no API key required, generous free tier for non-commercial use).
Results are cached in SQLite so we don't repeatedly hit the API for the
same IP.

Note: private/local IPs (127.0.0.1, 192.168.x.x, 10.x.x.x) won't resolve
to real geolocation data - that's expected during local testing. Once
deployed on a public server, real attacker IPs will return real data.
"""

import sqlite3

import requests

DB_PATH = "logs/honeypot.db"


def init_intel_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_intel (
            ip TEXT PRIMARY KEY,
            country TEXT,
            city TEXT,
            isp TEXT,
            looked_up_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def get_cached(ip):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT country, city, isp FROM ip_intel WHERE ip = ?", (ip,)
    ).fetchone()
    conn.close()
    if row:
        return {"country": row[0], "city": row[1], "isp": row[2]}
    return None


def save_cache(ip, country, city, isp):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO ip_intel (ip, country, city, isp) VALUES (?, ?, ?, ?)",
        (ip, country, city, isp),
    )
    conn.commit()
    conn.close()


def lookup_ip(ip):
    cached = get_cached(ip)
    if cached:
        return cached

    private_prefixes = ("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.")
    if ip.startswith(private_prefixes):
        result = {"country": "Local/Private", "city": "-", "isp": "-"}
        save_cache(ip, result["country"], result["city"], result["isp"])
        return result

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
            }
        else:
            result = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
    except Exception:
        result = {"country": "Lookup failed", "city": "-", "isp": "-"}

    save_cache(ip, result["country"], result["city"], result["isp"])
    return result
