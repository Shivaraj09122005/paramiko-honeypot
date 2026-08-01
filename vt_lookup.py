"""
VirusTotal Hash Lookup - Milestone 11 (extension)
------------------------------------------------------
Checks a captured sample's SHA256 hash against VirusTotal's database of
70+ antivirus engines - WITHOUT ever uploading or executing the file
itself. Only the hash is sent, which is enough for VT to tell us if
that exact file has been seen before and what engines think of it.

Requires a free VirusTotal API key, loaded from the VT_API_KEY
environment variable (never hardcoded, never committed to git).
Free tier: ~4 requests/minute, 500/day - plenty for a honeypot project.
"""

import os
import time

import requests

VT_API_KEY = os.environ.get("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/{}"

_last_call_time = 0
_MIN_SECONDS_BETWEEN_CALLS = 16  # keeps us under the 4/minute free tier limit


def lookup_hash(sha256: str) -> dict:
    if not VT_API_KEY:
        return {"verdict": "no_api_key", "malicious": 0, "total": 0}

    global _last_call_time
    elapsed = time.time() - _last_call_time
    if elapsed < _MIN_SECONDS_BETWEEN_CALLS:
        time.sleep(_MIN_SECONDS_BETWEEN_CALLS - elapsed)

    try:
        resp = requests.get(
            VT_URL.format(sha256),
            headers={"x-apikey": VT_API_KEY},
            timeout=10,
        )
        _last_call_time = time.time()

        if resp.status_code == 404:
            return {"verdict": "not_found", "malicious": 0, "total": 0}
        if resp.status_code == 429:
            return {"verdict": "rate_limited", "malicious": 0, "total": 0}
        if resp.status_code != 200:
            return {"verdict": "error", "malicious": 0, "total": 0}

        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        return {"verdict": verdict, "malicious": malicious, "total": total}

    except Exception:
        return {"verdict": "error", "malicious": 0, "total": 0}
