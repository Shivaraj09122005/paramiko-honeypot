"""
AI Mitigation Advisor - Milestone 16 (+ live AI chat)
------------------------------------------------------
Turns everything the honeypot captured about one attacker session -
commands run, ATT&CK categories, malware verdicts, IP - into a
mitigation report.

Two modes:

1. RULE-BASED (no API key set): a curated knowledge base maps ATT&CK
   categories to fixed remediation steps. Deterministic, offline.

2. LLM-ENHANCED (Gemini API key set via the dashboard's Settings page):
   the real session findings (actual commands typed, not just
   categories) are sent to Google's Gemini API, which writes a tailored
   incident summary and mitigation list specific to what that attacker
   actually did.

Once an API key is set, this module also powers a chat endpoint so you
can ask follow-up questions about a specific session from the dashboard.

Uses Gemini's free tier via plain REST calls (the `requests` library,
already a dependency of this project) - no extra SDK needed.

The API key is stored locally in a file next to this script
(.gemini_api_key) - make sure that file is in your .gitignore so you
never commit it.
"""

import os
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

import db
import analyzer
import attck_mapping

try:
    import malware_capture
except ImportError:
    malware_capture = None

try:
    import vt_lookup
except ImportError:
    vt_lookup = None

API_KEY_FILE = Path(__file__).parent / ".gemini_api_key"

GEMINI_MODEL = "gemini-flash-latest"
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"


# --- API key storage --------------------------------------------------

def get_api_key() -> Optional[str]:
    """Local file first, then the GEMINI_API_KEY env var. None if unset."""
    if API_KEY_FILE.exists():
        key = API_KEY_FILE.read_text().strip()
        if key:
            return key
    return os.environ.get("GEMINI_API_KEY")


def save_api_key(key: str):
    API_KEY_FILE.write_text(key.strip())
    try:
        API_KEY_FILE.chmod(0o600)
    except Exception:
        pass  # chmod isn't meaningful on some platforms; not critical


def clear_api_key():
    if API_KEY_FILE.exists():
        API_KEY_FILE.unlink()


def has_api_key() -> bool:
    return bool(get_api_key())


# --- Rule-based fallback knowledge base --------------------------------

MITIGATIONS_BY_CATEGORY = {
    "Reconnaissance": [
        "No action needed on its own - attackers always recon first. "
        "Worth flagging only if this pattern shows up against real "
        "production infrastructure rather than the honeypot.",
    ],
    "Download / Staging": [
        "Block outbound connections to the attacker-supplied URL/domain "
        "at the firewall or egress proxy.",
        "Restrict outbound internet access from servers that don't need it.",
        "Hash any downloaded artifact and check it against VirusTotal "
        "before it is ever executed on a real host.",
    ],
    "Privilege Escalation": [
        "Disable password-based SSH auth; require key-based auth only.",
        "Remove unnecessary sudo/setuid entitlements from service accounts.",
        "Enable auditd/sudo logging so real privilege escalation is caught.",
    ],
    "Persistence": [
        "Audit crontab, systemd units, and ~/.ssh/authorized_keys for "
        "entries you didn't create.",
        "Turn on file-integrity monitoring on authorized_keys, crontab, "
        "and systemd unit directories.",
        "Rotate SSH host/user keys if persistence was actually achieved "
        "on a real host.",
    ],
    "Defense Evasion": [
        "Ship logs off-host in real time (syslog/SIEM forwarding).",
        "Make shell history tamper-evident (auditd exec logging).",
    ],
    "Destruction": [
        "CRITICAL: verify backups are current and stored off-host/immutable.",
        "If this pattern appears against a real host, isolate it from the "
        "network immediately and begin incident response.",
    ],
    "Uncategorized": [
        "Command didn't match a known pattern - review it manually.",
    ],
}

GENERAL_HARDENING = [
    "Use SSH key-based authentication only; disable password auth on any "
    "real host this honeypot is decoying for.",
    "Move real SSH off port 22 and/or front it with a bastion + MFA.",
    "Feed this honeypot's banned-IP and download events into your real "
    "firewall/SIEM blocklist.",
]

_RISK_WEIGHTS = {"Low": 5, "Medium": 15, "High": 25, "Critical": 40}


@dataclass
class MitigationReport:
    session_id: str
    src_ip: str
    risk_score: int
    attck_techniques: list = field(default_factory=list)
    malware_findings: list = field(default_factory=list)
    mitigations: list = field(default_factory=list)
    narrative: Optional[str] = None
    mode: str = "rule-based"


def _collect_session_findings(session_id: str):
    events = db.session_events(session_id)
    categories_seen = {}
    downloads = []
    risk_score = 0
    for event_type, _u, _p, command, tool, url, _ts in events:
        if event_type == "command" and command:
            category, risk = analyzer.classify_and_score(command)
            categories_seen[category] = categories_seen.get(category, 0) + 1
            risk_score += _RISK_WEIGHTS.get(risk, 0)
        elif event_type == "download_attempt" and url:
            downloads.append({"tool": tool, "url": url})
            risk_score += _RISK_WEIGHTS["High"]
    return categories_seen, downloads, risk_score


def _malware_findings_for_session(session_id: str):
    findings = []
    if malware_capture is None:
        return findings
    get_files = (
        getattr(malware_capture, "files_for_session", None)
        or getattr(malware_capture, "get_session_files", None)
    )
    if get_files is None:
        return findings
    try:
        captured_files = get_files(session_id)
    except Exception:
        return findings
    for f in captured_files:
        sha256 = f.get("sha256") if isinstance(f, dict) else getattr(f, "sha256", None)
        verdict = None
        if vt_lookup is not None and sha256:
            vt_check = (
                getattr(vt_lookup, "lookup_hash", None)
                or getattr(vt_lookup, "check_hash", None)
            )
            if vt_check:
                try:
                    verdict = vt_check(sha256)
                except Exception:
                    verdict = None
        findings.append({"sha256": sha256, "verdict": verdict})
    return findings


def _is_malicious_verdict(verdict) -> bool:
    if isinstance(verdict, dict):
        return bool(verdict.get("malicious") or verdict.get("positives") or 0)
    return bool(verdict)


def _build_findings_summary(session_id: str) -> dict:
    """Everything about a session, in one JSON-friendly dict - used both
    for the report generation and for chat context."""
    sessions = {row[0]: row[1] for row in db.recent_sessions(limit=1000)}
    src_ip = sessions.get(session_id, "unknown")

    categories_seen, downloads, risk_score = _collect_session_findings(session_id)
    malware_findings = _malware_findings_for_session(session_id)
    if any(_is_malicious_verdict(f.get("verdict")) for f in malware_findings):
        risk_score += 40
    risk_score = min(risk_score, 100)

    techniques = []
    for category, count in categories_seen.items():
        info = attck_mapping.get_attck_info(category)
        techniques.append({"category": category, "count": count, **info})

    events = db.session_events(session_id)
    commands = [c for (etype, _u, _p, c, _t, _url, _ts) in events if etype == "command" and c]

    return {
        "session_id": session_id,
        "src_ip": src_ip,
        "risk_score": risk_score,
        "attck_techniques": techniques,
        "malware_findings": malware_findings,
        "downloads": downloads,
        "commands": commands,
    }


def generate_report(session_id: str) -> MitigationReport:
    """Main entry point. Uses Gemini if an API key is set, otherwise
    falls back to the rule-based knowledge base automatically."""
    summary = _build_findings_summary(session_id)

    report = MitigationReport(
        session_id=session_id,
        src_ip=summary["src_ip"],
        risk_score=summary["risk_score"],
        attck_techniques=summary["attck_techniques"],
        malware_findings=summary["malware_findings"],
    )

    api_key = get_api_key()
    if api_key:
        try:
            _generate_with_llm(report, summary, api_key)
            return report
        except Exception as e:
            report.narrative = f"(AI analysis failed, showing rule-based fallback instead: {e})"

    _generate_rule_based(report, summary)
    return report


def _generate_rule_based(report: MitigationReport, summary: dict):
    categories_seen = {t["category"]: t["count"] for t in summary["attck_techniques"]}
    mitigations = []
    seen = set()
    for category in categories_seen:
        for step in MITIGATIONS_BY_CATEGORY.get(category, []):
            if step not in seen:
                mitigations.append(step)
                seen.add(step)
    if summary["malware_findings"]:
        step = ("Malicious/unknown files were downloaded in this session - "
                "quarantine them, never execute them, block their hashes "
                "and the source URL/domain.")
        if step not in seen:
            mitigations.append(step)
            seen.add(step)
    for step in GENERAL_HARDENING:
        if step not in seen:
            mitigations.append(step)
            seen.add(step)
    report.mitigations = mitigations
    report.mode = "rule-based"


def _call_gemini(api_key: str, contents: list, system_instruction: str = None, temperature: float = 0.3) -> str:
    """Low-level Gemini REST call. contents is a list of
    {"role": "user"|"model", "parts": [{"text": ...}]} dicts.
    Retries a couple of times on timeout or 503 (server overloaded),
    since the free tier occasionally responds slowly or gets busy."""
    payload = {
        "contents": contents,
        "generationConfig": {"temperature": temperature},
    }
    if system_instruction:
        payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

    last_error = None
    for attempt in range(3):
        try:
            resp = requests.post(
                f"{GEMINI_API_URL}?key={api_key}",
                json=payload,
                timeout=60,
            )
            if resp.status_code == 503:
                last_error = RuntimeError(f"Gemini API error 503: {resp.text[:300]}")
                time.sleep(2 * (attempt + 1))  # 2s, then 4s
                continue
            if resp.status_code != 200:
                raise RuntimeError(f"Gemini API error {resp.status_code}: {resp.text[:300]}")
            data = resp.json()
            try:
                return data["candidates"][0]["content"]["parts"][0]["text"].strip()
            except (KeyError, IndexError):
                raise RuntimeError(f"Unexpected Gemini response shape: {json.dumps(data)[:300]}")
        except requests.exceptions.Timeout as e:
            last_error = e
            continue

    raise RuntimeError(f"Gemini API unavailable after 3 attempts: {last_error}")


def _generate_with_llm(report: MitigationReport, summary: dict, api_key: str):
    prompt = (
        "You are a SOC analyst reviewing one SSH honeypot session. Analyze "
        "the real findings below (actual commands typed, ATT&CK categories, "
        "malware verdicts, risk score) and respond with ONLY a JSON object, "
        "no other text, no markdown fences, in exactly this shape:\n"
        '{"narrative": "<plain-English incident summary, under 200 words>", '
        '"mitigations": ["<specific, concrete mitigation step>", "..."]}\n\n'
        f"Findings:\n{json.dumps(summary, indent=2)}"
    )
    text = _call_gemini(api_key, [{"role": "user", "parts": [{"text": prompt}]}])
    text = text.strip("`")
    if text.lower().startswith("json"):
        text = text[4:].strip()
    parsed = json.loads(text)
    report.narrative = parsed.get("narrative", "")
    report.mitigations = parsed.get("mitigations", [])
    report.mode = "llm-enhanced"


def chat_about_session(session_id: str, message: str, history: list) -> str:
    """
    Powers the chat box on the mitigations page. `history` is a list of
    {"role": "user"|"assistant", "content": str} from earlier turns in
    that browser session (sent by the frontend each time). Requires a
    Gemini API key to be set via the Settings page.
    """
    api_key = get_api_key()
    if not api_key:
        return "No API key set yet. Go to Settings and add your Gemini API key first."

    summary = _build_findings_summary(session_id)
    system_prompt = (
        "You are a SOC analyst assistant helping a defender understand and "
        "respond to one SSH honeypot session. These are the real findings "
        f"for this session:\n{json.dumps(summary, indent=2)}\n\n"
        "Answer the defender's questions about this session, the attacker's "
        "likely intent, and concrete mitigation/hardening steps. Be specific "
        "and concise. Format your answer in markdown: use short paragraphs, "
        "bullet or numbered lists for steps, and code blocks for commands - "
        "never write a long wall-of-text paragraph."
    )

    contents = []
    for h in history:
        role = "model" if h.get("role") == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": h.get("content", "")}]})
    contents.append({"role": "user", "parts": [{"text": message}]})

    try:
        return _call_gemini(api_key, contents, system_instruction=system_prompt, temperature=0.4)
    except Exception as e:
        return f"AI chat failed: {e}"
