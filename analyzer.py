"""
Command Intent Analyzer - Milestone 9
------------------------------------------
Classifies captured attacker commands into intent categories, loosely
inspired by MITRE ATT&CK tactic groupings (formalized further in
Milestone 10). This starts as a fast, offline, rule-based classifier -
no API key or network call required - which is how real detection
engines are often built before layering an LLM on top for harder,
free-form cases. A natural extension: swap classify_command's fallback
with a call to an LLM API for commands that don't match any rule.
"""

CATEGORY_RULES = [
    ("Reconnaissance", ["whoami", "uname", "id", "hostname", "ps", "ifconfig",
                         "netstat", "ls", "pwd", "history", "cat /etc/passwd", "ip a"]),
    ("Download / Staging", ["wget", "curl"]),
    ("Privilege Escalation", ["sudo", "su ", "chmod +s", "passwd"]),
    ("Persistence", ["crontab", "systemctl", ".bashrc", "authorized_keys", "useradd"]),
    ("Defense Evasion", ["history -c", "unset histfile", "clear", "rm -f /var/log"]),
    ("Destruction", ["rm -rf", "dd if=", "mkfs", ":(){:|:&};:"]),
]

RISK_BY_CATEGORY = {
    "Reconnaissance": "Low",
    "Download / Staging": "High",
    "Privilege Escalation": "High",
    "Persistence": "High",
    "Defense Evasion": "Medium",
    "Destruction": "Critical",
    "Uncategorized": "Low",
}


import re


def classify_command(command: str) -> str:
    """Return the best-matching intent category for a command string,
    using whole-word matching so keywords like 'ps' don't falsely match
    inside unrelated substrings like 'https'."""
    if not command:
        return "Uncategorized"
    lowered = command.lower()
    for category, keywords in CATEGORY_RULES:
        for kw in keywords:
            pattern = r"\b" + re.escape(kw) + r"\b"
            if re.search(pattern, lowered):
                return category
    return "Uncategorized"


def risk_level(category: str) -> str:
    return RISK_BY_CATEGORY.get(category, "Low")


def classify_and_score(command: str):
    """Convenience helper: returns (category, risk_level) together."""
    category = classify_command(command)
    return category, risk_level(category)
