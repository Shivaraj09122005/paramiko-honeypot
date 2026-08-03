"""
Fake user accounts - Milestone 14 (multi-user realism)
--------------------------------------------------------
Maps a username to a fake Linux identity (uid/gid/home/shell) so the
honeypot feels like a real multi-user box instead of always dropping
everyone into root. Any password is still accepted for any username
(we want to capture whatever credentials attackers try) - only the
*identity* differs based on username.
"""

FAKE_USERS = {
    "root":   {"uid": 0,    "gid": 0,    "home": "/root",        "sudoer": True},
    "admin":  {"uid": 1000, "gid": 1000, "home": "/home/admin",  "sudoer": True},
    "ubuntu": {"uid": 1001, "gid": 1001, "home": "/home/ubuntu", "sudoer": True},
    "backup": {"uid": 1002, "gid": 1002, "home": "/home/backup", "sudoer": False},
    "deploy": {"uid": 1003, "gid": 1003, "home": "/home/deploy", "sudoer": False},
}


def get_user_identity(username: str) -> dict:
    """
    Returns the fake identity for a username. Unknown usernames (which
    real attackers constantly try - 'oracle', 'postgres', 'test', etc.)
    still get a believable non-root, non-sudoer identity rather than
    falling back to root.
    """
    if username in FAKE_USERS:
        return FAKE_USERS[username]
    return {
        "uid": 1000,
        "gid": 1000,
        "home": f"/home/{username}",
        "sudoer": False,
    }
