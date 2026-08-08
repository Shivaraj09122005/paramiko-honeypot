"""
Fake SSH Honeypot Server - Milestone 4
----------------------------------------
Accepts SSH connections on a chosen port, logs every username/password
attempt (and the connecting IP), then "succeeds" and drops the attacker
into a fake shell backed by a real virtual filesystem, extended commands,
and fake wget/curl download capture (URL logging always; optional real
capture + hashing + VirusTotal check via malware_capture.py - see there).
"""

import json
import logging
import os
import socket
import threading
import uuid
from datetime import datetime, timezone

import paramiko

import db
import malware_capture
import telegram_alerts
from fake_fs import FakeFilesystem
from users import get_user_identity

HOST = "0.0.0.0"
PORT = 2222
HOST_KEY_PATH = "keys/server_key"
LOG_PATH = "logs/sessions.jsonl"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("honeypot")


def ensure_host_key():
    if not os.path.exists(HOST_KEY_PATH):
        os.makedirs(os.path.dirname(HOST_KEY_PATH), exist_ok=True)
        log.info("No host key found, generating a new one at %s", HOST_KEY_PATH)
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_PATH)
    return paramiko.RSAKey(filename=HOST_KEY_PATH)


def log_event(event: dict):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")
    db.insert_event(event)


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip, session_id):
        self.client_ip = client_ip
        self.session_id = session_id
        self.event = threading.Event()
        self.username = None
        self.identity = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log.info("Login attempt from %s -> user=%r pass=%r", self.client_ip, username, password)
        self.username = username
        self.identity = get_user_identity(username)
        log_event({
            "event": "login_attempt",
            "src_ip": self.client_ip,
            "session_id": self.session_id,
            "username": username,
            "password": password,
        })
        telegram_alerts.alert_login(self.client_ip, username, password)
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def run_command(command, fs: FakeFilesystem, client_ip, username="root", identity=None):
    if not command:
        return ""

    if identity is None:
        identity = {"uid": 0, "gid": 0, "home": "/root", "sudoer": True}

    parts = command.split()
    cmd = parts[0]
    args = parts[1:]

    if cmd in ("exit", "logout"):
        return None
    if cmd == "pwd":
        return fs.pwd()
    if cmd == "ls":
        target = args[0] if args else None
        return fs.ls(target)
    if cmd == "cd":
        target = args[0] if args else None
        error = fs.cd(target)
        return error or ""
    if cmd == "cat":
        if not args:
            return "cat: missing operand"
        return fs.cat(args[0])
    if cmd == "whoami":
        return username
    if cmd == "uname":
        if "-a" in args:
            return "Linux prod-web01 6.1.0-21-amd64 #1 SMP Debian x86_64 GNU/Linux"
        return "Linux"
    if cmd == "id":
        uid, gid = identity["uid"], identity["gid"]
        return f"uid={uid}({username}) gid={gid}({username}) groups={gid}({username})"
    
    if cmd == "hostname":
        return "prod-web01"
    if cmd == "echo":
        return " ".join(args)
    if cmd == "clear":
        return "\x1b[2J\x1b[H"
    if cmd in ("wget", "curl"):
        return handle_download(cmd, args, fs, client_ip)
    if cmd == "touch":
        if not args:
            return "touch: missing file operand"
        fs.add_file(args[0], "")
        return ""
    if cmd == "mkdir":
        if not args:
            return "mkdir: missing operand"
        error = fs.mkdir(args[0])
        return error or ""
    if cmd == "rm":
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            return "rm: missing operand"
        error = fs.rm(targets[0])
        return error or ""
    if cmd == "which":
        if not args:
            return ""
        return f"/usr/bin/{args[0]}"
    if cmd == "history":
        return fs.cat(".bash_history")
    if cmd == "ps":
        return (
            "  PID TTY      TIME CMD\n"
            "    1 ?        00:00:02 systemd\n"
            "  842 ?        00:00:00 sshd\n"
            " 1193 pts/0    00:00:00 bash\n"
            " 1240 pts/0    00:00:00 ps"
        )
    if cmd in ("ifconfig", "ip"):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255\n"
            "        ether 02:42:ac:11:00:05  txqueuelen 0  (Ethernet)"
        )
    if cmd == "netstat":
        return (
            "Active Internet connections\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:22222           0.0.0.0:*               LISTEN"
        )
    if cmd == "sudo":
        log.warning("Privilege escalation attempt from %s: %r", client_ip, command)
        log_event({
            "event": "privilege_escalation_attempt",
            "src_ip": client_ip,
            "username": username,
            "command": command,
        })
        telegram_alerts.alert_privilege_escalation(client_ip, command)
        if not identity.get("sudoer", False):
            return f"{username} is not in the sudoers file.  This incident will be reported."
        return "" if not args else run_command(" ".join(args), fs, client_ip, "root", {"uid": 0, "gid": 0, "home": "/root", "sudoer": True})

    return f"bash: {cmd}: command not found"
    if cmd == "hostname":
        return "prod-web01"
    if cmd == "echo":
        return " ".join(args)
    if cmd == "clear":
        return "\x1b[2J\x1b[H"
    if cmd in ("wget", "curl"):
        return handle_download(cmd, args, fs, client_ip)
    if cmd == "touch":
        if not args:
            return "touch: missing file operand"
        fs.add_file(args[0], "")
        return ""
    if cmd == "mkdir":
        if not args:
            return "mkdir: missing operand"
        error = fs.mkdir(args[0])
        return error or ""
    if cmd == "rm":
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            return "rm: missing operand"
        error = fs.rm(targets[0])
        return error or ""
    if cmd == "which":
        if not args:
            return ""
        return f"/usr/bin/{args[0]}"
    if cmd == "history":
        return fs.cat(".bash_history")
    if cmd == "ps":
        return (
            "  PID TTY      TIME CMD\n"
            "    1 ?        00:00:02 systemd\n"
            "  842 ?        00:00:00 sshd\n"
            " 1193 pts/0    00:00:00 bash\n"
            " 1240 pts/0    00:00:00 ps"
        )
    if cmd in ("ifconfig", "ip"):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255\n"
            "        ether 02:42:ac:11:00:05  txqueuelen 0  (Ethernet)"
        )
    if cmd == "netstat":
        return (
            "Active Internet connections\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:22222           0.0.0.0:*               LISTEN"
        )
    if cmd == "chmod":
        return ""
    if cmd == "chown":
        return ""
    if cmd == "passwd":
        return f"Changing password for {username}.\nCurrent password: "
    if cmd in ("useradd", "adduser"):
        if not args:
            return f"usage: {cmd} username"
        return ""
    if cmd == "userdel":
        return ""
    if cmd == "crontab":
        if "-l" in args:
            return "no crontab for " + username
        return ""
    if cmd == "find":
        return ""
    if cmd == "grep":
        return ""
    if cmd == "df":
        return (
            "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
            "/dev/sda1       20510780 8443212  11015200  44% /\n"
            "tmpfs             999999       0    999999   0% /dev/shm"
        )
    if cmd == "du":
        return "4.0K\t."
    if cmd == "free":
        return (
            "              total        used        free      shared\n"
            "Mem:        2048576      612344     1101234       12456\n"
            "Swap:       1048572           0     1048572"
        )
    if cmd == "top" or cmd == "htop":
        return (
            "top - 19:40:12 up 3 days,  2:14,  1 user,  load average: 0.08, 0.05, 0.01\n"
            "Tasks:  98 total,   1 running,  97 sleeping\n"
            "%Cpu(s):  1.3 us,  0.7 sy,  0.0 ni, 97.9 id\n"
            "MiB Mem :   2001.0 total,   1075.4 free,    598.0 used,    327.6 buff/cache"
        )
    if cmd == "env" or cmd == "export":
        return f"HOME=/{identity['home']}\nUSER={username}\nSHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
    if cmd in ("service", "systemctl"):
        return "nginx.service - active (running)"
    if cmd in ("nano", "vim", "vi"):
        return ""
    if cmd == "ssh":
        return "ssh: connect to host: Connection refused"
    if cmd == "scp":
        return "scp: connect to host: Connection refused"
    if cmd == "nmap":
        return "Starting Nmap...\nHost seems down. Try -Pn."
    if cmd == "nc" or cmd == "ncat" or cmd == "netcat":
        return ""
    if cmd == "apt" or cmd == "apt-get":
        return "Reading package lists... Done\nAll packages are up to date."
    if cmd == "dpkg":
        return ""
    if cmd == "uptime":
        return "19:40:12 up 3 days,  2:14,  1 user,  load average: 0.08, 0.05, 0.01"
    if cmd == "date":
        return "Sat Aug  1 19:40:12 UTC 2026"
    if cmd == "w" or cmd == "who":
        return f"{username}     pts/0        10.0.0.4         19:40"
    if cmd == "last":
        return f"{username}     pts/0        10.0.0.4    Sat Aug  1 19:40   still logged in"
    if cmd == "groups":
        return username
    if cmd == "man":
        return "" if not args else f"No manual entry for {args[0]}"
    if cmd == "lscpu":
        return "Architecture:        x86_64\nCPU(s):              4\nModel name:          Intel(R) Xeon(R) CPU"

    return f"bash: {cmd}: command not found"

def handle_download(tool, args, fs: FakeFilesystem, client_ip):
    urls = [a for a in args if a.startswith("http://") or a.startswith("https://")]
    if not urls:
        return f"{tool}: missing URL"

    url = urls[0]
    filename = url.rstrip("/").split("/")[-1] or "index.html"

    log.warning("Download attempt from %s via %s: %s", client_ip, tool, url)
    log_event({
        "event": "download_attempt",
        "src_ip": client_ip,
        "tool": tool,
        "url": url,
    })
    telegram_alerts.alert_download(client_ip, tool, url)

    # Milestone 11: real capture, hashed + quarantined, never executed
    # (see malware_capture.py for the safety rules). Runs in a background
    # thread so a slow/hanging URL never blocks the attacker's fake shell.
    threading.Thread(
        target=malware_capture.capture,
        args=(url, tool, client_ip),
        daemon=True,
    ).start()

    fs.add_file(filename, f"[fake honeypot placeholder - attacker tried to fetch {url}]\n")

    if tool == "wget":
        return (
            "--2026-07-31 12:00:00--  " + url + "\n"
            "Resolving host... connected.\n"
            "HTTP request sent, awaiting response... 200 OK\n"
            f"Saving to: '{filename}'\n\n"
            f"{filename}       100%[===================>]  saved\n"
        )
    else:
        return f"  % Total    % Received % Xferd  Average Speed\n100  1024  100  1024    0     0  saved to {filename}"


# Commands that real attackers use to try to pop a root shell after
# logging in as an unprivileged user. Any of these trigger the fake
# "[sudo] password for ...:" prompt below, instead of the old inline
# sudoer-only elevation.
SUDO_SHELL_ESCALATIONS = {"sudo su", "sudo su -", "sudo -i", "sudo -s"}


def handle_shell(channel, client_ip, session_id, username, identity):
    fs = FakeFilesystem(home_dir=identity["home"])

    # Mutable per-session identity so a successful "sudo su" can promote
    # the rest of the session to root without opening a new connection.
    state = {"username": username, "identity": identity}

    def prompt_char():
        return "#" if state["identity"]["uid"] == 0 else "$"

    def prompt_bytes():
        cwd = fs.pwd()
        short = "~" if cwd == state["identity"]["home"] else cwd
        return f"{state['username']}@prod-web01:{short}{prompt_char()} ".encode()

    channel.send(b"Last login: Tue Jul 29 09:14:02 2026 from 10.0.0.4\r\n")
    channel.send(prompt_bytes())

    buffer = b""
    awaiting_sudo_password = False

    while True:
        try:
            data = channel.recv(1024)
        except Exception:
            break
        if not data:
            break

        for byte in data:
            b = bytes([byte])

            if b in (b"\r", b"\n"):
                line = buffer.decode(errors="ignore").strip()
                buffer = b""
                channel.send(b"\r\n")

                if awaiting_sudo_password:
                    awaiting_sudo_password = False

                    # We don't actually check the password - the honeypot's
                    # whole job is to capture it and keep the attacker
                    # engaged, so any input here "succeeds".
                    log.warning(
                        "Sudo password captured from %s (user=%s): %r",
                        client_ip, state["username"], line,
                    )
                    log_event({
                        "event": "sudo_password_captured",
                        "src_ip": client_ip,
                        "session_id": session_id,
                        "username": state["username"],
                        "password": line,
                    })
                    telegram_alerts.alert_privilege_escalation(
                        client_ip, f"sudo su (password entered: {line!r})"
                    )

                    state["identity"] = {"uid": 0, "gid": 0, "home": "/root", "sudoer": True}
                    state["username"] = "root"
                    fs.home_dir = "/root"
                    fs.cd("/root")

                    channel.send(prompt_bytes())
                    continue

                command = line
                if not command:
                    channel.send(prompt_bytes())
                    continue

                log.info("Command from %s: %r", client_ip, command)
                log_event({
                    "event": "command",
                    "src_ip": client_ip,
                    "session_id": session_id,
                    "command": command,
                })
                telegram_alerts.alert_command(client_ip, state["username"], command)

                if command in SUDO_SHELL_ESCALATIONS:
                    log.warning("Privilege escalation attempt from %s: %r", client_ip, command)
                    log_event({
                        "event": "privilege_escalation_attempt",
                        "src_ip": client_ip,
                        "username": state["username"],
                        "command": command,
                    })
                    channel.send(f"[sudo] password for {state['username']}: ".encode())
                    awaiting_sudo_password = True
                    continue

                output = run_command(command, fs, client_ip, state["username"], state["identity"])
                if output is None:
                    channel.send(b"logout\r\n")
                    channel.close()
                    return
                if output:
                    channel.send(output.replace("\n", "\r\n").encode() + b"\r\n")
                channel.send(prompt_bytes())

            elif b in (b"\x7f", b"\x08"):
                if buffer:
                    buffer = buffer[:-1]
                if not awaiting_sudo_password:
                    channel.send(b"\x08 \x08")
            else:
                buffer += b
                if not awaiting_sudo_password:
                    channel.send(b)


def handle_connection(client_socket, client_ip):
    session_id = str(uuid.uuid4())[:8]  # short id groups all events from this connection
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(ensure_host_key())

    server = HoneypotServer(client_ip, session_id)
    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        log.warning("SSH negotiation failed with %s", client_ip)
        return

    channel = transport.accept(20)
    if channel is None:
        return

    server.event.wait(10)

    try:
        handle_shell(channel, client_ip, session_id, server.username, server.identity)
    finally:
        transport.close()


def main():
    ensure_host_key()
    os.makedirs("logs", exist_ok=True)
    db.init_db()
    malware_capture.init_samples_table()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)
    log.info("Honeypot listening on %s:%s", HOST, PORT)

    while True:
        client_socket, addr = sock.accept()
        client_ip = addr[0]
        log.info("Connection from %s", client_ip)
        t = threading.Thread(target=handle_connection, args=(client_socket, client_ip), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
