"""
Fake SSH Honeypot Server - Milestone 3
----------------------------------------
Accepts SSH connections on a chosen port, logs every username/password
attempt (and the connecting IP), then "succeeds" and drops the attacker
into a fake shell backed by a real virtual filesystem so their session
can be recorded and interactively explored.

This is educational / defensive security tooling. Only ever run this on
a machine you control, isolated from anything sensitive.
"""

import json
import logging
import os
import socket
import threading
from datetime import datetime, timezone

import paramiko

from fake_fs import FakeFilesystem

HOST = "0.0.0.0"
PORT = 2222                      # non-privileged port; use iptables/authbind to map 22 -> 2222 later
HOST_KEY_PATH = "keys/server_key"
LOG_PATH = "logs/sessions.jsonl"  # one JSON object per line = one event

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("honeypot")


def ensure_host_key():
    """Generate an RSA host key once, on first run, if one doesn't exist yet."""
    if not os.path.exists(HOST_KEY_PATH):
        os.makedirs(os.path.dirname(HOST_KEY_PATH), exist_ok=True)
        log.info("No host key found, generating a new one at %s", HOST_KEY_PATH)
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_PATH)
    return paramiko.RSAKey(filename=HOST_KEY_PATH)


def log_event(event: dict):
    """Append one structured event to the JSONL log file."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")


class HoneypotServer(paramiko.ServerInterface):
    """
    Implements paramiko's server-side callbacks. The key trick for a
    honeypot: check_auth_password ALWAYS returns success, after logging
    whatever credentials were tried, so we capture as many attempts and
    follow-on shell sessions as possible.
    """

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log.info("Login attempt from %s -> user=%r pass=%r", self.client_ip, username, password)
        log_event({
            "event": "login_attempt",
            "src_ip": self.client_ip,
            "username": username,
            "password": password,
        })
        return paramiko.AUTH_SUCCESSFUL  # always let them "in"

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def run_command(command, fs: FakeFilesystem):
    """
    Interpret one command line against the fake filesystem and return the
    text output to send back to the attacker (may be empty string).
    Returns None to signal the session should end (exit/logout).
    """
    if not command:
        return ""

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
        return "root"

    if cmd == "uname":
        if "-a" in args:
            return "Linux prod-web01 6.1.0-21-amd64 #1 SMP Debian x86_64 GNU/Linux"
        return "Linux"

    if cmd == "id":
        return "uid=0(root) gid=0(root) groups=0(root)"

    if cmd == "hostname":
        return "prod-web01"

    if cmd == "echo":
        return " ".join(args)

    if cmd == "clear":
        return "\x1b[2J\x1b[H"

    return f"bash: {cmd}: command not found"


def handle_shell(channel, client_ip):
    """
    Fake shell backed by a real virtual filesystem (Milestone 3). Supports
    ls, cd, cat, pwd, whoami, uname, id, hostname, echo alongside login/
    command logging.
    """
    fs = FakeFilesystem()

    def prompt_bytes():
        cwd = fs.pwd()
        short = "~" if cwd == "/root" else cwd
        return f"root@prod-web01:{short}# ".encode()

    channel.send(b"Last login: Tue Jul 29 09:14:02 2026 from 10.0.0.4\r\n")
    channel.send(prompt_bytes())

    buffer = b""
    while True:
        try:
            data = channel.recv(1024)
        except Exception:
            break
        if not data:
            break

        # handle backspace / enter minimally so it feels like a real terminal
        for byte in data:
            b = bytes([byte])
            if b in (b"\r", b"\n"):
                command = buffer.decode(errors="ignore").strip()
                channel.send(b"\r\n")
                if command:
                    log.info("Command from %s: %r", client_ip, command)
                    log_event({
                        "event": "command",
                        "src_ip": client_ip,
                        "command": command,
                    })

                output = run_command(command, fs)
                if output is None:  # exit / logout
                    channel.send(b"logout\r\n")
                    channel.close()
                    return

                if output:
                    channel.send(output.replace("\n", "\r\n").encode() + b"\r\n")
                channel.send(prompt_bytes())
                buffer = b""
            elif b in (b"\x7f", b"\x08"):  # backspace
                buffer = buffer[:-1]
                channel.send(b"\x08 \x08")
            else:
                buffer += b
                channel.send(b)


def handle_connection(client_socket, client_ip):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(ensure_host_key())
    server = HoneypotServer(client_ip)

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
        handle_shell(channel, client_ip)
    finally:
        transport.close()


def main():
    ensure_host_key()
    os.makedirs("logs", exist_ok=True)

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
