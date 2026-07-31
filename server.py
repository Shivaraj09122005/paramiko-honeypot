"""
Fake SSH Honeypot Server - Milestone 4
----------------------------------------
Accepts SSH connections on a chosen port, logs every username/password
attempt (and the connecting IP), then "succeeds" and drops the attacker
into a fake shell backed by a real virtual filesystem, extended commands,
and fake wget/curl download capture (URL logging only - never touches the
real network).
"""

import json
import logging
import os
import socket
import threading
from datetime import datetime, timezone

import paramiko
import db
from fake_fs import FakeFilesystem

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
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def run_command(command, fs: FakeFilesystem, client_ip):
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
            "  PID TTY          TIME CMD\n"
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
            "Proto Recv-Q Send-Q Local Address       Foreign Address     State\n"
            "tcp        0      0 0.0.0.0:2222        0.0.0.0:*           LISTEN\n"
            "tcp        0      0 0.0.0.0:22222       0.0.0.0:*           LISTEN"
        )

    if cmd == "sudo":
        log.warning("Privilege escalation attempt from %s: %r", client_ip, command)
        log_event({
            "event": "privilege_escalation_attempt",
            "src_ip": client_ip,
            "command": command,
        })
        return "root@prod-web01:~# " if not args else run_command(" ".join(args), fs, client_ip)

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

    fs.add_file(filename, f"[fake honeypot placeholder - attacker tried to fetch {url}]\n")

    if tool == "wget":
        return (
            "--2026-07-31 12:00:00--  " + url + "\n"
            "Resolving host... connected.\n"
            "HTTP request sent, awaiting response... 200 OK\n"
            f"Saving to: '{filename}'\n\n"
            f"{filename}           100%[===================>]  saved\n"
        )
    else:
        return f"  % Total    % Received % Xferd   Average Speed\n100  1024  100  1024    0     0   saved to {filename}"


def handle_shell(channel, client_ip):
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

                output = run_command(command, fs, client_ip)
                if output is None:
                    channel.send(b"logout\r\n")
                    channel.close()
                    return

                if output:
                    channel.send(output.replace("\n", "\r\n").encode() + b"\r\n")
                channel.send(prompt_bytes())
                buffer = b""
            elif b in (b"\x7f", b"\x08"):
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
    db.init_db()

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
