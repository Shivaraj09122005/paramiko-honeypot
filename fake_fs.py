"""
Fake Filesystem - Milestone 3/4, extended in Milestone 14 for
per-user home directories.
--------------------------------------------------------------
An in-memory virtual filesystem the fake shell can navigate. Directories
are represented as nested Python dicts; files are plain strings. No real
disk I/O ever happens, so nothing an attacker does can touch the real
host filesystem.
"""


def build_default_tree():
    """Returns a dict tree resembling a small Debian-ish multi-user filesystem."""
    return {
        "etc": {
            "passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "mysql:x:112:117:MySQL Server:/nonexistent:/bin/false\n"
                "admin:x:1000:1000:admin:/home/admin:/bin/bash\n"
                "ubuntu:x:1001:1001:ubuntu:/home/ubuntu:/bin/bash\n"
                "backup:x:1002:1002:backup:/home/backup:/bin/bash\n"
                "deploy:x:1003:1003:deploy:/home/deploy:/bin/bash\n"
            ),
            "hostname": "prod-web01\n",
            "issue": "Debian GNU/Linux 12 \\n \\l\n",
        },
        "home": {
            "admin": {
                "notes.txt": "TODO: rotate backup keys, patch nginx CVE\n",
                ".bash_history": "ls\ncd /var/www\nvim config.php\nsudo systemctl restart nginx\n",
            },
            "ubuntu": {
                ".bash_history": "sudo apt update\nsudo apt upgrade -y\nls -la\n",
                ".profile": "# ~/.profile: executed by the command interpreter for login shells.\n",
            },
            "backup": {
                ".bash_history": "tar -czf backup.tar.gz /var/www\nscp backup.tar.gz user@10.0.0.9:/backups/\n",
                "backup.sh": "#!/bin/bash\ntar -czf /tmp/backup.tar.gz /var/www\n",
            },
            "deploy": {
                ".bash_history": "git pull origin main\nsystemctl restart app\n",
                ".ssh": {
                    "authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... deploy@ci-server\n",
                },
            },
        },
        "root": {
            ".bash_history": "apt update\nsystemctl restart nginx\n",
        },
        "var": {
            "www": {
                "html": {
                    "index.php": "<?php echo 'Welcome'; ?>\n",
                }
            },
            "log": {
                "auth.log": "Accepted password for admin from 10.0.0.5\n",
            },
        },
        "tmp": {},
    }


class FakeFilesystem:
    """
    Tracks a fake current working directory and lets the shell run
    ls / cd / cat / pwd / mkdir / touch / rm against the in-memory tree.
    Now home-directory-aware: each session starts in the logged-in
    user's home directory instead of always at "/".
    """

    def __init__(self, home_dir="/"):
        self.tree = build_default_tree()
        self.home_dir = home_dir
        self._ensure_home_exists(home_dir)
        self.cwd = self._path_to_parts(home_dir)

    def _path_to_parts(self, path):
        if path in ("/", ""):
            return ["/"]
        return ["/"] + [p for p in path.split("/") if p]

    def _ensure_home_exists(self, home_dir):
        """
        If an attacker logs in with a username we didn't predefine (e.g.
        'oracle', 'test', 'git'), create an empty home dir on the fly so
        cd/pwd/ls don't break.
        """
        parts = [p for p in home_dir.split("/") if p]
        node = self.tree
        for part in parts:
            if part not in node or not isinstance(node[part], dict):
                node[part] = {}
            node = node[part]

    def _cwd_dict(self):
        node = self.tree
        for part in self.cwd[1:]:
            node = node[part]
        return node

    def pwd(self):
        if len(self.cwd) == 1:
            return "/"
        return "/" + "/".join(self.cwd[1:])

    def ls(self, path=None):
        node = self._resolve_dir(path) if path else self._cwd_dict()
        if node is None:
            return f"ls: cannot access '{path}': No such file or directory"
        if not isinstance(node, dict):
            return path or ""
        names = sorted(node.keys())
        return "  ".join(names) if names else ""

    def cd(self, path):
        if not path or path == "~":
            self.cwd = self._path_to_parts(self.home_dir)
            return None
        if path == "..":
            if len(self.cwd) > 1:
                self.cwd.pop()
            return None
        if path == "/":
            self.cwd = ["/"]
            return None

        target = self._resolve_dir(path)
        if target is None:
            return f"bash: cd: {path}: No such file or directory"
        if not isinstance(target, dict):
            return f"bash: cd: {path}: Not a directory"

        if path.startswith("/"):
            self.cwd = ["/"] + [p for p in path.split("/") if p]
        elif path.startswith("~"):
            self.cwd = self._path_to_parts(self.home_dir + path[1:])
        else:
            self.cwd = self.cwd + [p for p in path.split("/") if p]
        return None

    def cat(self, path):
        node = self._resolve_node(path)
        if node is None:
            return f"cat: {path}: No such file or directory"
        if isinstance(node, dict):
            return f"cat: {path}: Is a directory"
        return node.rstrip("\n")

    def _resolve_node(self, path):
        if path.startswith("/"):
            parts = [p for p in path.split("/") if p]
            node = self.tree
        elif path.startswith("~"):
            full = self.home_dir + path[1:]
            parts = [p for p in full.split("/") if p]
            node = self.tree
        else:
            parts = [p for p in path.split("/") if p]
            node = self._cwd_dict()

        for part in parts:
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def _resolve_dir(self, path):
        node = self._resolve_node(path)
        return node if isinstance(node, dict) else None

    def add_file(self, name, content):
        self._cwd_dict()[name] = content

    def mkdir(self, name):
        cwd = self._cwd_dict()
        if name in cwd:
            return f"mkdir: cannot create directory '{name}': File exists"
        cwd[name] = {}
        return None

    def rm(self, name):
        cwd = self._cwd_dict()
        if name not in cwd:
            return f"rm: cannot remove '{name}': No such file or directory"
        del cwd[name]
        return None
