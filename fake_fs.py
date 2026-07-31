"""
Fake Filesystem - Milestone 3
--------------------------------
An in-memory virtual filesystem the fake shell can navigate. Directories
are represented as nested Python dicts; files are represented as plain
strings (their fake contents). This is intentionally simple - no real
disk I/O ever happens, so nothing an attacker does can touch the real
host filesystem.
"""


def build_default_tree():
    """Returns a dict tree resembling a small Debian-ish filesystem."""
    return {
        "etc": {
            "passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "mysql:x:112:117:MySQL Server:/nonexistent:/bin/false\n"
            ),
            "hostname": "prod-web01\n",
            "issue": "Debian GNU/Linux 12 \\n \\l\n",
        },
        "home": {
            "admin": {
                "notes.txt": "TODO: rotate backup keys, patch nginx CVE\n",
                ".bash_history": "ls\ncd /var/www\nvim config.php\n",
            }
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
    ls / cd / cat / pwd / mkdir / touch against the in-memory tree.
    """

    def __init__(self):
        self.tree = build_default_tree()
        self.cwd = ["/"]  # path components; "/" means root

    def _cwd_dict(self):
        """Return the dict node for the current directory."""
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
            self.cwd = ["/"]
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
        """Resolve a path (absolute or relative) to whatever node is there."""
        if path.startswith("/"):
            parts = [p for p in path.split("/") if p]
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
