"""Map SSH host keys (from session-bind / hostbound auth) to host names."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from .wire import fingerprint

# Published host keys (api.github.com/meta, docs.gitlab.com, bitbucket.org/site/ssh).
BUILTIN = {
    "github.com": [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
    ],
    "gitlab.com": [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf",
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9",
    ],
    "bitbucket.org": [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIazEu89wgQZ4bqs3d63QSMzYVa0MuJ2e2gKTKqu+UUO",
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPIQmuzMBuKdWeF4+a2sjSSpBK0iqitSQ+5BM9KhpexuGt20JpTVM7u5BDZngncgrqDMbWdxMWWOGtZ9UgbqgZE=",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQeJzhupRu0u0cdegZIa8e86EG2qOCsIsD1Xw0xSeiPDlCr7kq97NLmMbpKTX6Esc30NuoqEEHCuc7yWtwp8dI76EEEB1VqY9QJq6vk+aySyboD5QF61I/1WeTwu+deCbgKMGbUijeXhtfbxSxm6JwGrXrhBdofTsbKRUsrN1WoNgUa8uqN1Vx6WAJw1JHPhglEGGHea6QICwJOAr/6mrui/oB7pkaWKHj3z7d1IC4KWLtY47elvjbaTlkN04Kc/5LFEirorGYVbt15kAUlqGM65pk6ZBxtaO3+30LVlORZkxOh+LKL/BvbZ/iRNhItLqNyieoQj/uh/7Iv4uyH/cV/0b4WDSd3DptigWq84lJubb9t/DnZlrJazxyDCulTmKdOR7vs9gMTo+uoIrPSb8ScTtvw65+odKAlBj59dhnVp9zd7QUojOpXlL62Aw56U4oO+FALuevvMjiWeavKhJqlR7i5n9srYcrNV7ttmDw7kf/97P5zauIhxcjX+xHv4M=",
    ],
}

DEFAULT_FILES = ["~/.ssh/known_hosts", "~/.ssh/known_hosts2", "/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"]


def _host_variants(name: str) -> list[str]:
    return [name]


def _strip_port(h: str) -> str:
    if h.startswith("[") and "]:" in h:
        host, port = h[1:].split("]:", 1)
        return host if port == "22" else f"{host}:{port}"
    return h


class HostDB:
    """host key blob -> set of names, from built-ins plus known_hosts files.

    Hashed known_hosts entries (|1|salt|hash) can't be reversed, so they are
    matched against candidate names (ssh config Host/HostName values and host
    names used in the policy)."""

    def __init__(self):
        self.names: dict[bytes, set[str]] = {}
        self.hashed: list[tuple[bytes, bytes, bytes]] = []
        self.candidates: set[str] = set()
        for host, lines in BUILTIN.items():
            for line in lines:
                self.add(base64.b64decode(line.split()[1]), host)

    def add(self, blob: bytes, name: str) -> None:
        self.names.setdefault(blob, set()).add(name)

    def load_known_hosts(self, path: str) -> int:
        path = os.path.expanduser(path)
        n = 0
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if parts[0].startswith("@"):
                if parts[0] != "@cert-authority" and parts[0] != "@revoked":
                    continue
                continue  # CA and revoked lines don't name a host key
            if len(parts) < 3:
                continue
            hosts, b64 = parts[0], parts[2]
            try:
                blob = base64.b64decode(b64, validate=True)
            except ValueError:
                continue
            for h in hosts.split(","):
                if h.startswith("|1|"):
                    try:
                        _, _, salt, digest = h.split("|", 3)
                        self.hashed.append((base64.b64decode(salt), base64.b64decode(digest), blob))
                    except ValueError:
                        pass
                elif not h.startswith("!"):
                    self.add(blob, _strip_port(h))
                n += 1
        return n

    def load_default(self, files: list[str] | None = None) -> None:
        for p in files or DEFAULT_FILES:
            self.load_known_hosts(p)

    def add_candidates(self, names) -> None:
        for n in names:
            if n and not any(c in n for c in "*?!"):
                self.candidates.add(n)

    def lookup(self, blob: bytes | None) -> list[str]:
        if not blob:
            return []
        out = set(self.names.get(blob, set()))
        for salt, digest, b in self.hashed:
            if b != blob:
                continue
            for cand in self.candidates:
                for form in (cand, f"[{cand}]:22"):
                    if hmac.compare_digest(hmac.new(salt, form.encode(), hashlib.sha1).digest(), digest):
                        out.add(cand)
        return sorted(out)

    def describe(self, blob: bytes | None) -> str:
        if not blob:
            return "unknown host"
        names = self.lookup(blob)
        return ",".join(names) if names else f"unrecognised host key {fingerprint(blob)}"
