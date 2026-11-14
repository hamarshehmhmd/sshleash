"""Who is on the other end of a unix socket: pid, program and its parents."""
from __future__ import annotations

import os
import socket
import struct
import subprocess
import sys


def peer_pid(sock) -> int | None:
    try:
        if sys.platform.startswith("linux"):
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, _uid, _gid = struct.unpack("3i", creds)
            return pid or None
        if sys.platform == "darwin":
            SOL_LOCAL, LOCAL_PEERPID = 0, 2
            raw = sock.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4)
            return struct.unpack("i", raw)[0] or None
    except (OSError, AttributeError):
        return None
    return None


def _linux_proc(pid: int):
    try:
        with open(f"/proc/{pid}/comm") as f:
            name = f.read().strip()
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        ppid = 0
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("PPid:"):
                    ppid = int(line.split()[1])
        return name, cmd, ppid
    except (OSError, ValueError):
        return None


def _ps_proc(pid: int):
    try:
        out = subprocess.run(["ps", "-o", "ppid=,comm=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=2).stdout.strip()
        cmd = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=2).stdout.strip()
        if not out:
            return None
        ppid, comm = out.split(None, 1)
        return os.path.basename(comm), cmd, int(ppid)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def process_info(pid: int | None, depth: int = 8) -> dict:
    """{'pid', 'name', 'cmdline', 'parents': [names...]}"""
    if not pid:
        return {"pid": None, "name": "unknown", "cmdline": "", "parents": []}
    reader = _linux_proc if sys.platform.startswith("linux") else _ps_proc
    first = reader(pid)
    if not first:
        return {"pid": pid, "name": "unknown", "cmdline": "", "parents": []}
    name, cmd, ppid = first
    parents = []
    seen = {pid}
    while ppid > 1 and ppid not in seen and len(parents) < depth:
        seen.add(ppid)
        info = reader(ppid)
        if not info:
            break
        pname, pcmd, ppid = info
        parents.append(pname)
    return {"pid": pid, "name": name, "cmdline": cmd, "parents": parents}


def names(info: dict) -> list[str]:
    out = [info.get("name") or "unknown"]
    cmd = info.get("cmdline") or ""
    if cmd:
        out.append(os.path.basename(cmd.split()[0]))
    out.extend(info.get("parents") or [])
    seen, uniq = set(), []
    for n in out:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq
