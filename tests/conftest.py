import asyncio
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import pytest

from sshleash import wire
from sshleash.hosts import HostDB
from sshleash.policy import parse
from sshleash.proxy import Leash, Logger, serve

needs_openssh = pytest.mark.skipif(not (shutil.which("ssh-agent") and shutil.which("ssh-keygen")),
                                   reason="OpenSSH tools not installed")


class AgentClient:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(10)
        self.s.connect(path)

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            c = self.s.recv(n - len(buf))
            if not c:
                raise ConnectionError("closed")
            buf += c
        return buf

    def request(self, framed: bytes) -> bytes:
        self.s.sendall(framed)
        n = int.from_bytes(self._recv(4), "big")
        return self._recv(n)

    def identities(self):
        r = self.request(wire.frame(wire.REQUEST_IDENTITIES))
        assert r[0] == wire.IDENTITIES_ANSWER
        return wire.parse_identities(r[1:])

    def sign(self, blob, data) -> bytes:
        return self.request(wire.build_sign_request(blob, data))

    def bind(self, hostkey, sid, sig, fwd) -> bytes:
        return self.request(wire.build_session_bind(hostkey, sid, sig, fwd))

    def close(self):
        self.s.close()


def _keygen(d, name):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", os.path.join(d, name)], check=True)
    with open(os.path.join(d, name + ".pub")) as f:
        return wire.blob_from_openssh_line(f.read())


def _start_agent(sock):
    p = subprocess.Popen(["ssh-agent", "-D", "-a", sock], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        if os.path.exists(sock):
            return p
        time.sleep(0.05)
    p.kill()
    raise RuntimeError("ssh-agent did not start")


class Env:
    pass


@pytest.fixture
def env():
    if not (shutil.which("ssh-agent") and shutil.which("ssh-keygen")):
        pytest.skip("OpenSSH tools not installed")
    d = tempfile.mkdtemp(prefix="sl", dir="/tmp")
    e = Env()
    e.dir = d
    e.agent_sock = os.path.join(d, "a.sock")
    e.host_agent_sock = os.path.join(d, "h.sock")
    e.agent = _start_agent(e.agent_sock)
    e.host_agent = _start_agent(e.host_agent_sock)
    e.work = _keygen(d, "work")
    e.bot = _keygen(d, "bot")
    e.devbox = _keygen(d, "devbox")
    e.gitserver = _keygen(d, "gitserver")
    run_env = dict(os.environ, SSH_AUTH_SOCK=e.agent_sock)
    subprocess.run(["ssh-add", "-q", os.path.join(d, "work"), os.path.join(d, "bot")], env=run_env, check=True,
                   capture_output=True)
    subprocess.run(["ssh-add", "-q", os.path.join(d, "devbox"), os.path.join(d, "gitserver")],
                   env=dict(os.environ, SSH_AUTH_SOCK=e.host_agent_sock), check=True, capture_output=True)
    with open(os.path.join(d, "known_hosts"), "w") as f:
        for name in ("devbox", "gitserver"):
            with open(os.path.join(d, name + ".pub")) as k:
                kt, b64 = k.read().split()[:2]
            f.write(f"{name} {kt} {b64}\n")

    def host_sig(hostkey_blob, sid):
        c = AgentClient(e.host_agent_sock)
        r = c.sign(hostkey_blob, sid)
        c.close()
        assert r[0] == wire.SIGN_RESPONSE
        return wire.Reader(r[1:]).string()

    e.host_sig = host_sig
    e.servers = []
    yield e
    for stop, loop, t in e.servers:
        loop.call_soon_threadsafe(stop.set)
        t.join(5)
    e.agent.kill()
    e.host_agent.kill()
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def leash(env):
    """leash(policy_text) -> (socket path, log path, Leash)"""
    counter = [0]

    def start(policy_text, upstream=None):
        counter[0] += 1
        sock = os.path.join(env.dir, f"l{counter[0]}.sock")
        log = os.path.join(env.dir, f"log{counter[0]}.jsonl")
        pol = parse(policy_text, path="test")
        db = HostDB()
        db.load_known_hosts(os.path.join(env.dir, "known_hosts"))
        lsh = Leash(upstream or env.agent_sock, pol, db, Logger(log, quiet=True))
        ready = threading.Event()
        holder = {}

        def run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            stop = asyncio.Event()
            holder["stop"], holder["loop"] = stop, loop
            r = asyncio.Event()

            async def main():
                task = asyncio.create_task(serve(sock, lsh, ready=r, stop=stop))
                await r.wait()
                ready.set()
                await task

            loop.run_until_complete(main())
            loop.close()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        assert ready.wait(5)
        env.servers.append((holder["stop"], holder["loop"], t))
        return sock, log, lsh

    return start
