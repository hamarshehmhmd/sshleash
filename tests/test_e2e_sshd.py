"""End-to-end with real sshd servers: laptop -> devbox (agent forwarded) -> gitserver.

Runs only with SSHLEASH_E2E=1 and an sshd binary (CI installs openssh-server).
Two unprivileged sshd processes listen on 127.0.0.1 with their own host keys."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import pytest

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
pytestmark = pytest.mark.skipif(not (os.environ.get("SSHLEASH_E2E") and SSHD), reason="set SSHLEASH_E2E=1 with sshd")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"sshd on {port} did not start")


@pytest.fixture
def lab(env):
    d = tempfile.mkdtemp(prefix="e2e", dir="/tmp")
    auth = os.path.join(d, "authorized_keys")
    with open(auth, "w") as f:
        f.write(open(f"{env.dir}/work.pub").read())
    kh = os.path.join(d, "known_hosts")
    procs, ports = [], {}
    with open(kh, "w") as khf:
        for name in ("devbox", "gitserver"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{d}/{name}_host"], check=True)
            port = free_port()
            ports[name] = port
            cfg = f"{d}/{name}_sshd_config"
            with open(cfg, "w") as c:
                c.write(f"""Port {port}
ListenAddress 127.0.0.1
HostKey {d}/{name}_host
PidFile {d}/{name}.pid
AuthorizedKeysFile {auth}
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowAgentForwarding yes
LogLevel VERBOSE
""")
            pub = open(f"{d}/{name}_host.pub").read().split()
            khf.write(f"{name} {pub[0]} {pub[1]}\n")
            procs.append(subprocess.Popen([SSHD, "-D", "-e", "-f", cfg], stdout=subprocess.DEVNULL,
                                          stderr=open(f"{d}/{name}.log", "w")))
            wait_port(port)
    yield {"dir": d, "kh": kh, "ports": ports}
    for p in procs:
        p.kill()
    shutil.rmtree(d, ignore_errors=True)


def start_leash(env, lab, policy):
    pol = os.path.join(lab["dir"], "policy.toml")
    open(pol, "w").write(policy)
    sock = os.path.join(lab["dir"], "leash.sock")
    log = os.path.join(lab["dir"], "leash.jsonl")
    if os.path.exists(log):
        os.unlink(log)
    p = subprocess.Popen([sys.executable, "-m", "sshleash", "run", "--socket", sock, "--upstream", env.agent_sock,
                          "--policy", pol, "--log", log, "--known-hosts", lab["kh"]],
                         stderr=open(os.path.join(lab["dir"], "leash.err"), "w"))
    for _ in range(100):
        if os.path.exists(sock):
            break
        time.sleep(0.05)
    return p, sock, log


def two_hops(lab, sock):
    common = ["-F", "/dev/null", "-o", f"UserKnownHostsFile={lab['kh']}", "-o", "StrictHostKeyChecking=yes",
              "-o", "BatchMode=yes", "-o", "IdentityFile=/nonexistent"]
    inner = " ".join(["ssh"] + common + ["-p", str(lab["ports"]["gitserver"]), "-o", "HostKeyAlias=gitserver",
                                          "127.0.0.1", "echo", "hop2-ok"])
    cmd = ["ssh"] + common + ["-p", str(lab["ports"]["devbox"]), "-o", "HostKeyAlias=devbox",
                              "-o", f"ForwardAgent={sock}", "127.0.0.1", "echo hop1-ok; " + inner]
    return subprocess.run(cmd, env=dict(os.environ, SSH_AUTH_SOCK=sock), capture_output=True, text=True, timeout=60)


def events(log):
    return [json.loads(x) for x in open(log)] if os.path.exists(log) else []


def test_forwarded_hop_is_seen_and_allowed(env, lab):
    p, sock, log = start_leash(env, lab, '[default]\naction = "allow"\n')
    try:
        r = two_hops(lab, sock)
        assert "hop1-ok" in r.stdout and "hop2-ok" in r.stdout, r.stderr
        signs = [e for e in events(log) if e["op"] == "sign"]
        assert signs[0]["host"] == "devbox" and signs[0]["forwarded"] is False
        hop2 = signs[-1]
        assert hop2["forwarded"] is True and hop2["via"] == "devbox" and hop2["host"] == "gitserver"
        assert hop2["process"]["name"] == "ssh"
    finally:
        p.terminate()


def test_forwarded_hop_denied_by_policy(env, lab):
    p, sock, log = start_leash(env, lab, '''
[[rule]]
name = "nothing through devbox"
via = ["devbox"]
host = ["gitserver"]
action = "deny"
''')
    try:
        r = two_hops(lab, sock)
        assert "hop1-ok" in r.stdout and "hop2-ok" not in r.stdout
        assert "Permission denied" in r.stderr
        denied = [e for e in events(log) if e.get("decision") == "deny"]
        assert denied and denied[0]["via"] == "devbox" and denied[0]["host"] == "gitserver"
    finally:
        p.terminate()
