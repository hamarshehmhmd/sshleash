import os

from sshleash import audit
from sshleash.cli import main

LEASH = "~/.ssh/sshleash.sock"


def write(p, text):
    p.write_text(text)
    return str(p)


def codes(findings):
    return [(f.severity, f.code) for f in findings]


def test_config_findings(tmp_path):
    inc = tmp_path / "devpod.conf"
    write(inc, "# DevPod Start myws.devpod\nHost myws.devpod\n  ForwardAgent yes\n  User vscode\n# DevPod End\n")
    cfg = write(tmp_path / "config", f"""
Include {inc}

Host devbox
  HostName devbox.internal
  ForwardAgent yes

Host safe
  ForwardAgent {tmp_path}/sshleash.sock

Host nothing
  ForwardAgent no

Host *.lab
  ForwardAgent=yes
""")
    c = audit.parse_ssh_config(cfg)
    f = audit.check_config(c, LEASH)
    assert codes(f) == [("medium", "forward-tool"), ("medium", "forward-host"), ("info", "forward-leashed"),
                        ("high", "forward-wildcard")]
    assert "DevPod" in f[0].message and f[0].where.endswith("devpod.conf:3")
    assert "devbox.internal" in c.hostnames and "devbox" in c.hostnames and "myws.devpod" in c.hostnames
    assert f[3].fix.startswith("ForwardAgent ~/.ssh/sshleash.sock")


def test_global_forwardagent_before_any_host_is_wildcard(tmp_path):
    cfg = write(tmp_path / "config", "ForwardAgent yes\nHost x\n  User y\n")
    f = audit.check_config(audit.parse_ssh_config(cfg), LEASH)
    assert codes(f) == [("high", "forward-wildcard")]


def test_match_block_counts_as_wildcard(tmp_path):
    cfg = write(tmp_path / "config", "Match host *.corp exec true\n  ForwardAgent yes\n")
    assert codes(audit.check_config(audit.parse_ssh_config(cfg), LEASH)) == [("high", "forward-wildcard")]


def test_include_cycle_and_missing(tmp_path):
    a = tmp_path / "a"
    write(a, f"Include {a}\nInclude {tmp_path}/missing\nHost h\n ForwardAgent yes\n")
    f = audit.check_config(audit.parse_ssh_config(str(a)), LEASH)
    assert codes(f) == [("medium", "forward-host")]


def test_agent_checks(env):
    f, keys = audit.check_agent({"SSH_AUTH_SOCK": env.agent_sock}, LEASH)
    assert codes(f) == [("medium", "agent-unfiltered")]
    assert sorted(k["comment"] for k in keys) == ["bot", "work"]
    f, _ = audit.check_agent({"SSH_AUTH_SOCK": env.agent_sock, "SSH_CONNECTION": "1.2.3.4 5 6.7.8.9 22"}, LEASH)
    assert codes(f) == [("medium", "remote-forwarded-agent")]
    f, _ = audit.check_agent({}, LEASH)
    assert codes(f) == [("info", "no-agent")]
    f, _ = audit.check_agent({"SSH_AUTH_SOCK": "/nonexistent.sock"}, LEASH)
    assert codes(f) == [("low", "agent-unreachable")]


def test_audit_cli_exit_codes(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    cfg = write(tmp_path / "config", "Host *\n  ForwardAgent yes\n")
    assert main(["audit", "--config", cfg, "--no-processes"]) == 1
    out = capsys.readouterr().out
    assert "HIGH" in out and "every matching host" in out
    ok = write(tmp_path / "ok", "Host x\n  ForwardAgent no\n")
    assert main(["audit", "--config", ok, "--no-processes"]) == 0
    assert main(["audit", "--config", cfg, "--no-processes", "--fail-on", "never"]) == 0
    capsys.readouterr()
    assert main(["audit", "--config", cfg, "--json", "--no-processes"]) == 1
    import json
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["code"] == "forward-wildcard"


def test_process_scan_finds_children(env):
    import subprocess
    import sys
    if not sys.platform.startswith("linux"):
        return
    p = subprocess.Popen(["sleep", "30"], env=dict(os.environ, SSH_AUTH_SOCK=env.agent_sock))
    try:
        found = audit.scan_processes({env.agent_sock})
        assert any(x["pid"] == p.pid and x["real_agent"] for x in found)
    finally:
        p.kill()
