import json
import os

from sshleash.cli import main


def test_init_writes_policy(tmp_path, capsys):
    p = tmp_path / "pol.toml"
    assert main(["init", "--policy", str(p)]) == 0
    assert p.exists() and "[[rule]]" in p.read_text()
    assert "ForwardAgent ~/.ssh/sshleash.sock" in capsys.readouterr().out
    p.write_text("# mine")
    main(["init", "--policy", str(p)])
    assert p.read_text() == "# mine"


def test_explain(tmp_path, capsys):
    p = tmp_path / "pol.toml"
    p.write_text('[[rule]]\nname = "no prod via forwarding"\nforwarded = true\nhost = "*.prod"\naction = "deny"\n')
    assert main(["explain", "--policy", str(p), "--key", "work", "--host", "db.prod", "--via", "devbox"]) == 1
    assert "DENY  (rule: no prod via forwarding)" in capsys.readouterr().out
    assert main(["explain", "--policy", str(p), "--key", "work", "--host", "db.prod"]) == 0
    assert main(["explain", "--policy", str(tmp_path / "missing.toml")]) == 2


def test_log_command(tmp_path, capsys):
    log = tmp_path / "log.jsonl"
    log.write_text("\n".join(json.dumps(e) for e in [
        {"ts": "2026-11-14T10:00:00+0000", "op": "sign", "kind": "ssh-auth", "decision": "allow",
         "key": "work ED25519 SHA256:x", "host": "github.com", "user": "git", "rule": "default"},
        {"ts": "2026-11-14T10:00:01+0000", "op": "sign", "kind": "ssh-auth", "decision": "deny",
         "key": "work ED25519 SHA256:x", "host": "github.com", "user": "git", "forwarded": True, "via": "devbox",
         "process": {"pid": 42, "name": "ssh", "parents": ["bash"]}, "rule": "forwarded agents must ask",
         "reason": "refused by user"},
    ]) + "\n")
    assert main(["log", "--log", str(log)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "10:00:00 ALLOW   login git@github.com with work ED25519 SHA256:x  [default]"
    assert "via forwarded agent on devbox  by ssh < bash (pid 42)" in out[1]
    assert main(["log", "--log", str(log), "--deny", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "deny"
    assert main(["log", "--log", str(tmp_path / "none")]) == 0


def test_run_refuses_without_upstream(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    assert main(["run", "--socket", str(tmp_path / "s.sock")]) == 2
    monkeypatch.setenv("SSH_AUTH_SOCK", str(tmp_path / "s.sock"))
    assert main(["run", "--socket", str(tmp_path / "s.sock")]) == 2
