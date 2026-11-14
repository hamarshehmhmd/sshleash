import json
import os
import subprocess

from conftest import AgentClient

from sshleash import wire

ALLOW_ALL = '[default]\naction = "allow"\n'


def events(log):
    if not os.path.exists(log):
        return []
    return [json.loads(x) for x in open(log)]


def test_lists_and_signs_through_real_agent(env, leash):
    sock, log, _ = leash(ALLOW_ALL)
    out = subprocess.run(["ssh-add", "-l"], env=dict(os.environ, SSH_AUTH_SOCK=sock), capture_output=True, text=True)
    assert out.returncode == 0
    assert "work" in out.stdout and "bot" in out.stdout


def test_sshsig_git_signing_allowed_and_denied(env, leash, tmp_path):
    sock, log, _ = leash('''
[[rule]]
name = "bot may not sign commits"
key = "bot"
kind = "sshsig"
action = "deny"
''')
    f = tmp_path / "msg"
    f.write_text("hello")
    e = dict(os.environ, SSH_AUTH_SOCK=sock)
    ok = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", f"{env.dir}/work.pub", "-n", "git", str(f)], env=e,
                        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    assert (tmp_path / "msg.sig").exists()
    os.unlink(tmp_path / "msg.sig")
    bad = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", f"{env.dir}/bot.pub", "-n", "git", str(f)], env=e,
                         capture_output=True, text=True)
    assert bad.returncode != 0 and "refused" in bad.stderr
    ev = [x for x in events(log) if x["op"] == "sign"]
    assert [x["decision"] for x in ev] == ["allow", "deny"]
    assert ev[1]["kind"] == "sshsig" and ev[1]["namespace"] == "git"
    assert ev[1]["rule"] == "bot may not sign commits"
    assert ev[1]["process"]["name"] == "ssh-keygen"


def test_connection_level_deny_hides_key(env, leash):
    sock, log, _ = leash('''
[[rule]]
name = "hide bot from ssh-add"
key = "bot"
process = ["ssh-add"]
action = "deny"
''')
    out = subprocess.run(["ssh-add", "-l"], env=dict(os.environ, SSH_AUTH_SOCK=sock), capture_output=True, text=True)
    assert "work" in out.stdout and "bot" not in out.stdout
    ev = events(log)
    assert ev[-1]["op"] == "list" and ev[-1]["hidden_keys"] == ["bot"]


def _forwarded_channel(env, sock, fwd_host=None, verified=True):
    """Simulate what OpenSSH does on a forwarded agent channel: our ssh client binds
    the channel to the session with devbox (forwarding=1), then the ssh client on
    devbox binds its own session with gitserver (forwarding=0)."""
    c = AgentClient(sock)
    sid1 = os.urandom(32)
    r = c.bind(env.devbox, sid1, env.host_sig(env.devbox, sid1), True)
    assert r[0] == wire.SUCCESS
    sid2 = os.urandom(32)
    sig2 = env.host_sig(env.gitserver, sid2) if verified else env.host_sig(env.gitserver, b"other session")
    r = c.bind(env.gitserver, sid2, sig2, False)
    assert (r[0] == wire.SUCCESS) == verified
    return c, sid2


POL_FWD = '''
[[rule]]
name = "work key never via forwarding to gitserver"
key = "work"
forwarded = true
host = ["gitserver"]
action = "deny"
[[rule]]
name = "forwarded + unknown destination"
forwarded = true
host = ["unknown"]
action = "deny"
[[rule]]
name = "hide bot from devbox"
key = "bot"
via = ["devbox"]
action = "deny"
[default]
action = "allow"
'''


def test_forwarded_chain_identifies_hop_and_destination(env, leash):
    sock, log, _ = leash(POL_FWD)
    c, sid = _forwarded_channel(env, sock)
    keys = c.identities()
    assert [k[1] for k in keys] == ["work"]  # bot hidden from devbox
    r = c.sign(env.work, wire.build_userauth_data(sid, "git", "ssh-ed25519", env.work))
    assert r[0] == wire.FAILURE
    ev = [x for x in events(log) if x["op"] == "sign"][-1]
    assert ev["forwarded"] is True and ev["via"] == "devbox" and ev["host"] == "gitserver"
    assert ev["host_verified"] is True and ev["user"] == "git"
    assert ev["decision"] == "deny" and ev["rule"] == "work key never via forwarding to gitserver"
    c.close()


def test_local_bind_to_other_host_is_allowed(env, leash):
    sock, log, _ = leash(POL_FWD)
    c = AgentClient(sock)
    sid = os.urandom(32)
    assert c.bind(env.gitserver, sid, env.host_sig(env.gitserver, sid), False)[0] == wire.SUCCESS
    r = c.sign(env.work, wire.build_userauth_data(sid, "git", "ssh-ed25519", env.work))
    assert r[0] == wire.SIGN_RESPONSE
    ev = [x for x in events(log) if x["op"] == "sign"][-1]
    assert ev["forwarded"] is False and ev["host"] == "gitserver" and ev["decision"] == "allow"


def test_spoofed_bind_from_remote_is_not_believed(env, leash):
    sock, log, _ = leash(POL_FWD.replace('host = ["gitserver"]', 'host = ["somewhere-else"]'))
    c, sid = _forwarded_channel(env, sock, verified=False)
    r = c.sign(env.work, wire.build_userauth_data(sid, "git", "ssh-ed25519", env.work))
    assert r[0] == wire.FAILURE
    ev = [x for x in events(log) if x["op"] == "sign"][-1]
    assert ev["host"] == "" and ev["rule"] == "forwarded + unknown destination"


def test_hostbound_auth_names_destination_without_bind(env, leash):
    sock, log, _ = leash('[[rule]]\nname = "no gitserver"\nhost = "gitserver"\naction = "deny"\n')
    c = AgentClient(sock)
    data = wire.build_userauth_data(os.urandom(32), "me", "ssh-ed25519", env.work, hostkey=env.gitserver)
    assert c.sign(env.work, data)[0] == wire.FAILURE
    data = wire.build_userauth_data(os.urandom(32), "me", "ssh-ed25519", env.work, hostkey=env.devbox)
    assert c.sign(env.work, data)[0] == wire.SIGN_RESPONSE


def test_management_from_forwarded_channel_denied(env, leash):
    sock, log, _ = leash(ALLOW_ALL)
    c, _sid = _forwarded_channel(env, sock)
    assert c.request(wire.frame(wire.REMOVE_ALL_IDENTITIES))[0] == wire.FAILURE
    assert c.request(wire.frame(wire.LOCK, wire.string("pw")))[0] == wire.FAILURE
    ev = events(log)
    assert ev[-1]["op"] == "lock" and ev[-1]["decision"] == "deny"
    # keys are still there
    assert len(AgentClient(env.agent_sock).identities()) == 2


def test_management_from_local_allowed(env, leash):
    sock, log, _ = leash(ALLOW_ALL)
    c = AgentClient(sock)
    assert c.request(wire.frame(wire.REMOVE_ALL_IDENTITIES))[0] == wire.SUCCESS
    assert AgentClient(env.agent_sock).identities() == []


def _confirm_script(tmp_path, rc):
    p = tmp_path / f"confirm{rc}.sh"
    p.write_text(f'#!/bin/sh\necho "$1" >> "{tmp_path}/prompts"\nexit {rc}\n')
    p.chmod(0o755)
    return str(p)


def test_confirm_approve_deny_and_remember(env, leash, tmp_path):
    yes = _confirm_script(tmp_path, 0)
    sock, log, _ = leash(f'[settings]\nconfirm = "{yes}"\nremember = 60\n[[rule]]\nname = "ask"\nkey = "work"\naction = "confirm"\n')
    c = AgentClient(sock)
    c.identities()
    data = wire.build_userauth_data(os.urandom(32), "me", "ssh-ed25519", env.work, hostkey=env.devbox)
    assert c.sign(env.work, data)[0] == wire.SIGN_RESPONSE
    assert c.sign(env.work, data)[0] == wire.SIGN_RESPONSE
    prompts = (tmp_path / "prompts").read_text()
    assert prompts.count("Allow key 'work' to log in to me@devbox?") == 1  # second one remembered
    ev = [x for x in events(log) if x["op"] == "sign"]
    assert ev[0]["reason"] == "approved by user" and ev[1]["reason"] == "remembered approval"

    no = _confirm_script(tmp_path, 1)
    sock2, log2, _ = leash(f'[settings]\nconfirm = "{no}"\n[[rule]]\nname = "ask"\naction = "confirm"\n')
    c2 = AgentClient(sock2)
    assert c2.sign(env.work, data)[0] == wire.FAILURE
    assert events(log2)[-1]["reason"] == "refused by user"


def test_confirm_without_program_denies(env, leash):
    sock, log, _ = leash('[settings]\nconfirm = "/nonexistent/askpass"\n[default]\naction = "confirm"\n')
    c = AgentClient(sock)
    data = wire.build_userauth_data(os.urandom(32), "me", "ssh-ed25519", env.work, hostkey=env.devbox)
    assert c.sign(env.work, data)[0] == wire.FAILURE
    assert "failed to start" in events(log)[-1]["reason"]


def test_sign_without_listing_still_gets_comment(env, leash):
    sock, log, _ = leash('[[rule]]\nname = "no bot"\nkey = "bot"\naction = "deny"\n')
    c = AgentClient(sock)
    assert c.sign(env.bot, b"\x00" * 10)[0] == wire.FAILURE
    assert c.sign(env.work, b"\x00" * 10)[0] == wire.SIGN_RESPONSE


def test_upstream_down_closes_cleanly(env, leash):
    sock, log, _ = leash(ALLOW_ALL, upstream=os.path.join(env.dir, "nope.sock"))
    out = subprocess.run(["ssh-add", "-l"], env=dict(os.environ, SSH_AUTH_SOCK=sock), capture_output=True, text=True)
    assert out.returncode != 0
    assert events(log)[-1]["decision"] == "error"


def test_socket_permissions(env, leash):
    sock, _, _ = leash(ALLOW_ALL)
    assert oct(os.stat(sock).st_mode & 0o777) == "0o600"
