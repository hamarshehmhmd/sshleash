import subprocess

from sshleash import wire


def test_fingerprint_matches_ssh_keygen(env):
    out = subprocess.run(["ssh-keygen", "-lf", f"{env.dir}/work.pub"], capture_output=True, text=True).stdout
    assert wire.fingerprint(env.work) == out.split()[1]
    assert wire.key_type(env.work) == "ssh-ed25519"
    assert wire.short_type(env.work) == "ED25519"


def test_classify_userauth_plain_and_hostbound():
    blob = wire.string("ssh-ed25519") + wire.string(b"k" * 32)
    data = wire.build_userauth_data(b"sid123", "git", "ssh-ed25519", blob)
    info = wire.classify_sign_data(data)
    assert info["kind"] == "ssh-auth" and info["user"] == "git" and info["session_id"] == b"sid123"
    assert not info["hostbound"]
    hk = wire.string("ssh-ed25519") + wire.string(b"h" * 32)
    info = wire.classify_sign_data(wire.build_userauth_data(b"sid", "alice", "ssh-ed25519", blob, hostkey=hk))
    assert info["hostbound"] and info["hostkey"] == hk and info["user"] == "alice"


def test_classify_sshsig_and_garbage():
    data = b"SSHSIG" + wire.string("git") + wire.string("") + wire.string("sha512") + wire.string(b"x" * 64)
    assert wire.classify_sign_data(data) == {"kind": "sshsig", "namespace": "git", "hash": "sha512"}
    assert wire.classify_sign_data(b"\x00\x00")["kind"] == "unknown"
    assert wire.classify_sign_data(wire.string(b"sid") + b"\x05")["kind"] == "unknown"


def test_session_bind_roundtrip():
    msg = wire.build_session_bind(b"HK", b"SID", b"SIG", True)
    body = msg[4:]
    assert body[0] == wire.EXTENSION
    name, rest = wire.parse_extension(body[1:])
    assert name == wire.SESSION_BIND
    b = wire.parse_session_bind(rest)
    assert b == {"hostkey": b"HK", "session_id": b"SID", "forwarding": True}


def test_identities_roundtrip():
    keys = [(b"blob1", "a"), (b"blob2", "b c")]
    framed = wire.build_identities(keys)
    assert wire.parse_identities(framed[5:]) == keys


def test_truncated_raises():
    import pytest
    with pytest.raises(wire.WireError):
        wire.Reader(b"\x00\x00\x00\x09abc").string()
