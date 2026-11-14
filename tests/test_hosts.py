import base64
import subprocess

from sshleash.hosts import HostDB


def test_builtin_github():
    db = HostDB()
    b = base64.b64decode("AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl")
    assert db.lookup(b) == ["github.com"]
    assert db.lookup(None) == []
    assert db.describe(b"x").startswith("unrecognised host key SHA256:")


def test_known_hosts_plain_port_and_hashed(env, tmp_path):
    pub = open(f"{env.dir}/devbox.pub").read().split()
    kh = tmp_path / "kh"
    kh.write_text(f"devbox,10.0.0.5 {pub[0]} {pub[1]}\n[jump.example]:2222 {pub[0]} {pub[1]}\n# c\n@revoked * {pub[0]} {pub[1]}\n")
    db = HostDB()
    assert db.load_known_hosts(str(kh)) == 3
    assert db.lookup(env.devbox) == ["10.0.0.5", "devbox", "jump.example:2222"]

    hashed = tmp_path / "kh2"
    hashed.write_text(f"secret-box {pub[0]} {pub[1]}\n")
    subprocess.run(["ssh-keygen", "-q", "-H", "-f", str(hashed)], check=True, capture_output=True)
    assert "secret-box" not in hashed.read_text()
    db2 = HostDB()
    db2.load_known_hosts(str(hashed))
    assert db2.lookup(env.devbox) == []
    db2.add_candidates(["secret-box", "*.wild"])
    assert db2.lookup(env.devbox) == ["secret-box"]


def test_missing_file_is_fine():
    assert HostDB().load_known_hosts("/nonexistent/kh") == 0
