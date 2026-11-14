"""SSH agent protocol (draft-miller-ssh-agent) wire helpers."""
from __future__ import annotations

import base64
import hashlib
import struct

FAILURE = 5
SUCCESS = 6
REQUEST_IDENTITIES = 11
IDENTITIES_ANSWER = 12
SIGN_REQUEST = 13
SIGN_RESPONSE = 14
ADD_IDENTITY = 17
REMOVE_IDENTITY = 18
REMOVE_ALL_IDENTITIES = 19
ADD_SMARTCARD_KEY = 20
REMOVE_SMARTCARD_KEY = 21
LOCK = 22
UNLOCK = 23
ADD_ID_CONSTRAINED = 25
ADD_SMARTCARD_KEY_CONSTRAINED = 26
EXTENSION = 27
EXTENSION_FAILURE = 28

MANAGEMENT = {
    ADD_IDENTITY: "add-key",
    REMOVE_IDENTITY: "remove-key",
    REMOVE_ALL_IDENTITIES: "remove-all-keys",
    ADD_SMARTCARD_KEY: "add-smartcard",
    REMOVE_SMARTCARD_KEY: "remove-smartcard",
    LOCK: "lock",
    UNLOCK: "unlock",
    ADD_ID_CONSTRAINED: "add-key",
    ADD_SMARTCARD_KEY_CONSTRAINED: "add-smartcard",
}

MAX_MESSAGE = 256 * 1024
USERAUTH_REQUEST = 50
SESSION_BIND = b"session-bind@openssh.com"


class WireError(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise WireError("truncated message")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self._take(1)[0]

    def u32(self) -> int:
        return struct.unpack(">I", self._take(4))[0]

    def string(self) -> bytes:
        return self._take(self.u32())

    def boolean(self) -> bool:
        return self.u8() != 0

    def rest(self) -> bytes:
        return self._take(len(self.data) - self.pos)

    @property
    def done(self) -> bool:
        return self.pos >= len(self.data)


def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def string(b: bytes | str) -> bytes:
    if isinstance(b, str):
        b = b.encode()
    return u32(len(b)) + b


def frame(msg_type: int, payload: bytes = b"") -> bytes:
    return u32(len(payload) + 1) + bytes([msg_type]) + payload


def fingerprint(blob: bytes) -> str:
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def key_type(blob: bytes) -> str:
    try:
        return Reader(blob).string().decode("ascii", "replace")
    except WireError:
        return "unknown"


def short_type(blob: bytes) -> str:
    t = key_type(blob)
    table = {
        "ssh-ed25519": "ED25519", "ssh-rsa": "RSA", "ssh-dss": "DSA",
        "ecdsa-sha2-nistp256": "ECDSA", "ecdsa-sha2-nistp384": "ECDSA-384",
        "ecdsa-sha2-nistp521": "ECDSA-521",
        "sk-ssh-ed25519@openssh.com": "ED25519-SK", "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
    }
    if t in table:
        return table[t]
    if "-cert-" in t:
        return "CERT"
    return t


def parse_identities(payload: bytes) -> list[tuple[bytes, str]]:
    r = Reader(payload)
    n = r.u32()
    out = []
    for _ in range(n):
        blob = r.string()
        comment = r.string().decode("utf-8", "replace")
        out.append((blob, comment))
    return out


def build_identities(keys: list[tuple[bytes, str]]) -> bytes:
    body = u32(len(keys)) + b"".join(string(b) + string(c) for b, c in keys)
    return frame(IDENTITIES_ANSWER, body)


def parse_sign_request(payload: bytes) -> tuple[bytes, bytes, int]:
    r = Reader(payload)
    blob = r.string()
    data = r.string()
    flags = r.u32() if not r.done else 0
    return blob, data, flags


def classify_sign_data(data: bytes) -> dict:
    """Work out what a signature is for: SSH user authentication, an SSHSIG
    (git commit/tag or file signature) or something else."""
    if data.startswith(b"SSHSIG"):
        try:
            r = Reader(data[6:])
            ns = r.string().decode("utf-8", "replace")
            r.string()  # reserved
            hash_alg = r.string().decode("ascii", "replace")
            return {"kind": "sshsig", "namespace": ns, "hash": hash_alg}
        except WireError:
            return {"kind": "unknown"}
    try:
        r = Reader(data)
        session_id = r.string()
        if r.u8() != USERAUTH_REQUEST:
            return {"kind": "unknown"}
        user = r.string().decode("utf-8", "replace")
        service = r.string().decode("utf-8", "replace")
        method = r.string().decode("ascii", "replace")
        if not method.startswith("publickey"):
            return {"kind": "unknown"}
        r.boolean()
        r.string()  # algorithm
        r.string()  # public key
        out = {"kind": "ssh-auth", "user": user, "service": service, "session_id": session_id,
               "hostbound": False}
        if method == "publickey-hostbound-v00@openssh.com":
            out["hostkey"] = r.string()
            out["hostbound"] = True
        return out
    except WireError:
        return {"kind": "unknown"}


def parse_extension(payload: bytes) -> tuple[bytes, bytes]:
    r = Reader(payload)
    name = r.string()
    return name, r.rest()


def parse_session_bind(body: bytes) -> dict:
    r = Reader(body)
    hostkey = r.string()
    session_id = r.string()
    r.string()  # signature, verified by the upstream agent
    forwarding = r.boolean()
    return {"hostkey": hostkey, "session_id": session_id, "forwarding": forwarding}


def build_session_bind(hostkey: bytes, session_id: bytes, signature: bytes, forwarding: bool) -> bytes:
    body = string(SESSION_BIND) + string(hostkey) + string(session_id) + string(signature) + bytes([1 if forwarding else 0])
    return frame(EXTENSION, body)


def build_sign_request(blob: bytes, data: bytes, flags: int = 0) -> bytes:
    return frame(SIGN_REQUEST, string(blob) + string(data) + u32(flags))


def build_userauth_data(session_id: bytes, user: str, alg: str, blob: bytes, hostkey: bytes | None = None) -> bytes:
    method = "publickey-hostbound-v00@openssh.com" if hostkey else "publickey"
    out = string(session_id) + bytes([USERAUTH_REQUEST]) + string(user) + string("ssh-connection") + string(method)
    out += b"\x01" + string(alg) + string(blob)
    if hostkey:
        out += string(hostkey)
    return out


def blob_from_openssh_line(line: str) -> bytes:
    parts = line.split()
    for p in parts:
        if p.startswith("AAAA"):
            return base64.b64decode(p)
    raise WireError("no key blob in line")
