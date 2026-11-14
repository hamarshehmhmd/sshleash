"""The filtering agent: listens on its own socket and relays allowed requests
to the real ssh-agent."""
from __future__ import annotations

import asyncio
import itertools
import json
import os
import stat
import sys
import time
from dataclasses import dataclass, field

from . import confirm as confirm_mod
from . import peer as peer_mod
from . import wire
from .hosts import HostDB
from .policy import Context, Policy

_ids = itertools.count(1)


@dataclass
class Bind:
    hostkey: bytes
    session_id: bytes
    forwarding: bool
    verified: bool


@dataclass
class Conn:
    id: int
    peer: dict
    binds: list = field(default_factory=list)
    comments: dict = field(default_factory=dict)

    @property
    def forwarded(self) -> bool:
        # The first bind on a connection comes from the local ssh client; it
        # sets forwarding=1 when the connection is a forwarded agent channel.
        return bool(self.binds) and self.binds[0].forwarding

    def via_keys(self) -> list[bytes]:
        return [b.hostkey for b in self.binds if b.forwarding]


async def read_message(reader: asyncio.StreamReader) -> bytes | None:
    try:
        head = await reader.readexactly(4)
    except (asyncio.IncompleteReadError, ConnectionError):
        return None
    n = int.from_bytes(head, "big")
    if n == 0 or n > wire.MAX_MESSAGE:
        return None
    try:
        return await reader.readexactly(n)
    except (asyncio.IncompleteReadError, ConnectionError):
        return None


class Logger:
    def __init__(self, path: str | None, stream=sys.stderr, quiet: bool = False):
        self.path = os.path.expanduser(path) if path else None
        self.stream = stream
        self.quiet = quiet
        if self.path:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)

    def emit(self, event: dict) -> None:
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
        if self.path:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        if not self.quiet and self.stream:
            print(format_event(event), file=self.stream, flush=True)


def format_event(e: dict) -> str:
    t = e.get("ts", "")[11:19]
    decision = e.get("decision", "").upper()
    op = e.get("op", "")
    if op == "sign":
        what = {"ssh-auth": "login", "sshsig": f"sshsig[{e.get('namespace', '')}]"}.get(e.get("kind"), "sign")
        user = f"{e['user']}@" if e.get("user") else ""
        dest = e.get("host") or "unknown host"
        target = "" if e.get("kind") == "sshsig" else f" {user}{dest}"
        line = f"{t} {decision:<7} {what}{target} with {e.get('key', '?')}"
    elif op == "list":
        line = f"{t} {decision:<7} list keys: showed {e.get('shown', 0)}, hid {e.get('hidden', 0)}"
    else:
        line = f"{t} {decision:<7} {op}"
    if e.get("forwarded"):
        line += f"  via forwarded agent on {e.get('via') or 'unknown host'}"
    p = e.get("process") or {}
    if p.get("pid"):
        chain = " < ".join([p.get("name", "?")] + (p.get("parents") or [])[:3])
        line += f"  by {chain} (pid {p['pid']})"
    if e.get("rule"):
        line += f"  [{e['rule']}]"
    if e.get("reason"):
        line += f"  {e['reason']}"
    return line


class Leash:
    def __init__(self, upstream: str, policy: Policy, hosts: HostDB, logger: Logger):
        self.upstream = upstream
        self.policy = policy
        self.hosts = hosts
        self.log = logger
        self.remembered: dict[tuple, float] = {}
        self.comments: dict[bytes, str] = {}
        self._confirm_lock = asyncio.Lock()

    # -- context helpers -------------------------------------------------
    def _base_ctx(self, conn: Conn) -> Context:
        via = []
        for hk in conn.via_keys():
            names = self.hosts.lookup(hk)
            via.extend(names or [wire.fingerprint(hk)])
        return Context(forwarded=conn.forwarded, via=via, processes=peer_mod.names(conn.peer))

    def _event_base(self, conn: Conn, ctx: Context) -> dict:
        return {"conn": conn.id, "forwarded": ctx.forwarded, "via": ",".join(ctx.via),
                "process": conn.peer}

    def _destination(self, conn: Conn, info: dict) -> tuple[bytes | None, bool]:
        if info.get("hostkey"):
            return info["hostkey"], True
        sid = info.get("session_id")
        if sid:
            for i in range(len(conn.binds) - 1, -1, -1):
                b = conn.binds[i]
                if b.session_id != sid:
                    continue
                # On a forwarded channel only the first bind comes from our own
                # ssh client; later ones come from the remote machine and are
                # only believed if the real agent verified their signature.
                if conn.forwarded and i > 0 and not b.verified:
                    return None, False
                return b.hostkey, b.verified or i == 0
        return None, False

    # -- request handlers --------------------------------------------------
    async def _relay(self, up_r, up_w, msg: bytes) -> bytes | None:
        up_w.write(len(msg).to_bytes(4, "big") + msg)
        await up_w.drain()
        return await read_message(up_r)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        conn = Conn(id=next(_ids), peer=peer_mod.process_info(peer_mod.peer_pid(sock)))
        try:
            up_r, up_w = await asyncio.open_unix_connection(self.upstream)
        except OSError as e:
            self.log.emit({"op": "connect", "decision": "error", "reason": f"upstream agent: {e}", "conn": conn.id})
            writer.close()
            return
        try:
            while True:
                msg = await read_message(reader)
                if msg is None:
                    break
                reply = await self.dispatch(conn, msg, up_r, up_w)
                if reply is None:
                    break
                writer.write(len(reply).to_bytes(4, "big") + reply)
                await writer.drain()
        except (ConnectionError, wire.WireError):
            pass
        finally:
            up_w.close()
            writer.close()

    async def dispatch(self, conn: Conn, msg: bytes, up_r, up_w) -> bytes | None:
        t, payload = msg[0], msg[1:]
        failure = bytes([wire.FAILURE])
        if t == wire.REQUEST_IDENTITIES:
            return await self._identities(conn, msg, up_r, up_w)
        if t == wire.SIGN_REQUEST:
            return await self._sign(conn, msg, payload, up_r, up_w)
        if t == wire.EXTENSION:
            name, body = wire.parse_extension(payload)
            reply = await self._relay(up_r, up_w, msg)
            if reply is None:
                return None
            if name == wire.SESSION_BIND:
                b = wire.parse_session_bind(body)
                conn.binds.append(Bind(b["hostkey"], b["session_id"], b["forwarding"], reply[:1] == bytes([wire.SUCCESS])))
            return reply
        if t in wire.MANAGEMENT:
            ctx = self._base_ctx(conn)
            op = wire.MANAGEMENT[t]
            if conn.forwarded and not self.policy.allow_forwarded_management:
                self.log.emit({**self._event_base(conn, ctx), "op": op, "decision": "deny",
                               "reason": "key management from a forwarded agent is off (allow_forwarded_management)"})
                return failure
            reply = await self._relay(up_r, up_w, msg)
            self.log.emit({**self._event_base(conn, ctx), "op": op,
                           "decision": "allow" if reply and reply[:1] == bytes([wire.SUCCESS]) else "failed"})
            return reply
        return await self._relay(up_r, up_w, msg)

    async def _identities(self, conn, msg, up_r, up_w):
        reply = await self._relay(up_r, up_w, msg)
        if not reply or reply[0] != wire.IDENTITIES_ANSWER:
            return reply
        keys = wire.parse_identities(reply[1:])
        base = self._base_ctx(conn)
        shown, hidden = [], []
        for blob, comment in keys:
            conn.comments[blob] = comment
            self.comments[blob] = comment
            ctx = Context(**{**base.__dict__, "key_fp": wire.fingerprint(blob), "key_comment": comment})
            ok, _rule = self.policy.visible(ctx)
            (shown if ok else hidden).append((blob, comment))
        if hidden or conn.forwarded:
            self.log.emit({**self._event_base(conn, base), "op": "list", "decision": "allow",
                           "shown": len(shown), "hidden": len(hidden),
                           "hidden_keys": [c or wire.fingerprint(b) for b, c in hidden]})
        return wire.build_identities(shown)[4:]

    async def _sign(self, conn, msg, payload, up_r, up_w):
        blob, data, _flags = wire.parse_sign_request(payload)
        info = wire.classify_sign_data(data)
        dest_key, verified = self._destination(conn, info)
        hosts = self.hosts.lookup(dest_key) if dest_key else []
        if dest_key and not hosts:
            hosts = [wire.fingerprint(dest_key)]
        ctx = self._base_ctx(conn)
        ctx.key_fp = wire.fingerprint(blob)
        ctx.key_comment = conn.comments.get(blob) or self.comments.get(blob) or await self._lookup_comment(blob)
        ctx.hosts = hosts
        ctx.kind = info["kind"]
        ctx.namespace = info.get("namespace", "")
        action, rule = self.policy.decide(ctx)
        key_label = f"{ctx.key_comment or '(no comment)'} {wire.short_type(blob)} {ctx.key_fp}"
        event = {**self._event_base(conn, ctx), "op": "sign", "kind": ctx.kind, "key": key_label,
                 "key_fp": ctx.key_fp, "host": ",".join(hosts), "host_verified": verified,
                 "user": info.get("user", ""), "namespace": ctx.namespace, "rule": rule}
        reason = ""
        if action == "confirm":
            remember_key = (ctx.key_fp, tuple(hosts), tuple(ctx.processes[:1]), ctx.forwarded, tuple(ctx.via))
            if self.remembered.get(remember_key, 0) > time.monotonic():
                action, reason = "allow", "remembered approval"
            else:
                prompt = self.prompt(ctx, info)
                async with self._confirm_lock:
                    ok, reason = await confirm_mod.ask(prompt, self.policy.confirm, self.policy.confirm_timeout)
                action = "allow" if ok else "deny"
                if ok and self.policy.remember > 0:
                    self.remembered[remember_key] = time.monotonic() + self.policy.remember
            event["confirmed"] = True
        if action == "deny":
            self.log.emit({**event, "decision": "deny", "reason": reason})
            return bytes([wire.FAILURE])
        reply = await self._relay(up_r, up_w, msg)
        ok = bool(reply) and reply[0] == wire.SIGN_RESPONSE
        self.log.emit({**event, "decision": "allow" if ok else "failed", "reason": reason})
        return reply

    async def _lookup_comment(self, blob: bytes) -> str:
        """A client may sign without listing keys first; ask the real agent."""
        try:
            r, w = await asyncio.open_unix_connection(self.upstream)
        except OSError:
            return ""
        try:
            reply = await self._relay(r, w, bytes([wire.REQUEST_IDENTITIES]))
            if reply and reply[0] == wire.IDENTITIES_ANSWER:
                for b, c in wire.parse_identities(reply[1:]):
                    self.comments[b] = c
        except (OSError, wire.WireError):
            pass
        finally:
            w.close()
        return self.comments.get(blob, "")

    def prompt(self, ctx: Context, info: dict) -> str:
        what = {"ssh-auth": "log in to", "sshsig": f"make a '{ctx.namespace}' signature"}.get(ctx.kind, "sign data")
        dest = ",".join(ctx.hosts) or "an unknown host"
        lines = [f"Allow key '{ctx.key_comment or ctx.key_fp}' to {what}"
                 + (f" {info.get('user', '')}@{dest}" if ctx.kind == "ssh-auth" else "") + "?"]
        if ctx.forwarded:
            lines.append(f"Requested through a FORWARDED agent on {', '.join(ctx.via) or 'an unknown host'}.")
        if ctx.processes:
            lines.append("Program: " + " < ".join(ctx.processes[:4]))
        return "\n".join(lines)


def _prepare_socket(path: str) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, mode=0o700, exist_ok=True)
    if os.path.exists(path):
        if stat.S_ISSOCK(os.stat(path).st_mode):
            os.unlink(path)
        else:
            raise SystemExit(f"sshleash: {path} exists and is not a socket")


async def serve(socket_path: str, leash: Leash, ready: asyncio.Event | None = None,
                stop: asyncio.Event | None = None) -> None:
    _prepare_socket(socket_path)
    old = os.umask(0o177)
    try:
        server = await asyncio.start_unix_server(leash.handle, path=socket_path)
    finally:
        os.umask(old)
    os.chmod(socket_path, 0o600)
    if ready:
        ready.set()
    async with server:
        if stop:
            await stop.wait()
        else:
            await server.serve_forever()
    try:
        os.unlink(socket_path)
    except OSError:
        pass
