"""Policy: an ordered list of rules, first match wins."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

ACTIONS = ("allow", "deny", "confirm")
KINDS = ("ssh-auth", "sshsig", "unknown")
LIST_FIELDS = ("key", "host", "via", "process", "kind", "namespace")
REQUEST_FIELDS = ("host", "kind", "namespace")  # only known once a signature is requested

DEFAULT_PATH = "~/.config/sshleash/policy.toml"

STARTER = '''# sshleash policy. Rules are checked top to bottom; the first match wins.
#
# Match fields (all optional, all must match):
#   key       = ["work*", "SHA256:..."]   key comment or fingerprint (globs)
#   host      = ["github.com", "*.corp"]  where the signature will be used ("unknown" if sshleash can't tell)
#   forwarded = true                      request came through a forwarded agent (ssh -A, ForwardAgent)
#   via       = ["devbox*"]               the machine(s) the agent was forwarded to
#   process   = ["codex*", "sbx"]         the local program asking, or any of its parent programs
#   kind      = ["ssh-auth"]              ssh-auth (logins, git over ssh), sshsig (git commit/tag signing), unknown
#   namespace = ["git"]                   SSHSIG namespace
# action = "allow" | "deny" | "confirm"   (confirm pops up a yes/no dialog; no dialog program = deny)
#
# A rule that only uses key/forwarded/via/process and says "deny" also hides the key
# from that connection's key list (ssh-add -l doesn't show it), unless an earlier
# rule could still allow or confirm a request with that key.

[settings]
confirm = "auto"        # auto | ssh-askpass | zenity | kdialog | osascript | "/path/to/command"
confirm_timeout = 30    # seconds; no answer = deny
remember = 0            # seconds to remember a "yes" for the same key + host + program
allow_forwarded_management = false   # let forwarded agents add/remove keys or lock the agent

[[rule]]
name = "forwarded agents must ask"
forwarded = true
action = "confirm"

[[rule]]
name = "sandboxes and AI apps must ask"
process = ["sbx", "com.docker.*", "ChatGPT*", "codex*", "claude*", "Claude*", "cursor*", "Cursor*"]
action = "confirm"

[default]
action = "allow"
'''


class PolicyError(ValueError):
    pass


def _as_list(v, name):
    if v is None:
        return None
    if isinstance(v, str):
        return [v]
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return v
    raise PolicyError(f"{name} must be a string or a list of strings")


@dataclass
class Rule:
    name: str
    action: str
    key: list | None = None
    host: list | None = None
    via: list | None = None
    process: list | None = None
    kind: list | None = None
    namespace: list | None = None
    forwarded: bool | None = None

    @property
    def connection_level(self) -> bool:
        return all(getattr(self, f) is None for f in REQUEST_FIELDS)


@dataclass
class Context:
    key_fp: str = ""
    key_comment: str = ""
    hosts: list = field(default_factory=list)       # destination names; [] = unknown
    forwarded: bool = False
    via: list = field(default_factory=list)          # names of forwarding hops
    processes: list = field(default_factory=list)    # requesting program and its parents
    kind: str = "unknown"
    namespace: str = ""


def _any(patterns, values) -> bool:
    return any(fnmatchcase(v, p) for p in patterns for v in values)


def _names_or_unknown(values):
    return values if values else ["unknown"]


def matches_connection(rule: Rule, ctx: Context) -> bool:
    if rule.key is not None and not _any(rule.key, [ctx.key_fp, ctx.key_comment]):
        return False
    if rule.forwarded is not None and rule.forwarded != ctx.forwarded:
        return False
    if rule.via is not None and not _any(rule.via, _names_or_unknown(ctx.via)):
        return False
    if rule.process is not None and not _any(rule.process, ctx.processes or ["unknown"]):
        return False
    return True


def matches(rule: Rule, ctx: Context) -> bool:
    if not matches_connection(rule, ctx):
        return False
    if rule.host is not None and not _any(rule.host, _names_or_unknown(ctx.hosts)):
        return False
    if rule.kind is not None and ctx.kind not in rule.kind:
        return False
    if rule.namespace is not None and not _any(rule.namespace, [ctx.namespace or ""]):
        return False
    return True


@dataclass
class Policy:
    rules: list = field(default_factory=list)
    default: str = "allow"
    confirm: str = "auto"
    confirm_timeout: float = 30.0
    remember: float = 0.0
    allow_forwarded_management: bool = False
    path: str | None = None

    def decide(self, ctx: Context) -> tuple[str, str]:
        for r in self.rules:
            if matches(r, ctx):
                return r.action, r.name
        return self.default, "default"

    def visible(self, ctx: Context) -> tuple[bool, str]:
        """Should this key be listed to this connection at all?

        Hidden only when a connection-level rule (no host/kind/namespace) says
        deny before any rule that could still allow a request with this key."""
        for r in self.rules:
            if not matches_connection(r, ctx):
                continue
            if r.connection_level:
                return r.action != "deny", r.name
            if r.action != "deny":
                return True, r.name
        return True, "default"

    def host_names(self) -> set[str]:
        out = set()
        for r in self.rules:
            for f in ("host", "via"):
                out.update(getattr(r, f) or [])
        return out


def parse(text: str, path: str | None = None) -> Policy:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"{path or 'policy'}: {e}") from None
    unknown_top = set(data) - {"settings", "rule", "default"}
    if unknown_top:
        raise PolicyError(f"unknown section(s): {', '.join(sorted(unknown_top))}")
    s = data.get("settings", {})
    pol = Policy(path=path)
    pol.confirm = str(s.get("confirm", "auto"))
    pol.confirm_timeout = float(s.get("confirm_timeout", 30))
    pol.remember = float(s.get("remember", 0))
    pol.allow_forwarded_management = bool(s.get("allow_forwarded_management", False))
    pol.default = data.get("default", {}).get("action", "allow")
    if pol.default not in ACTIONS:
        raise PolicyError(f"default action must be one of {ACTIONS}")
    for i, raw in enumerate(data.get("rule", []), 1):
        extra = set(raw) - set(LIST_FIELDS) - {"name", "action", "forwarded"}
        if extra:
            raise PolicyError(f"rule {i}: unknown field(s) {', '.join(sorted(extra))}")
        action = raw.get("action")
        if action not in ACTIONS:
            raise PolicyError(f"rule {i}: action must be one of {ACTIONS}")
        rule = Rule(name=str(raw.get("name", f"rule {i}")), action=action)
        for f in LIST_FIELDS:
            setattr(rule, f, _as_list(raw.get(f), f"rule {i}: {f}"))
        if rule.kind:
            bad = [k for k in rule.kind if k not in KINDS]
            if bad:
                raise PolicyError(f"rule {i}: unknown kind {bad}; use {KINDS}")
        if "forwarded" in raw:
            if not isinstance(raw["forwarded"], bool):
                raise PolicyError(f"rule {i}: forwarded must be true or false")
            rule.forwarded = raw["forwarded"]
        pol.rules.append(rule)
    return pol


def load(path: str | None = None) -> Policy:
    p = os.path.expanduser(path or os.environ.get("SSHLEASH_POLICY") or DEFAULT_PATH)
    if not os.path.exists(p):
        if path:
            raise PolicyError(f"policy file not found: {p}")
        pol = parse(STARTER, path="(built-in starter policy)")
        return pol
    with open(p, encoding="utf-8") as f:
        return parse(f.read(), path=p)
