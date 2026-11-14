"""sshleash command line."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys

from . import __version__, audit as audit_mod, wire
from .hosts import HostDB
from .policy import DEFAULT_PATH, STARTER, Context, PolicyError, load
from .proxy import Leash, Logger, format_event, serve

DEFAULT_SOCKET = "~/.ssh/sshleash.sock"
DEFAULT_LOG = "~/.local/state/sshleash/log.jsonl"
SSH_CONFIGS = ["~/.ssh/config", "/etc/ssh/ssh_config"]

C = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m", "end": "\033[0m",
     "bold": "\033[1m", "green": "\033[32m"}


def _use_color(json_out=False) -> bool:
    if json_out or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))


def _c(name, text, on):
    return f"{C[name]}{text}{C['end']}" if on else text


def cmd_init(a) -> int:
    path = os.path.expanduser(a.policy or DEFAULT_PATH)
    if os.path.exists(path) and not a.force:
        print(f"policy already exists: {path} (use --force to overwrite)")
    else:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(STARTER)
        print(f"wrote starter policy: {path}")
    sock = DEFAULT_SOCKET
    print(f"""
Next steps
  1. Start the leash in front of your current agent (keep it running, or use a user service):
       sshleash run &
  2. Forward the filtered socket instead of your real agent. In ~/.ssh/config:
       Host devbox
         ForwardAgent {sock}
  3. Hand the filtered socket to programs you don't fully trust:
       SSH_AUTH_SOCK={sock} codex      # or: export SSH_AUTH_SOCK={sock}
  4. Check what is still exposed:
       sshleash audit""")
    return 0


def _hostdb(policy, configs, extra_known_hosts=()) -> HostDB:
    db = HostDB()
    db.load_default()
    for kh in extra_known_hosts:
        db.load_known_hosts(kh)
    cfg = audit_mod.SSHConfig()
    for p in configs:
        audit_mod.parse_ssh_config(p, cfg)
    db.add_candidates(cfg.hostnames)
    db.add_candidates(policy.host_names())
    return db


def cmd_run(a) -> int:
    upstream = a.upstream or os.environ.get("SSH_AUTH_SOCK")
    socket_path = os.path.expanduser(a.socket)
    if not upstream:
        print("sshleash: no upstream agent (set SSH_AUTH_SOCK or pass --upstream)", file=sys.stderr)
        return 2
    upstream = os.path.expanduser(upstream)
    if os.path.abspath(upstream) == os.path.abspath(socket_path):
        print("sshleash: upstream is the sshleash socket itself; pass --upstream with your real agent",
              file=sys.stderr)
        return 2
    try:
        policy = load(a.policy)
    except PolicyError as e:
        print(f"sshleash: {e}", file=sys.stderr)
        return 2
    logger = Logger(None if a.no_log else a.log, quiet=a.quiet)
    leash = Leash(upstream, policy, _hostdb(policy, SSH_CONFIGS, a.known_hosts or ()), logger)
    print(f"sshleash {__version__}: filtering {upstream}\n  policy: {policy.path}\n  socket: {socket_path}\n"
          f"  use it: export SSH_AUTH_SOCK={socket_path}   or   ForwardAgent {socket_path}", file=sys.stderr, flush=True)

    async def main():
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        await serve(socket_path, leash, stop=stop)

    asyncio.run(main())
    return 0


def cmd_audit(a) -> int:
    color = _use_color(a.json)
    configs = a.config or SSH_CONFIGS
    res = audit_mod.run(configs, dict(os.environ), a.socket, processes=not a.no_processes)
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        print(_c("bold", "sshleash audit", color) + f"  (ssh config: {', '.join(res['files']) or 'none found'})")
        if res["keys"]:
            print(f"\nKeys in the agent ({len(res['keys'])}):")
            for k in res["keys"]:
                hw = "  hardware (touch)" if k["hardware"] else ""
                print(f"  {k['type']:<10} {k['fingerprint']}  {k['comment']}{hw}")
        print()
        if not res["findings"]:
            print(_c("green", "No findings.", color))
        for f in res["findings"]:
            sev = _c(f["severity"], f"{f['severity'].upper():<6}", color)
            print(f"{sev} {f['message']}")
            if f["where"]:
                print(f"       at {f['where']}")
            if f["fix"]:
                print(f"       fix: {f['fix']}")
    worst = min((audit_mod.SEV_ORDER[f["severity"]] for f in res["findings"]), default=9)
    threshold = audit_mod.SEV_ORDER.get(a.fail_on, 9) if a.fail_on != "never" else -1
    return 1 if worst <= threshold else 0


def cmd_explain(a) -> int:
    try:
        policy = load(a.policy)
    except PolicyError as e:
        print(f"sshleash: {e}", file=sys.stderr)
        return 2
    ctx = Context(key_fp=a.key if a.key.startswith("SHA256:") else "", key_comment="" if a.key.startswith("SHA256:") else a.key,
                  hosts=[a.host] if a.host else [], forwarded=a.forwarded or bool(a.via),
                  via=[a.via] if a.via else [], processes=a.process or [], kind=a.kind,
                  namespace=a.namespace or "")
    action, rule = policy.decide(ctx)
    visible, vrule = policy.visible(ctx)
    color = _use_color()
    label = {"allow": "green", "deny": "high", "confirm": "medium"}[action]
    print(f"{_c(label, action.upper(), color)}  (rule: {rule})")
    if not visible:
        print(f"key hidden from this connection (rule: {vrule})")
    print(f"policy: {policy.path}")
    return 0 if action == "allow" else 1


def cmd_log(a) -> int:
    path = os.path.expanduser(a.log)
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        print(f"no log at {path}")
        return 0
    events = [json.loads(x) for x in lines if x.strip()]
    if a.deny:
        events = [e for e in events if e.get("decision") == "deny"]
    color = _use_color(a.json)
    for e in events[-a.n:]:
        if a.json:
            print(json.dumps(e))
            continue
        line = format_event(e)
        if color:
            line = line.replace(" DENY ", " " + _c("high", "DENY", True) + " ", 1)
            line = line.replace(" ALLOW ", " " + _c("green", "ALLOW", True) + " ", 1)
        print(line)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sshleash", description="An SSH agent firewall: forwarded agents, sandboxes "
                                "and AI tools only get the keys and hosts your policy allows.")
    p.add_argument("--version", action="version", version=f"sshleash {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="write a starter policy and print setup steps")
    s.add_argument("--policy")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("run", help="run the filtering agent in the foreground")
    s.add_argument("--socket", default=DEFAULT_SOCKET, help=f"socket to listen on (default {DEFAULT_SOCKET})")
    s.add_argument("--upstream", help="real agent socket (default: $SSH_AUTH_SOCK)")
    s.add_argument("--policy", help=f"policy file (default {DEFAULT_PATH}, or the starter policy)")
    s.add_argument("--log", default=DEFAULT_LOG)
    s.add_argument("--known-hosts", action="append", help="extra known_hosts file used to name hosts (repeatable)")
    s.add_argument("--no-log", action="store_true", help="don't write the JSON log file")
    s.add_argument("-q", "--quiet", action="store_true", help="don't print decisions to stderr")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("audit", help="find agent forwarding and programs that can use your keys")
    s.add_argument("--config", action="append", help="ssh config file(s) to check (default ~/.ssh/config + system)")
    s.add_argument("--socket", default=DEFAULT_SOCKET)
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-processes", action="store_true", help="skip the running-process scan")
    s.add_argument("--fail-on", default="high", choices=["high", "medium", "low", "info", "never"])
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("explain", help="dry-run the policy for a request")
    s.add_argument("--policy")
    s.add_argument("--key", default="", help="key comment or SHA256 fingerprint")
    s.add_argument("--host", help="destination host")
    s.add_argument("--forwarded", action="store_true")
    s.add_argument("--via", help="host the agent was forwarded to (implies --forwarded)")
    s.add_argument("--process", action="append", help="requesting program (repeat for parents)")
    s.add_argument("--kind", default="ssh-auth", choices=["ssh-auth", "sshsig", "unknown"])
    s.add_argument("--namespace")
    s.set_defaults(func=cmd_explain)

    s = sub.add_parser("log", help="show recent decisions")
    s.add_argument("--log", default=DEFAULT_LOG)
    s.add_argument("-n", type=int, default=20)
    s.add_argument("--deny", action="store_true", help="only denied requests")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_log)

    a = p.parse_args(argv)
    try:
        return a.func(a)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
