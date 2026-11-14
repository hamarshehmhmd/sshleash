"""Ask a human: yes/no dialog through ssh-askpass, zenity, kdialog or osascript."""
from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import sys


def find_program(setting: str) -> list[str] | None:
    s = (setting or "auto").strip()
    if s not in ("auto", "ssh-askpass", "zenity", "kdialog", "osascript"):
        return shlex.split(s)
    if s in ("auto", "ssh-askpass"):
        askpass = os.environ.get("SSH_ASKPASS")
        if askpass and shutil.which(askpass):
            return ["@askpass", askpass]
        for cand in ("ssh-askpass", "/usr/lib/ssh/ssh-askpass", "/usr/libexec/openssh/ssh-askpass"):
            if shutil.which(cand):
                return ["@askpass", cand]
        if s != "auto":
            return None
    if s in ("auto", "zenity") and shutil.which("zenity") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return ["@zenity"]
    if s in ("auto", "kdialog") and shutil.which("kdialog") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return ["@kdialog"]
    if s in ("auto", "osascript") and sys.platform == "darwin" and shutil.which("osascript"):
        return ["@osascript"]
    return None


def _argv(prog: list[str], prompt: str, timeout: float) -> tuple[list[str], str | None]:
    kind = prog[0]
    if kind == "@askpass":
        return [prog[1], prompt], None
    if kind == "@zenity":
        return ["zenity", "--question", "--title=sshleash", f"--timeout={int(timeout)}", "--ok-label=Allow",
                "--cancel-label=Deny", "--text", prompt], None
    if kind == "@kdialog":
        return ["kdialog", "--title", "sshleash", "--yesno", prompt], None
    if kind == "@osascript":
        esc = prompt.replace("\\", "\\\\").replace('"', '\\"')
        script = (f'display dialog "{esc}" with title "sshleash" buttons {{"Deny", "Allow"}} '
                  f'default button "Deny" giving up after {int(timeout)}')
        return ["osascript", "-e", script], "button returned:Allow"
    return prog + [prompt], None


async def ask(prompt: str, setting: str, timeout: float) -> tuple[bool, str]:
    prog = find_program(setting)
    if not prog:
        return False, "no confirm program available (set settings.confirm)"
    argv, needle = _argv(prog, prompt, timeout)
    env = dict(os.environ, SSH_ASKPASS_PROMPT="confirm", SSHLEASH_PROMPT=prompt)
    try:
        proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.DEVNULL,
                                                    stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.DEVNULL, env=env)
    except OSError as e:
        return False, f"confirm program failed to start: {e}"
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return False, f"no answer within {int(timeout)}s"
    if needle is not None:
        ok = needle in out.decode(errors="replace")
    else:
        ok = proc.returncode == 0
    return ok, "approved by user" if ok else "refused by user"
