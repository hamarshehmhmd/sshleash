"""Render the sshleash narrated demo: real command output + edge-tts narration.

Local scenes run the real commands in a throwaway HOME (/tmp/slhome) with a real
ssh-agent. The two-hop scenes replay demo/captured/twohop.txt, the transcript of
demo/twohop.sh recorded by the CI e2e job on a GitHub runner with two real sshd servers.

Usage: python demo/render.py [scene numbers]   (needs ffmpeg, edge-tts, Pillow, OpenSSH)
"""
import asyncio
import os
import re
import shutil
import subprocess
import sys
import time

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.join(HERE, "build")
OUT = os.path.join(ROOT, "demo.mp4")
SDKBIN = os.path.join(ROOT, ".venv", "bin")
DEMO = ROOT
FAKEHOME = "/tmp/slhome"
W, H, FPS = 1280, 720, 24
VOICE = "en-US-AndrewNeural"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BG, FG = (24, 26, 33), (220, 223, 228)
ANSI = {"31": (255, 95, 95), "32": (95, 215, 120), "33": (240, 200, 80),
        "2": (130, 135, 145), "36": (90, 200, 230), "35": (200, 140, 230), "1": FG}
PROMPT = "me@laptop ~ $ "
CI_PROMPT = "runner@ci-laptop ~ $ "
TITLEBAR = "laptop — bash"
REPLAY = {}


def load_replay():
    path = os.path.join(HERE, "captured", "twohop.txt")
    cur, buf = None, []
    for line in open(path).read().splitlines():
        if line.startswith("$ "):
            if cur is not None:
                REPLAY[cur] = "\n".join(buf).rstrip("\n")
            cur, buf = line[2:], []
        else:
            buf.append(line)
    if cur is not None:
        REPLAY[cur] = "\n".join(buf).rstrip("\n")
    # colour the decisions like the live terminal does
    for k, v in REPLAY.items():
        v = re.sub(r"(\d\d:\d\d:\d\d )DENY ", "\\1\x1b[31mDENY\x1b[0m ", v)
        v = re.sub(r"(\d\d:\d\d:\d\d )ALLOW", "\\1\x1b[32mALLOW\x1b[0m", v)
        REPLAY[k] = v


SCENES = [
    {
        "kind": "title",
        "title": "sshleash",
        "sub": "an SSH agent firewall\nforwarded agents · sandboxes · AI coding tools",
        "say": ("This is s s h leash, a small open source S S H agent firewall. It sits in front of your s s h agent, "
                "so forwarded agents, sandboxes and A I coding tools only get the keys and hosts you allow."),
    },
    {
        "kind": "bullets",
        "title": "The problem",
        "bullets": [
            "ssh -A / ForwardAgent yes hands the remote your whole agent",
            "   root and every process there (AI agents too) can log in as you",
            "ChatGPT Desktop / Codex forwards your agent to remote machines (HN, Nov 2026)",
            "Docker sandboxes forwarded the host agent: a bot cloned private repos as you",
            "DevPod & co. write ForwardAgent yes into ~/.ssh/config",
            "A YubiKey blink doesn't say which host is asking",
        ],
        "say": ("Agent forwarding gives the remote machine your whole agent. Root there, and every process of your user, including an A I agent, can log in as you. And tools turn it on for you: ChatGPT Desktop, Docker sandboxes, dev container tools. Even a hardware key's blinking light doesn't say what you're approving."),
    },
    {
        "kind": "term",
        "cmds": ["sshleash audit --config examples/ssh_config --no-processes"],
        "say": ("Start with an audit. s s h leash audit reads your s s h config and your agent. Here, a wildcard "
                "host forwards the agent to every lab machine, a dev box forwards it, and DevPod wrote its own "
                "forwarding block. And the agent itself is unfiltered, with two keys that work without a touch."),
    },
    {
        "kind": "term",
        "cmds": ["cat ~/.config/sshleash/policy.toml | grep -E '^(name|key|kind|forwarded|host|via|action)'",
                 "setsid sshleash run --quiet >/dev/null 2>&1 < /dev/null & sleep 1",
                 "export SSH_AUTH_SOCK=" + FAKEHOME + "/.ssh/sshleash.sock",
                 "ssh-keygen -Y sign -f ~/.ssh/deploy-bot.pub -n git ~/release.txt",
                 "ssh-keygen -Y sign -f ~/.ssh/laptop-key.pub -n git ~/release.txt",
                 "sshleash log -n 2"],
        "show": ["cat ~/.config/sshleash/policy.toml | grep -E '^(name|key|kind|forwarded|host|via|action)'",
                 "sshleash run --quiet &",
                 "export SSH_AUTH_SOCK=~/.ssh/sshleash.sock",
                 "ssh-keygen -Y sign -f ~/.ssh/deploy-bot.pub -n git ~/release.txt",
                 "ssh-keygen -Y sign -f ~/.ssh/laptop-key.pub -n git ~/release.txt",
                 "sshleash log -n 2"],
        "say": ('A policy is a list of rules, first match wins. Rules match the key, the destination host, forwarding, the local program asking, and the kind of signature. s s h leash run relays allowed requests to your real agent. Here the deploy key may not sign git commits, so that is refused, while the laptop key signs fine. Every decision is logged.'),
    },
    {
        "kind": "term", "replay": True, "titlebar": "GitHub Actions runner — real sshd servers",
        "prompt": CI_PROMPT,
        "cmds": ["grep -A1 'Host devbox' ~/.ssh/config | tail -2",
                 "ssh devbox 'echo on $(hostname -s)-as-devbox; ssh-add -l'",
                 "ssh devbox 'ssh gitserver echo hello from gitserver'"],
        "say": ('Now forwarding, recorded on a C I runner with two real s s h servers. The config forwards the s s h leash socket instead of the agent. On the dev box, s s h add only lists the laptop key; the deploy key is hidden. Then a login from the dev box to the git server, through the forwarded agent, is refused by the policy.'),
    },
    {
        "kind": "term", "replay": True, "titlebar": "GitHub Actions runner — real sshd servers",
        "prompt": CI_PROMPT,
        "cmds": ["sshleash log -n 6"],
        "say": ("The log shows why: the login came through the forwarded agent on dev box, headed for git server. s s h leash knows the destination because open s s h binds each agent connection to the server's host key, and the real agent verifies that signature, so a remote machine can't fake it."),
    },
    {
        "kind": "term",
        "cmds": ["sshleash explain --policy examples/policy.toml --key work --host github.com --via devbox",
                 "sshleash explain --policy examples/policy.toml --key work --host prod-db --via devbox",
                 "sshleash explain --policy examples/policy.toml --key work --host github.com --process git --process codex"],
        "say": ("You can dry run a policy with explain. In this example policy, a forwarded agent may reach GitHub "
                "after a pop up confirmation, anything else is denied, and a git push started by an A I coding "
                "agent is matched through its parent process. Confirm uses s s h askpass, zenity, k dialog or a "
                "mac O S dialog, and no answer means no."),
    },
    {
        "kind": "bullets",
        "title": "sshleash",
        "bullets": [
            "pipx install git+https://github.com/hamarshehmhmd/sshleash",
            "sshleash init  ·  sshleash run  ·  ForwardAgent ~/.ssh/sshleash.sock",
            "speaks the standard ssh-agent protocol (tested with OpenSSH ssh-agent)",
            "Linux + macOS · JSON log · audit exit codes for CI",
            "github.com/hamarshehmhmd/sshleash",
            "GNU AGPL-3.0-or-later (commercial licenses available)",
        ],
        "say": ("Install it with one pip x line, run s s h leash init, and forward the s s h leash socket instead of "
                "your agent. It speaks the standard agent protocol, is tested with open s s h's agent, and runs on Linux and mac O S. s s h leash is licensed under the "
                "GNU A G P L version 3 or later, with commercial licenses available from the author."),
    },
]
async def tts(text, path):
    import edge_tts
    for attempt in range(8):
        try:
            await edge_tts.Communicate(text, VOICE, rate="+4%").save(path)
            return
        except Exception:
            if os.path.exists(path):
                os.remove(path)
            if attempt == 7:
                raise
            await asyncio.sleep(5)


def duration(path):
    out = subprocess.check_output(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
        text=True,
    )
    return float(out.strip())


EXPORTS = {}


def run_cmd(cmd, cwd):
    if cmd.startswith("export ") and "=" in cmd:
        k, v = cmd[7:].split("=", 1)
        EXPORTS[k] = v
        return ""
    env = dict(os.environ, FORCE_COLOR="1", **EXPORTS)
    env.pop("NO_COLOR", None)
    env["PATH"] = os.pathsep.join([SDKBIN, env["PATH"]])
    env["COLUMNS"] = "120"
    p = subprocess.run(
        ["bash", "-c", "shopt -s nullglob; " + cmd],
        cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
    )
    return p.stdout.rstrip("\n")


def parse_ansi(line):
    spans, color, bold = [], FG, False
    for part in re.split(r"(\x1b\[[0-9;]*m)", line):
        m = re.match(r"\x1b\[([0-9;]*)m", part)
        if m:
            for code in (m.group(1) or "0").split(";"):
                if code == "0":
                    color, bold = FG, False
                elif code == "1":
                    bold = True
                elif code in ANSI:
                    color = ANSI[code]
        elif part:
            spans.append((part, color, bold))
    return spans


class Term:
    def __init__(self):
        self.font = ImageFont.truetype(MONO, 14)
        self.bold = ImageFont.truetype(MONO_B, 14)
        self.cw = self.font.getlength("M")
        self.lh = 20
        self.cols = int((W - 80) / self.cw)

    def wrap(self, spans):
        lines, cur, n = [], [], 0
        for text, c, b in spans:
            while text:
                room = self.cols - n
                if room <= 4:
                    lines.append(cur); cur, n = [], 0
                    text = "    " + text.lstrip(" ")
                    room = self.cols
                if len(text) <= room:
                    cur.append((text, c, b)); n += len(text); text = ""
                else:
                    cut = text.rfind(" ", 0, room + 1)
                    cut = cut if cut > 4 else room
                    cur.append((text[:cut], c, b)); lines.append(cur); cur, n = [], 0
                    text = "    " + text[cut:].lstrip(" ")
        lines.append(cur)
        return lines

    def frame(self, lines, cursor=False):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([20, 14, W - 20, H - 14], 12, fill=(30, 33, 41), outline=(60, 64, 76))
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([40 + i * 24, 30, 54 + i * 24, 44], fill=c)
        d.text((W // 2, 37), TITLEBAR, font=ImageFont.truetype(SANS, 15), fill=(150, 155, 165), anchor="mm")
        visible = lines[-30:]
        y = 64
        for ln in visible:
            x = 40
            for text, c, b in ln:
                d.text((x, y), text, font=self.bold if b else self.font, fill=c)
                x += self.cw * len(text)
            y += self.lh
        if cursor:
            last = visible[-1] if visible else []
            x = 40 + self.cw * sum(len(t) for t, _, _ in last)
            d.rectangle([x, y - self.lh + 3, x + self.cw - 2, y - 4], fill=FG)
        return img


def card(scene):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    if scene["kind"] == "title":
        d.text((W // 2, 280), scene["title"], font=ImageFont.truetype(MONO_B, 78), fill=(95, 215, 120), anchor="mm")
        d.multiline_text((W // 2, 420), scene["sub"], font=ImageFont.truetype(SANS, 32), fill=FG, anchor="mm",
                         align="center", spacing=12)
        d.text((W // 2, 620), "github.com/hamarshehmhmd/sshleash  ·  run · audit · explain · log  ·  GNU AGPL-3.0",
               font=ImageFont.truetype(SANS, 20), fill=(150, 155, 165), anchor="mm")
    else:
        d.text((90, 90), scene["title"], font=ImageFont.truetype(SANS_B, 52), fill=(95, 215, 120))
        f = ImageFont.truetype(SANS, 29)
        y = 200
        for b in scene["bullets"]:
            if b and not b.startswith("   "):
                d.text((90, y), "•", font=f, fill=(240, 200, 80))
            d.text((130, y), b.strip(), font=f, fill=FG)
            y += 58 if b.startswith("   ") or not b else 62
    return img


class Writer:
    def __init__(self, path, audio):
        self.p = subprocess.Popen(
            ["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
             "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-", "-i", audio,
             "-af", "apad", "-c:v", "libx264", "-preset", "medium", "-crf", "23",
             "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", "-ar", "44100",
             "-shortest", path],
            stdin=subprocess.PIPE,
        )
        self.n = 0

    def put(self, img, count=1):
        data = img.tobytes()
        for _ in range(count):
            self.p.stdin.write(data)
        self.n += count

    def close(self):
        self.p.stdin.close()
        self.p.wait()
        if self.p.returncode:
            sys.exit("ffmpeg failed")


def _cap_output(out, tail=False):
    lines = out.splitlines()
    if tail and len(lines) > 26:
        return "\n".join(["…"] + lines[-25:])
    if len(lines) > 24:
        lines = lines[:22] + ["…", lines[-1]]
    return "\n".join(lines)


def render_scene(i, scene, workdir):
    audio = os.path.join(BUILD, f"s{i}.mp3")
    if not os.path.exists(audio):
        asyncio.run(tts(scene["say"], audio))
    total = int((duration(audio) + 0.7) * FPS)
    path = os.path.join(BUILD, f"s{i}.mp4")
    w = Writer(path, audio)
    if scene["kind"] != "term":
        w.put(card(scene), total)
        w.close()
        return path
    t = Term()
    shown = scene.get("show", scene["cmds"])
    wd = workdir
    if scene.get("replay"):
        outputs = [REPLAY[c] for c in scene["cmds"]]
    else:
        outputs = [run_cmd(c, wd) if scene.get("scroll") else _cap_output(run_cmd(c, wd), scene.get("tail")) for c in scene["cmds"]]
    # If show has more lines than cmds (a command displayed as several visual lines
    # that map to one executed command), join show into one typed command per output.
    if len(shown) != len(outputs):
        if len(outputs) == 1:
            shown = [" ".join(s.rstrip("\\").strip() for s in shown)]
        elif len(shown) > len(outputs):
            # first N-1 outputs map 1:1; remaining show lines are the last command
            shown = list(shown[: len(outputs) - 1]) + [
                " ".join(s.rstrip("\\").strip() for s in shown[len(outputs) - 1 :])
            ]
    steps = list(zip(shown, outputs))
    typing = sum(len(s) for s, _ in steps) / 32 * FPS
    pause = max(6, int((total - typing) / max(1, len(steps))) - 4)
    lines = []
    for cmd, out in steps:
        prompt = [(scene.get("prompt", PROMPT), (95, 215, 120), True)]
        for k in range(0, len(cmd) + 1, 2):
            frame = t.frame(lines + t.wrap(prompt + [(cmd[:k], FG, False)]), cursor=True)
            w.put(frame)
        lines += t.wrap(prompt + [(cmd, FG, False)])
        outl = []
        for ol in out.splitlines():
            outl += t.wrap(parse_ansi(ol))
        hold = min(pause, max(0, total - w.n))
        if scene.get("scroll") and len(outl) > 28:
            # reveal the output gradually so the narration can walk through it
            reveal = int(hold * scene.get("reveal", 0.8))
            for f in range(reveal):
                k = 28 + int((len(outl) - 28) * (f + 1) / reveal)
                w.put(t.frame(lines + outl[:k]))
            hold -= reveal
        lines += outl
        lines.append([])
        w.put(t.frame(lines), max(0, hold))
    final = t.frame(lines + t.wrap([(scene.get("prompt", PROMPT), (95, 215, 120), True)]), cursor=True)
    if w.n < total:
        w.put(final, total - w.n)
    w.close()
    return path






def setup():
    load_replay()
    subprocess.run(["pkill", "-f", "sshleash run"], check=False)
    subprocess.run(["pkill", "-f", f"ssh-agent -a {FAKEHOME}"], check=False)
    shutil.rmtree(FAKEHOME, ignore_errors=True)
    os.makedirs(f"{FAKEHOME}/.ssh", mode=0o700)
    os.makedirs(f"{FAKEHOME}/.config/sshleash")
    for k in ("laptop-key", "deploy-bot"):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", k, "-f", f"{FAKEHOME}/.ssh/{k}"], check=True)
    agent = f"{FAKEHOME}/agent.sock"
    subprocess.Popen(["ssh-agent", "-a", agent], stdout=subprocess.DEVNULL)
    time.sleep(0.5)
    subprocess.run(["ssh-add", "-q", f"{FAKEHOME}/.ssh/laptop-key", f"{FAKEHOME}/.ssh/deploy-bot"],
                   env=dict(os.environ, SSH_AUTH_SOCK=agent), check=True)
    with open(f"{FAKEHOME}/.config/sshleash/policy.toml", "w") as f:
        f.write('''[[rule]]
name = "the deploy key never signs commits"
key = "deploy-*"
kind = ["sshsig"]
action = "deny"

[[rule]]
name = "forwarded agents must ask"
forwarded = true
action = "confirm"

[default]
action = "allow"
''')
    with open(f"{FAKEHOME}/release.txt", "w") as f:
        f.write("v0.1.0\n")
    EXPORTS["SSH_AUTH_SOCK"] = agent
    EXPORTS["HOME"] = FAKEHOME


def main():
    os.makedirs(BUILD, exist_ok=True)
    setup()
    only = [int(x) for x in sys.argv[1:]]
    parts = []
    for i, s in enumerate(SCENES):
        if not only or i in only:
            globals()["TITLEBAR"] = s.get("titlebar", "laptop — bash")
            parts.append(render_scene(i, s, DEMO))
        else:
            parts.append(os.path.join(BUILD, "s%d.mp4" % i))
    subprocess.run(["pkill", "-f", "sshleash run"], check=False)
    with open(os.path.join(BUILD, "list.txt"), "w") as fh:
        fh.writelines(f"file '{p}'\n" for p in parts)
    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i",
         os.path.join(BUILD, "list.txt"), "-c:v", "libx264", "-crf", "23", "-pix_fmt", "yuv420p",
         "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart", OUT],
        check=True,
    )
    with open(os.path.join(BUILD, "narration.txt"), "w") as fh:
        fh.write("\n\n".join(s["say"] for s in SCENES) + "\n")
    print(OUT, round(duration(OUT), 1), "s")


if __name__ == "__main__":
    main()
