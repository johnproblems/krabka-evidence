#!/usr/bin/env python3
"""Render the README demos from real executions.

Runs `krabka-evidence` for real, captures the actual stdout of every
command shown, and renders terminal footage with ffmpeg's drawtext: typed
commands plus the captured outputs, nothing else. Every command's exit
code is asserted, so the demo fails instead of filming a surprise.

Outputs (each 10-15 s):
  docs/demo/demo-clean.{mp4,gif}   fixture -> build (CLEAN) -> verify (OK)
  docs/demo/demo-tamper.{mp4,gif}  build flipped-sig (FINDINGS) -> finding detail
  docs/demo/demo-bypass.{mp4,gif}  build bypass (FINDINGS) -> finding detail
  docs/demo/demo-json.{mp4,gif}    build --format json -> verify json -> trust ids

Needs: ffmpeg + ffprobe on PATH, a monospace TTF (DejaVu Sans Mono via
fontconfig by default), and a release build (built automatically).

Regenerate:  python3 scripts/demo.py [--ffmpeg BIN] [--font FILE]
"""

import json
import os
import shutil
import subprocess
import sys

WIDTH, HEIGHT = 960, 600
FPS = 10
FONTSIZE = 18
LINE_HEIGHT = 24
MARGIN_X = 28
TITLE_HEIGHT = 46
CONTENT_Y = TITLE_HEIGHT + 26
WRAP_COLS = 74
BG = "0x1e1e1e"
TITLE_BG = "0x2d2d2d"
GREEN = "0x7ee787"
WHITE = "0xffffff"
GRAY = "0xc9d1d9"
RED = "0xffa198"
DIM = "0x8b949e"

MIN_SECONDS, MAX_SECONDS = 10.0, 15.0


def run(cmd, **kwargs):
    """Run a command, returning completed process with text streams."""
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def require_ffmpeg(cli_value):
    """Locate ffmpeg and ffprobe."""
    ffmpeg = cli_value or shutil.which("ffmpeg")
    if not ffmpeg:
        sys.exit("error: ffmpeg not on PATH (nix: nix shell nixpkgs#ffmpeg)")
    ffprobe = os.path.join(os.path.dirname(ffmpeg), "ffprobe")
    if not os.path.exists(ffprobe):
        ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        sys.exit("error: ffprobe not found next to ffmpeg")
    return ffmpeg, ffprobe


def require_font(cli_value):
    """Locate a monospace TTF."""
    if cli_value:
        if not os.path.isfile(cli_value):
            sys.exit(f"error: font file {cli_value} not found")
        return cli_value
    fc_match = shutil.which("fc-match")
    if fc_match:
        probe = run(
            [fc_match, "DejaVu Sans Mono", "--format=%{file}"])
        path = probe.stdout.strip().split("\n")[0]
        if probe.returncode == 0 and path.endswith(".ttf") and os.path.isfile(path):
            return path
    sys.exit("error: no monospace TTF found (pass --font FILE)")


def wrap_line(text, width=WRAP_COLS):
    """Wrap one line for the frame, preferring spaces."""
    if len(text) <= width:
        return [text]
    words, lines, current = text.split(" "), [], ""
    for word in words:
        if len(word) > width:
            if current:
                lines.append(current)
                current = ""
            while len(word) > width:
                lines.append(word[:width])
                word = word[width:]
            current = word
        elif not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    if current or not lines:
        lines.append(current)
    return lines


def output_color(line):
    """Presentation color for a captured output line."""
    if "CLEAN" in line or line.startswith("OK:"):
        return GREEN
    if "FINDINGS" in line or line.startswith("FAIL"):
        return RED
    if line.startswith("wrote "):
        return DIM
    return GRAY


# Pixels a 2-char prompt occupies in DejaVu Sans Mono at FONTSIZE.
PROMPT_WIDTH = 22


def command_rows(text):
    """Hard-wrap a typed command like a terminal: 72 cols after `$ `, 74 after."""
    rows = [text[:WRAP_COLS - 2]]
    rest = text[WRAP_COLS - 2:]
    while rest:
        rows.append(rest[:WRAP_COLS])
        rest = rest[WRAP_COLS:]
    return rows


class Timeline:
    """A demo's typed commands and captured outputs on a clock."""

    def __init__(self, title):
        self.title = title
        self.events = []  # (kind, at, end, row, x, text, color)
        self.clock = 0.6
        self.row = 0

    def command(self, text, chars_per_sec):
        """Type a command after the prompt; returns when fully typed."""
        prompt_at = self.clock
        self.events.append(("show", prompt_at, None, self.row, MARGIN_X, "$ ", GREEN))
        step = max(1, round(chars_per_sec / FPS))
        chunks = [text[i:i + step] for i in range(0, len(text), step)]
        tick = len(text) / chars_per_sec / max(1, len(chunks))
        shown = ""
        for index, chunk in enumerate(chunks):
            shown += chunk
            start = prompt_at + 0.2 + index * tick
            last = index == len(chunks) - 1
            for piece_no, piece in enumerate(command_rows(shown)):
                x = MARGIN_X + PROMPT_WIDTH if piece_no == 0 else MARGIN_X
                if last:
                    self.events.append(
                        ("show", start, None, self.row + piece_no, x, piece, WHITE)
                    )
                else:
                    self.events.append(
                        ("flash", start, start + tick, self.row + piece_no, x, piece, WHITE)
                    )
        self.clock = prompt_at + 0.2 + len(chunks) * tick + 0.35
        self.row += len(command_rows(text))

    def output(self, lines, stagger=0.12):
        """Reveal captured output lines one by one."""
        for line in lines:
            for wrapped in wrap_line(line):
                self.events.append(
                    ("show", self.clock, None, self.row, MARGIN_X, wrapped, output_color(line))
                )
                self.row += 1
            self.clock += stagger
        self.clock += 0.4

    def finish(self, hold=1.0):
        """End the demo after a final hold; returns total seconds."""
        total = self.clock + hold
        if not MIN_SECONDS <= total <= MAX_SECONDS:
            sys.exit(f"error: demo {total:.1f}s is outside 10-15s, retune it")
        if self.row * LINE_HEIGHT + CONTENT_Y > HEIGHT - 10:
            sys.exit(f"error: demo overflows the frame ({self.row} rows), trim it")
        return total

    def filters(self, font, work):
        """Build the drawtext filter chain for these events.

        Every string goes through a `textfile`: captured output can hold
        any bytes, and no amount of inline escaping survives quotes,
        semicolons, and brackets together.
        """
        texts = [self.title] + [text for _, _, _, _, _, text, _ in self.events]
        paths = []
        for index, text in enumerate(texts):
            path = os.path.join(work, f"text-{index:03d}.txt")
            with open(path, "w") as handle:
                handle.write(text)
            paths.append(path)
        parts = [
            f"drawbox=x=0:y=0:w={WIDTH}:h={TITLE_HEIGHT}:c={TITLE_BG}:t=fill",
            f"drawtext=fontfile='{font}':textfile='{paths[0]}'"
            f":fontsize={FONTSIZE}:fontcolor={DIM}:x={MARGIN_X}:y=14",
        ]
        for number, (kind, at, end, row, x, _text, color) in enumerate(self.events, start=1):
            y = CONTENT_Y + row * LINE_HEIGHT
            gate = f"gte(t,{at:.2f})" if kind == "show" else f"between(t,{at:.2f},{end:.2f})"
            parts.append(
                f"drawtext=fontfile='{font}':textfile='{paths[number]}'"
                f":fontsize={FONTSIZE}:fontcolor={color}"
                f":x={x}:y={y}:enable='{gate}'"
            )
        return ",".join(parts)


class Shell:
    """A persistent working directory and environment for filmed commands."""

    def __init__(self, root):
        self.cwd = root
        self.env = dict(os.environ)

    def execute(self, text, expect=0):
        """Run typed text for real; return its stdout lines. Asserts everything."""
        print(f"$ {text}")
        if text.startswith("cd "):
            target = text[3:].strip()
            resolved = os.path.realpath(os.path.join(self.cwd, target))
            if not os.path.isdir(resolved):
                sys.exit(f"error: demo cd target missing: {resolved}")
            self.cwd = resolved
            return []
        if text.startswith("export ") and "=" in text:
            key, _, value = text[len("export "):].partition("=")
            self.env[key] = value.replace("$PATH", self.env.get("PATH", ""))
            return []
        completed = run(text, shell=True, cwd=self.cwd, env=self.env)
        if completed.returncode != expect:
            sys.exit(
                f"error: {text!r} exited {completed.returncode}, "
                f"expected {expect}\nstdout: {completed.stdout}\nstderr: {completed.stderr}"
            )
        if completed.stderr.strip():
            sys.exit(
                f"error: {text!r} wrote to stderr, refusing to film silently:\n"
                + completed.stderr
            )
        lines = completed.stdout.splitlines()
        for line in lines:
            print(f"  {line}")
        return lines


def film_clean(shell, binary):
    """Fixture, build, and verify a clean pack; returns the timeline."""
    demo = Timeline("krabka-evidence — clean pack, end to end")
    cmd = f"export PATH={os.path.dirname(binary)}:$PATH"
    shell.execute(cmd)
    demo.command(cmd, 65)
    cmd = "krabka-evidence fixture --scenario clean --out /tmp/ev-demo"
    out = shell.execute(cmd)
    assert out == ["wrote /tmp/ev-demo/clean"], out
    demo.command(cmd, 65)
    demo.output(out)
    shell.execute("cd /tmp/ev-demo/clean")
    demo.command("cd /tmp/ev-demo/clean", 40)
    cmd = (
        "krabka-evidence --audit audit --metadata metadata --archive archive "
        "--operator-keys keys/keys.toml --cluster-id fixture-cluster "
        "--sign-with keys/auditor.priv.pkcs8 -o evidence"
    )
    out = shell.execute(cmd)
    assert out[-1] == "CLEAN: evidence pack holds no findings", out
    demo.command(cmd, 75)
    demo.output(out, stagger=0.1)
    cmd = (
        "krabka-evidence verify evidence --format json "
        "| python3 -c \"import json,sys; s=json.load(sys.stdin); "
        "print(s['authentic'], s['findings'])\""
    )
    out = shell.execute(cmd)
    assert out == ["True 0"], out
    demo.command(cmd, 90)
    demo.output(out)
    return demo


def film_tamper(shell, binary):
    """Build a tampered pack and show the finding; returns the timeline."""
    demo = Timeline("krabka-evidence — tamper detected, end to end")
    cmd = f"export PATH={os.path.dirname(binary)}:$PATH"
    shell.execute(cmd)
    demo.command(cmd, 65)
    cmd = "krabka-evidence fixture --scenario flipped-sig --out /tmp/ev-demo"
    out = shell.execute(cmd)
    assert out == ["wrote /tmp/ev-demo/flipped-sig"], out
    demo.command(cmd, 65)
    demo.output(out)
    shell.execute("cd /tmp/ev-demo/flipped-sig")
    demo.command("cd /tmp/ev-demo/flipped-sig", 40)
    cmd = (
        "krabka-evidence --audit audit --metadata metadata --archive archive "
        "--operator-keys keys/keys.toml --cluster-id fixture-cluster "
        "--sign-with keys/auditor.priv.pkcs8 -o evidence"
    )
    out = shell.execute(cmd, expect=1)
    assert out[-1] == "FINDINGS: evidence pack holds 1 finding(s)", out
    demo.command(cmd, 75)
    demo.output(out, stagger=0.1)
    cmd = (
        "python3 -c \"import json; f = "
        "json.load(open('evidence/report.json'))['findings'][0]; "
        "print(f['check'], '-', f['title'], '@ audit', f['audit_offset'])\""
    )
    out = shell.execute(cmd)
    assert out == ["signature-verification - Signature does not verify @ audit 1"], out
    demo.command(cmd, 65)
    demo.output(out)
    return demo


def film_bypass(shell, binary):
    """Build a bypassed pack and show the finding; returns the timeline."""
    demo = Timeline("krabka-evidence — bypass detected, end to end")
    cmd = f"export PATH={os.path.dirname(binary)}:$PATH"
    shell.execute(cmd)
    demo.command(cmd, 65)
    cmd = "krabka-evidence fixture --scenario bypass --out /tmp/ev-demo"
    out = shell.execute(cmd)
    assert out == ["wrote /tmp/ev-demo/bypass"], out
    demo.command(cmd, 65)
    demo.output(out)
    shell.execute("cd /tmp/ev-demo/bypass")
    demo.command("cd /tmp/ev-demo/bypass", 40)
    cmd = (
        "krabka-evidence --audit audit --metadata metadata --archive archive "
        "--operator-keys keys/keys.toml --cluster-id fixture-cluster "
        "--sign-with keys/auditor.priv.pkcs8 -o evidence"
    )
    out = shell.execute(cmd, expect=1)
    assert out[-1] == "FINDINGS: evidence pack holds 1 finding(s)", out
    demo.command(cmd, 75)
    demo.output(out, stagger=0.1)
    cmd = (
        "python3 -c \"import json; f = "
        "json.load(open('evidence/report.json'))['findings'][0]; "
        "print(f['check'], '-', f['title'], '@ audit', f['audit_offset'])\""
    )
    out = shell.execute(cmd)
    assert out == ["bypass-listing - Gated action bypassed approval @ audit 14"], out
    demo.command(cmd, 65)
    demo.output(out)
    return demo


def film_json(shell, binary):
    """Build with JSON output and show the recorded trust ids."""
    demo = Timeline("krabka-evidence — JSON outputs, end to end")
    cmd = f"export PATH={os.path.dirname(binary)}:$PATH"
    shell.execute(cmd)
    demo.command(cmd, 65)
    cmd = "krabka-evidence fixture --scenario clean --out /tmp/ev-demo-json"
    out = shell.execute(cmd)
    assert out == ["wrote /tmp/ev-demo-json/clean"], out
    demo.command(cmd, 75)
    demo.output(out)
    shell.execute("cd /tmp/ev-demo-json/clean")
    demo.command("cd /tmp/ev-demo-json/clean", 40)
    cmd = (
        "krabka-evidence --audit audit --metadata metadata --archive archive "
        "--operator-keys keys/keys.toml --cluster-id fixture-cluster "
        "--sign-with keys/auditor.priv.pkcs8 -o evidence --format json "
        "| python3 -c \"import json,sys; s=json.load(sys.stdin); "
        "print(s['status'], 'checks:', len(s['checks']))\""
    )
    out = shell.execute(cmd)
    assert out == ["clean checks: 11"], out
    demo.command(cmd, 110)
    demo.output(out, stagger=0.1)
    cmd = (
        "krabka-evidence verify evidence --format json "
        "| python3 -c \"import json,sys; s=json.load(sys.stdin); "
        "print(s['authentic'], s['findings'])\""
    )
    out = shell.execute(cmd)
    assert out == ["True 0"], out
    demo.command(cmd, 100)
    demo.output(out)
    cmd = (
        "python3 -c \"import json; "
        "print(json.load(open('evidence/report.json'))['trust']['operator_key_ids'])\""
    )
    out = shell.execute(cmd)
    assert out == ["['alice-2026', 'bob-2026', 'carol-2026']"], out
    demo.command(cmd, 100)
    demo.output(out)
    return demo


def render(ffmpeg, font, demo, duration, work, mp4_path, gif_path):
    """Render one demo's MP4 and GIF from its filter chain."""
    graph = f"[0:v]{demo.filters(font, work)}[v]"
    mp4 = run(
        [
            ffmpeg, "-y", "-v", "error",
            "-f", "lavfi",
            "-i", f"color=c={BG}:s={WIDTH}x{HEIGHT}:r={FPS}:d={duration:.2f}",
            "-filter_complex", graph,
            "-map", "[v]",
            "-c:v", "libx264", "-pix_fmt", "yuv420p",
            "-crf", "23", "-preset", "veryfast",
            "-movflags", "+faststart",
            mp4_path,
        ]
    )
    if mp4.returncode != 0:
        sys.exit(f"error: mp4 render failed:\n{mp4.stderr}")
    palette = os.path.join(work, "palette.png")
    gif = run(
        [
            ffmpeg, "-y", "-v", "error", "-i", mp4_path,
            "-vf", "palettegen=reserve_transparent=0", palette,
        ]
    )
    if gif.returncode != 0:
        sys.exit(f"error: palette failed:\n{gif.stderr}")
    gif = run(
        [
            ffmpeg, "-y", "-v", "error", "-i", mp4_path, "-i", palette,
            "-lavfi", "paletteuse", gif_path,
        ]
    )
    if gif.returncode != 0:
        sys.exit(f"error: gif render failed:\n{gif.stderr}")
    print(f"rendered {mp4_path} + {gif_path} ({duration:.1f}s)")


def frame_md5(ffmpeg, path, at):
    """MD5 of one decoded frame."""
    out = run(
        [ffmpeg, "-v", "error", "-ss", str(at), "-i", path,
         "-frames:v", "1", "-f", "md5", "-"]
    )
    if out.returncode != 0:
        sys.exit(f"error: cannot decode {path} at {at}s:\n{out.stderr}")
    return out.stdout.strip().split("=")[-1].strip()


def ascii_frame(ffmpeg, path, at, cols=160, rows=60):
    """Decode one frame to ASCII art for a human readability check."""
    out = subprocess.run(
        [
            ffmpeg, "-v", "error", "-ss", str(at), "-i", path,
            "-frames:v", "1", "-vf", f"scale={cols}:{rows},format=gray",
            "-f", "rawvideo", "-",
        ],
        capture_output=True,
    )
    if out.returncode != 0 or len(out.stdout) < cols * rows:
        sys.exit(f"error: cannot extract a preview frame from {path}")
    ramp = " .:-=+*#%@"
    pixels = out.stdout[:cols * rows]
    lines = []
    for row in range(rows):
        band = pixels[row * cols:(row + 1) * cols]
        lines.append("".join(ramp[b * (len(ramp) - 1) // 256] for b in band))
    return "\n".join(lines)


def verify(ffmpeg, ffprobe, path, duration):
    """Verify one file: duration, clean decode, animated, non-blank."""
    probe = run(
        [ffprobe, "-v", "error", "-show_entries", "format=duration",
         "-of", "csv=p=0", path]
    )
    actual = float(probe.stdout.strip())
    if not MIN_SECONDS <= actual <= MAX_SECONDS:
        sys.exit(f"error: {path} is {actual:.1f}s, want 10-15s")
    decode = run([ffmpeg, "-v", "error", "-i", path, "-f", "null", "-"])
    if decode.returncode != 0 or decode.stderr.strip():
        sys.exit(f"error: {path} does not decode cleanly:\n{decode.stderr}")
    marks = [duration * 0.2, duration * 0.55, duration - 1.0]
    hashes = [frame_md5(ffmpeg, path, at) for at in marks]
    if len(set(hashes)) != 3:
        sys.exit(f"error: {path} is not animated (identical frames)")
    stats = run(
        [ffmpeg, "-i", path, "-vf",
         "signalstats,metadata=print:file=-:direct=1", "-f", "null", "-"]
    )
    levels = []
    for line in stats.stdout.splitlines():
        if "YAVG" not in line:
            continue
        tail = line.split("YAVG", 1)[1].lstrip("=:")
        try:
            levels.append(float(tail.split()[0]))
        except (ValueError, IndexError):
            continue
    if not levels:
        sys.exit(f"error: no brightness signal from {path}")
    mean = sum(levels) / len(levels)
    if not 10.0 < mean < 235.0:
        sys.exit(f"error: {path} looks blank (mean brightness {mean:.1f})")
    print(f"verified {path}: {actual:.1f}s, animated, brightness {mean:.0f}")
    return hashes


def main():
    """Build the release binary, film both demos, render, and verify."""
    args = sys.argv[1:]
    ffmpeg_arg, font_arg = None, None
    while args:
        flag, args = args[0], args[1:]
        if flag == "--ffmpeg" and args:
            ffmpeg_arg, args = args[0], args[1:]
        elif flag == "--font" and args:
            font_arg, args = args[0], args[1:]
        else:
            sys.exit(f"error: unknown argument {flag}")
    ffmpeg, ffprobe = require_ffmpeg(ffmpeg_arg)
    font = require_font(font_arg)
    print(f"ffmpeg: {ffmpeg}\nfont: {font}")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    build = run(["cargo", "build", "--release"], cwd=root)
    if build.returncode != 0:
        sys.exit(f"error: release build failed:\n{build.stderr[-2000:]}")
    binary = os.path.join(root, "target", "release", "krabka-evidence")
    if not os.path.isfile(binary):
        sys.exit("error: release binary missing after build")

    work = "/tmp/ev-demo-work"
    shutil.rmtree("/tmp/ev-demo", ignore_errors=True)
    shutil.rmtree("/tmp/ev-demo-json", ignore_errors=True)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    out_dir = os.path.join(root, "docs", "demo")
    os.makedirs(out_dir, exist_ok=True)

    shell = Shell(root)
    clean = film_clean(shell, binary)
    clean_seconds = clean.finish()
    tamper = film_tamper(Shell(root), binary)
    tamper_seconds = tamper.finish()
    bypass = film_bypass(Shell(root), binary)
    bypass_seconds = bypass.finish()
    json_demo = film_json(Shell(root), binary)
    json_seconds = json_demo.finish(hold=0.7)

    clean_mp4 = os.path.join(out_dir, "demo-clean.mp4")
    clean_gif = os.path.join(out_dir, "demo-clean.gif")
    tamper_mp4 = os.path.join(out_dir, "demo-tamper.mp4")
    tamper_gif = os.path.join(out_dir, "demo-tamper.gif")
    bypass_mp4 = os.path.join(out_dir, "demo-bypass.mp4")
    bypass_gif = os.path.join(out_dir, "demo-bypass.gif")
    json_mp4 = os.path.join(out_dir, "demo-json.mp4")
    json_gif = os.path.join(out_dir, "demo-json.gif")
    render(ffmpeg, font, clean, clean_seconds, work, clean_mp4, clean_gif)
    render(ffmpeg, font, tamper, tamper_seconds, work, tamper_mp4, tamper_gif)
    render(ffmpeg, font, bypass, bypass_seconds, work, bypass_mp4, bypass_gif)
    render(ffmpeg, font, json_demo, json_seconds, work, json_mp4, json_gif)

    for path, duration in [
        (clean_mp4, clean_seconds),
        (clean_gif, clean_seconds),
        (tamper_mp4, tamper_seconds),
        (tamper_gif, tamper_seconds),
        (bypass_mp4, bypass_seconds),
        (bypass_gif, bypass_seconds),
        (json_mp4, json_seconds),
        (json_gif, json_seconds),
    ]:
        verify(ffmpeg, ffprobe, path, duration)
    print("--- clean, near the end ---")
    print(ascii_frame(ffmpeg, clean_mp4, clean_seconds - 2.0))
    print("--- tamper, near the end ---")
    print(ascii_frame(ffmpeg, tamper_mp4, tamper_seconds - 2.0))
    print("--- bypass, near the end ---")
    print(ascii_frame(ffmpeg, bypass_mp4, bypass_seconds - 2.0))
    print("--- json, near the end ---")
    print(ascii_frame(ffmpeg, json_mp4, json_seconds - 2.0))
    for path in (
        clean_mp4,
        clean_gif,
        tamper_mp4,
        tamper_gif,
        bypass_mp4,
        bypass_gif,
        json_mp4,
        json_gif,
    ):
        size = os.path.getsize(path)
        print(f"{size:>10,} bytes  {os.path.relpath(path, root)}")


if __name__ == "__main__":
    main()
