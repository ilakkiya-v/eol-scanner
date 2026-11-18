"""Use a locally installed, logged-in Claude Code CLI as the AI backend.

This is how a Claude Enterprise user can use their own Claude login (and Mythos, if their org enabled it) without an
API key: the scanner runs `claude -p` as a child process. Safety:
  * the prompt is sent on stdin, never as a command-line argument (no shell / cmd.exe quoting issues);
  * only read-only tools exist in the session (--tools Read,Grep,Glob); Bash, Edit, Write, web tools, sub-agents and
    MCP tools are also denied (--disallowedTools), and nothing is pre-approved (--permission-mode dontAsk);
  * the working directory is the extracted source / saved crawl folder (or an empty temp folder for plain questions),
    and permissions.blockReadsOutsideWorkingDirectories stops the file tools reading anything else on the machine;
  * the uploaded code cannot configure the session: project/local settings (.claude/settings*.json, hooks, allow rules)
    are not loaded (--setting-sources user), hooks are disabled, .mcp.json is ignored (--strict-mcp-config), and
    CLAUDE.md / .claude files in the folder are set aside for the duration of the run (they could carry instructions);
  * ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN are removed from the child's environment so it uses the logged-in account.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Optional

READ_ONLY_TOOLS = ["Read", "Grep", "Glob"]
BLOCKED_TOOLS = ["Bash", "Edit", "Write", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "Task", "Agent", "mcp__*"]
# Session settings passed inline: they can only restrict (no allow rules), and override nothing the user's org enforces.
SESSION_SETTINGS = {"permissions": {"blockReadsOutsideWorkingDirectories": True},
                    "disableAllHooks": True}
# Files in an uploaded codebase that Claude Code would treat as instructions or configuration.
_INSTRUCTION_FILES = {"CLAUDE.md", "CLAUDE.local.md", ".mcp.json"}
_INSTRUCTION_DIRS = {".claude"}
_QUARANTINE_SUFFIX = ".eolscan-set-aside"
_SAFE_ARG = re.compile(r"^[A-Za-z0-9._:@/\[\]-]{1,120}$")


class ClaudeCodeError(Exception):
    pass


def find_cli(cfg: Optional[dict] = None) -> Optional[str]:
    explicit = ((cfg or {}).get("claude_cli") or "").strip()
    if explicit:
        return explicit if Path(explicit).exists() else None
    found = shutil.which("claude")
    if found:
        return found
    home = Path.home()
    for c in (home / ".local/bin/claude", home / ".claude/local/claude", home / ".local/bin/claude.exe",
              Path(os.environ.get("APPDATA", "")) / "npm" / "claude.cmd", Path("/opt/homebrew/bin/claude"), Path("/usr/local/bin/claude")):
        if str(c) not in ("npm/claude.cmd",) and c.exists():
            return str(c)
    return None


def _env() -> dict:
    env = dict(os.environ)
    for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        env.pop(k, None)  # use the CLI's own login (e.g. Claude Enterprise), not a stray API key
    return env


def _base_args(cli: str, cfg: dict, max_turns: int, tools: bool) -> list[str]:
    args = [cli, "-p", "Follow the instructions given on standard input.", "--output-format", "stream-json", "--verbose",
            "--max-turns", str(max_turns)]
    model = (cfg.get("model") or "").strip()
    if model and model != "claude-opus-5-5":  # default: whatever model the CLI/org is set to use
        if not _SAFE_ARG.match(model):
            raise ClaudeCodeError(f"model name '{model}' contains unexpected characters")
        args += ["--model", model]
    args += ["--tools", ",".join(READ_ONLY_TOOLS) if tools else "",
             "--permission-mode", "dontAsk", "--setting-sources", "user", "--strict-mcp-config",
             "--settings", json.dumps(SESSION_SETTINGS), "--disallowedTools", *BLOCKED_TOOLS]
    return args


def _set_aside(root: str) -> list[tuple[Path, Path]]:
    """Rename CLAUDE.md / .claude / .mcp.json inside the folder so Claude Code doesn't load them as instructions."""
    moved = []
    for dp, dns, fns in os.walk(root):
        for name in [n for n in dns if n in _INSTRUCTION_DIRS] + [n for n in fns if n in _INSTRUCTION_FILES]:
            src = Path(dp) / name
            dst = src.with_name(name + _QUARANTINE_SUFFIX)
            try:
                src.rename(dst)
                moved.append((src, dst))
            except OSError:
                pass
        dns[:] = [n for n in dns if n not in _INSTRUCTION_DIRS and not n.endswith(_QUARANTINE_SUFFIX)]
    return moved


def _restore(moved: list[tuple[Path, Path]]) -> None:
    for src, dst in reversed(moved):
        try:
            dst.rename(src)
        except OSError:
            pass


def run(prompt: str, cfg: dict, cwd: Optional[str] = None, *, tools: bool = False, max_turns: int = 3,
        timeout: int = 600, log: Callable[[str], None] = lambda m: None,
        cancelled: Callable[[], bool] = lambda: False) -> dict:
    """Run Claude Code non-interactively. Returns {text, turns, cost_usd, model}."""
    cli = find_cli(cfg)
    if not cli:
        raise ClaudeCodeError("Claude Code CLI not found. Install it, run `claude` once and sign in with your work account, "
                              "or set its full path in Settings -> AI assist.")
    tmp = None
    if cwd is None:
        tmp = tempfile.mkdtemp(prefix="eolscan-cc-")
        cwd = tmp
    args = _base_args(cli, cfg, max_turns, tools)
    moved = _set_aside(cwd)
    try:
        return _run(args, cwd, prompt, timeout, log, cancelled, tmp)
    finally:
        _restore(moved)
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def _run(args: list[str], cwd: str, prompt: str, timeout: int, log, cancelled, tmp) -> dict:
    try:
        proc = subprocess.Popen(args, cwd=cwd, env=_env(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    except OSError as e:
        raise ClaudeCodeError(f"could not start Claude Code: {e}") from e

    stderr_lines: list[str] = []
    threading.Thread(target=lambda: stderr_lines.extend(proc.stderr), daemon=True).start()  # type: ignore[arg-type]
    try:
        proc.stdin.write(prompt)  # type: ignore[union-attr]
        proc.stdin.close()  # type: ignore[union-attr]
    except OSError:
        pass

    result: dict = {"text": "", "turns": 0, "cost_usd": None, "model": None}
    texts: list[str] = []
    raw: list[str] = []
    start = time.time()
    killed = None

    def watchdog():
        nonlocal killed
        while proc.poll() is None:
            if cancelled():
                killed = "cancelled"
            elif time.time() - start > timeout:
                killed = f"timed out after {timeout // 60} min"
            if killed:
                proc.kill()
                return
            time.sleep(1)

    threading.Thread(target=watchdog, daemon=True).start()
    for line in proc.stdout:  # type: ignore[union-attr]
        line = line.strip()
        if not line:
            continue
        raw.append(line)
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        et = ev.get("type")
        if et == "system" and ev.get("model"):
            result["model"] = ev.get("model")
        elif et == "assistant":
            for b in (ev.get("message") or {}).get("content") or []:
                if b.get("type") == "tool_use":
                    inp = b.get("input") or {}
                    what = inp.get("file_path") or inp.get("pattern") or inp.get("path") or ""
                    log(f"Claude Code: {b.get('name')} {str(what)[:160]}")
                elif b.get("type") == "text" and b.get("text"):
                    texts.append(b["text"])
        elif et == "result":
            result["text"] = ev.get("result") or ""
            result["turns"] = ev.get("num_turns") or 0
            result["cost_usd"] = ev.get("total_cost_usd")
            if ev.get("is_error"):
                raise ClaudeCodeError(f"Claude Code reported an error: {str(ev.get('result') or ev.get('subtype'))[:400]}")
    proc.wait()
    if killed:
        raise ClaudeCodeError(f"Claude Code {killed}")
    if not result["text"]:
        result["text"] = "\n".join(texts)
    if not result["text"] and len(raw) == 1:  # older CLI that ignored stream-json: plain JSON result
        try:
            result["text"] = json.loads(raw[0]).get("result", "")
        except ValueError:
            result["text"] = raw[0]
    if proc.returncode not in (0, None) and not result["text"]:
        err = " ".join(stderr_lines)[-600:].strip()
        hint = " (not signed in? run `claude` once and use /login)" if re.search(r"log ?in|auth|credential|401", err, re.I) else ""
        if re.search(r"unknown option|unrecognized|invalid (?:option|value|setting)", err, re.I):
            hint = (" (this Claude Code version doesn't support the safety settings this app requires; update it with "
                    "`claude update` and try again)")
        raise ClaudeCodeError(f"Claude Code exited with code {proc.returncode}{hint}: {err or 'no output'}")
    return result


def complete(prompt: str, cfg: dict) -> str:
    from .llm import LLMUnavailable
    try:
        return run(prompt, cfg, tools=False, max_turns=2, timeout=600)["text"].strip()
    except ClaudeCodeError as e:
        raise LLMUnavailable(str(e)) from e
