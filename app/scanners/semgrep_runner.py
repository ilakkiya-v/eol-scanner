"""Optional: run Semgrep (if installed) on the extracted source and import its results.

Semgrep adds data-flow (taint) rules across many languages. It is not bundled: install it with `pip install semgrep`
(Linux/macOS; Windows support is newer, see Semgrep's docs). The ruleset comes from Settings -> code_review.semgrep_config:
a registry ruleset such as "p/default" (downloaded from semgrep.dev, needs internet; your code is not uploaded) or a
local folder of rules for air-gapped labs. Metrics are always turned off.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from ..importers import parse_semgrep


def available() -> bool:
    return shutil.which("semgrep") is not None


def run(src: Path, config: str, log: Callable[[str], None], cancelled: Callable[[], bool], timeout: int = 1800) -> list[dict]:
    exe = shutil.which("semgrep")
    if not exe:
        log("Semgrep is not installed; skipped (pip install semgrep)")
        return []
    if cancelled():
        return []
    cfg = config.strip() or "p/default"
    if not cfg.startswith(("p/", "r/")) and not Path(cfg).exists():
        log(f"Semgrep ruleset '{cfg}' not found; skipped")
        return []
    args = [exe, "scan", "--config", cfg, "--json", "--metrics=off", "--quiet", "--timeout", "30",
            "--max-target-bytes", "2000000", "--no-git-ignore", str(src)]
    log(f"running Semgrep with ruleset {cfg}")
    try:
        p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        log("Semgrep timed out; skipped")
        return []
    except OSError as e:
        log(f"Semgrep could not start: {e}")
        return []
    try:
        data = json.loads(p.stdout or "{}")
    except ValueError:
        log(f"Semgrep returned no JSON (exit {p.returncode}): {(p.stderr or '')[-300:]}")
        return []
    root = str(src.resolve())
    for r in data.get("results") or []:  # make paths relative to the project root
        path = str(Path(r.get("path", "")).resolve()) if r.get("path") else ""
        if path.startswith(root):
            r["path"] = path[len(root):].lstrip("/\\").replace("\\", "/")
    findings = parse_semgrep(data)
    errs = len(data.get("errors") or [])
    log(f"Semgrep: {len(findings)} rule groups from {len(data.get('results') or [])} results" + (f", {errs} file errors" if errs else ""))
    return findings
