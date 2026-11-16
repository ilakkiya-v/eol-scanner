"""Tiny SQLite persistence layer (scans, findings, settings, feed cache)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from typing import Any, Optional

from .config import DB_PATH

_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,            -- web | code
    target TEXT NOT NULL,
    mode TEXT,
    status TEXT NOT NULL,          -- queued | running | done | error | cancelled
    progress REAL DEFAULT 0,
    message TEXT DEFAULT '',
    operator TEXT DEFAULT '',
    ticket TEXT DEFAULT '',
    options TEXT DEFAULT '{}',
    summary TEXT DEFAULT '{}',
    log TEXT DEFAULT '[]',
    created REAL NOT NULL,
    finished REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    data TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT NOT NULL, fetched REAL NOT NULL);
"""


def conn() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            _conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
            _conn.row_factory = sqlite3.Row
            _conn.execute("PRAGMA journal_mode=WAL")
            _conn.execute("PRAGMA foreign_keys=ON")
            _conn.executescript(SCHEMA)
        return _conn


def _exec(sql: str, args: tuple = ()) -> sqlite3.Cursor:
    with _lock:
        return conn().execute(sql, args)


# ---------------------------------------------------------------- settings
DEFAULT_SETTINGS: dict[str, Any] = {
    "scope": {"allow": [], "deny": []},
    # llm: non-secret routing values only; keys/tokens come from the environment (see advisor/llm.py)
    "llm": {"provider": "none", "platform": "anthropic", "model": "claude-opus-5-5", "fallback": True,
            "base_url": "", "aws_region": "", "aws_profile": "", "workspace_id": "", "gcp_project": "",
            "gcp_region": "global", "foundry_resource": "", "effort": "high", "claude_cli": "",
            "ollama_url": "http://host.docker.internal:11434", "ollama_model": "llama3.1", "send_code": False},
    "feeds": {"online": True, "osv": True},
    # AI deep review + optional Semgrep. semgrep_config: a registry ruleset (needs internet) or a local rules folder.
    "code_review": {"semgrep_config": "p/default", "max_turns": 60, "max_input_tokens": 4000000, "timeout_min": 45},
    "scan_defaults": {"rate_per_sec": 5, "concurrency": 4, "max_pages": 30, "timeout": 10, "verify_tls": False},
}


def get_setting(key: str) -> Any:
    row = _exec("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row:
        val = json.loads(row["value"])
        default = DEFAULT_SETTINGS.get(key)
        if isinstance(default, dict) and isinstance(val, dict):
            return {**default, **val}
        return val
    return json.loads(json.dumps(DEFAULT_SETTINGS.get(key)))


def set_setting(key: str, value: Any) -> None:
    _exec("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
          (key, json.dumps(value)))


def all_settings() -> dict[str, Any]:
    return {k: get_setting(k) for k in DEFAULT_SETTINGS}


# ---------------------------------------------------------------- scans
def create_scan(kind: str, target: str, mode: str, operator: str, ticket: str, options: dict) -> str:
    sid = uuid.uuid4().hex[:12]
    _exec("INSERT INTO scans(id,kind,target,mode,status,operator,ticket,options,created) VALUES(?,?,?,?,?,?,?,?,?)",
          (sid, kind, target, mode, "queued", operator, ticket, json.dumps(options), time.time()))
    return sid


def update_scan(sid: str, **fields: Any) -> None:
    if not fields:
        return
    cols, vals = [], []
    for k, v in fields.items():
        cols.append(f"{k}=?")
        vals.append(json.dumps(v) if k in ("options", "summary", "log") else v)
    vals.append(sid)
    _exec(f"UPDATE scans SET {', '.join(cols)} WHERE id=?", tuple(vals))


def append_log(sid: str, line: str) -> None:
    with _lock:
        row = _exec("SELECT log FROM scans WHERE id=?", (sid,)).fetchone()
        if not row:
            return
        log = json.loads(row["log"])
        log.append([round(time.time(), 2), line])
        _exec("UPDATE scans SET log=? WHERE id=?", (json.dumps(log[-2000:]), sid))


def _scan_row(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k in ("options", "summary", "log"):
        d[k] = json.loads(d[k] or ("[]" if k == "log" else "{}"))
    return d


def get_scan(sid: str) -> Optional[dict]:
    row = _exec("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    return _scan_row(row) if row else None


def list_scans(limit: int = 200) -> list[dict]:
    rows = _exec("SELECT * FROM scans ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = _scan_row(r)
        d.pop("log", None)
        out.append(d)
    return out


def delete_scan(sid: str) -> None:
    _exec("DELETE FROM findings WHERE scan_id=?", (sid,))
    _exec("DELETE FROM scans WHERE id=?", (sid,))


# ---------------------------------------------------------------- findings
def add_finding(sid: str, finding: dict) -> None:
    fid = finding.setdefault("id", uuid.uuid4().hex[:12])
    _exec("INSERT OR REPLACE INTO findings(id,scan_id,severity,category,data) VALUES(?,?,?,?,?)",
          (fid, sid, finding.get("severity", "info"), finding.get("category", "info"), json.dumps(finding)))


def get_findings(sid: str) -> list[dict]:
    rows = _exec("SELECT data FROM findings WHERE scan_id=?", (sid,)).fetchall()
    return [json.loads(r["data"]) for r in rows]


def update_finding(fid: str, finding: dict) -> None:
    _exec("UPDATE findings SET data=?, severity=? WHERE id=?",
          (json.dumps(finding), finding.get("severity", "info"), fid))


def get_finding(fid: str) -> Optional[dict]:
    row = _exec("SELECT data FROM findings WHERE id=?", (fid,)).fetchone()
    return json.loads(row["data"]) if row else None


# ---------------------------------------------------------------- cache
def cache_get(key: str, max_age: Optional[float] = None) -> Optional[Any]:
    row = _exec("SELECT value, fetched FROM cache WHERE key=?", (key,)).fetchone()
    if not row:
        return None
    if max_age is not None and time.time() - row["fetched"] > max_age:
        return None
    return json.loads(row["value"])


def cache_get_any_age(key: str) -> Optional[Any]:
    return cache_get(key, None)


def cache_set(key: str, value: Any) -> None:
    _exec("INSERT INTO cache(key,value,fetched) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, fetched=excluded.fetched",
          (key, json.dumps(value), time.time()))
