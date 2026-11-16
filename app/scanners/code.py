"""Offline code review of an uploaded archive.

The archive is extracted with zip-slip / zip-bomb / symlink protection and is
only ever *read*. Nothing in it is executed, imported or built.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import tarfile
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable

from ..config import MAX_EXTRACTED_BYTES, MAX_FILES
from . import manifests
from .fingerprints import Component, match_js

SKIP_DIRS = {".git", ".svn", ".hg", ".idea", ".vscode", "__pycache__", ".tox", ".venv", "venv", ".gradle", "target/classes"}
TEXT_LIMIT = 4_000_000


class ArchiveError(Exception):
    pass


@dataclass
class CodeScanResult:
    components: list[Component] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    files_scanned: int = 0
    manifests: list[str] = field(default_factory=list)
    languages: dict = field(default_factory=dict)
    snippets: list[dict] = field(default_factory=list)   # for optional LLM review


def safe_extract(archive: Path, dest: Path) -> int:
    """Extract zip / tar(.gz) safely. Returns number of files extracted."""
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    total, count = 0, 0

    def target_for(name: str) -> Path:
        name = name.replace("\\", "/")
        if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
            raise ArchiveError(f"absolute path in archive: {name}")
        t = (root / name).resolve()
        if root not in t.parents and t != root:
            raise ArchiveError(f"path traversal in archive: {name}")
        return t

    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    continue  # never materialise symlinks
                count += 1
                total += info.file_size
                if count > MAX_FILES or total > MAX_EXTRACTED_BYTES:
                    raise ArchiveError("archive exceeds extraction limits (possible zip bomb)")
                if info.compress_size and info.file_size / max(1, info.compress_size) > 1000 and info.file_size > 50_000_000:
                    raise ArchiveError(f"suspicious compression ratio: {info.filename}")
                t = target_for(info.filename)
                t.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(t, "wb") as out:
                    shutil.copyfileobj(src, out, 1 << 20)
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue  # skip dirs, links, devices
                count += 1
                total += m.size
                if count > MAX_FILES or total > MAX_EXTRACTED_BYTES:
                    raise ArchiveError("archive exceeds extraction limits")
                t = target_for(m.name)
                t.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(m)
                if src:
                    with src, open(t, "wb") as out:
                        shutil.copyfileobj(src, out, 1 << 20)
    else:
        raise ArchiveError("unsupported archive (use .zip, .tar, .tar.gz)")
    return count


# --------------------------------------------------------------- code patterns
# Patterns that matter specifically for legacy / EOL code that will not be
# patched: they show *where* the risky surface is so it can be contained.
CODE_RULES = [
    # (id, regex, file glob suffixes, severity, title, kb)
    ("log4j-jndi-lookup", r"\$\{jndi:", (".xml", ".properties", ".yml", ".yaml", ".json", ".java"), "high",
     "JNDI lookup string in config/code", "log4j"),
    ("log4j1-socket", r"org\.apache\.log4j\.net\.(?:SocketServer|JMSAppender|SMTPAppender)|JDBCAppender", (".xml", ".properties", ".java"), "high",
     "Log4j 1.x network/JDBC appender configured (CVE-2019-17571 / CVE-2021-4104 / CVE-2022-23305 class)", "log4j"),
    ("java-deser", r"new\s+ObjectInputStream\s*\(|XMLDecoder\s*\(|readObject\s*\(\s*\)", (".java",), "medium",
     "Java native deserialization entry point", "deserialization"),
    ("xstream-fromxml", r"\bXStream\b[\s\S]{0,200}\.fromXML\(", (".java",), "medium", "XStream.fromXML (deserialization)", "deserialization"),
    ("fastjson-autotype", r"setAutoTypeSupport\s*\(\s*true|ParserConfig\.getGlobalInstance", (".java",), "high", "Fastjson autoType enabled", "deserialization"),
    ("struts-ognl", r"%\{|\$\{[^}]*#(?:context|_memberAccess)|struts\.devMode\"?\s*value=\"true|struts\.devMode\s*=\s*true", (".jsp", ".xml", ".properties"), "high",
     "Struts OGNL expression / devMode", "struts"),
    ("spring-actuator-expose", r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*['\"]?\*", (".properties", ".yml", ".yaml"), "high",
     "All Spring Boot actuator endpoints exposed", "actuator"),
    ("python-pickle", r"\bpickle\.loads?\(|\bcPickle\.loads?\(", (".py",), "medium", "pickle deserialization of possibly untrusted data", "deserialization"),
    ("python-yaml-load", r"yaml\.load\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)", (".py",), "medium", "yaml.load without SafeLoader", "deserialization"),
    ("python2-syntax", r"^\s*print\s+[\"'][^\n]*$|^\s*except\s+\w+\s*,\s*\w+\s*:", (".py",), "info", "Python 2-only syntax (runtime is EOL since 2020-01-01)", "python2"),
    ("django-debug", r"^\s*DEBUG\s*=\s*True", ("settings.py",), "medium", "Django DEBUG=True", "debug-endpoint"),
    ("flask-debug", r"app\.run\([^)]*debug\s*=\s*True", (".py",), "high", "Flask debug mode (Werkzeug console RCE)", "debug-endpoint"),
    ("php-unserialize", r"\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", (".php",), "high", "unserialize() on request data", "deserialization"),
    ("php-legacy-mysql", r"\bmysql_(?:query|connect|real_escape_string)\s*\(", (".php",), "medium", "Removed mysql_* API (code requires PHP <= 5.6)", "php-legacy"),
    ("php-eval-input", r"\b(?:eval|assert|create_function)\s*\([^)]*\$_(?:GET|POST|REQUEST)", (".php",), "critical", "eval/assert on request data", "code-injection"),
    ("aspnet-viewstate-mac", r"enableViewStateMac\s*=\s*\"false\"", (".config", ".aspx"), "high", "ViewState MAC disabled", "viewstate"),
    ("aspnet-customerrors-off", r"<customErrors\s+mode=\"Off\"", (".config",), "low", "ASP.NET customErrors Off (stack traces leak)", "debug-endpoint"),
    ("aspnet-machinekey", r"<machineKey[^>]+validationKey=\"[0-9A-Fa-f]{40,}\"", (".config",), "high", "Hardcoded machineKey (ViewState deserialization if leaked)", "viewstate"),
    ("angularjs-sce-off", r"\$sceProvider\.enabled\(\s*false\s*\)", (".js",), "high", "AngularJS $sce disabled (XSS)", "angularjs"),
    ("jquery-html-sink", r"\$\([^)]*location\.(?:hash|search)|\.html\(\s*(?:location|document\.URL|window\.name)", (".js", ".html"), "medium", "jQuery DOM-XSS sink with URL-controlled data", "dom-xss"),
    ("hardcoded-aws-key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", None, "high", "Hardcoded AWS access key id", "secrets"),
    ("private-key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", None, "high", "Private key committed", "secrets"),
    ("generic-password", r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]", (".properties", ".yml", ".yaml", ".config", ".xml", ".env", ".ini", ".py", ".php", ".js", ".java", ".cs"), "medium",
     "Hardcoded password", "secrets"),
    ("weak-hash-password", r"(?i)(?:md5|sha1)\s*\([^)]*pass", None, "medium", "MD5/SHA1 used for password hashing", "weak-crypto"),
    ("tls-verify-off", r"verify\s*=\s*False|InsecureSkipVerify:\s*true|rejectUnauthorized:\s*false|CURLOPT_SSL_VERIFYPEER,\s*(?:false|0)|ServerCertificateValidationCallback\s*=", None, "medium",
     "TLS certificate verification disabled", "weak-crypto"),
    ("legacy-ssl-protocol", r"SecurityProtocolType\.(?:Ssl3|Tls\b|Tls11)|PROTOCOL_TLSv1\b|SSLv3_method|TLSv1_method", None, "medium", "Legacy SSL/TLS protocol pinned in code", "legacy-tls"),
]
_RULES = [(rid, re.compile(rx, re.M), globs, sev, title, kb) for rid, rx, globs, sev, title, kb in CODE_RULES]

LANG_EXT = {".java": "Java", ".py": "Python", ".php": "PHP", ".js": "JavaScript", ".ts": "TypeScript", ".rb": "Ruby",
            ".go": "Go", ".cs": "C#", ".vb": "VB.NET", ".jsp": "JSP", ".aspx": "ASP.NET", ".asp": "Classic ASP",
            ".cfm": "ColdFusion", ".pl": "Perl", ".kt": "Kotlin", ".scala": "Scala", ".groovy": "Groovy"}

BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".class",
              ".dll", ".exe", ".so", ".dylib", ".mp4", ".mp3", ".svgz", ".bin", ".pyc", ".lock.bin"}


def _is_minified_lib(path: str) -> bool:
    return bool(re.search(r"(?:\.min\.js$|/(?:vendor|lib|libs|static|assets|public|bower_components|wwwroot|scripts?)/)", path, re.I))


def scan_tree(root: Path, log: Callable[[str], None], progress: Callable[[float, str], None],
              cancelled: Callable[[], bool], include_node_modules: bool = False) -> CodeScanResult:
    res = CodeScanResult()
    all_files = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and (include_node_modules or d != "node_modules")]
        for f in filenames:
            all_files.append((rel_dir, f))
    total = max(1, len(all_files))
    rule_hits: dict[str, dict] = {}
    for i, (rel_dir, fname) in enumerate(all_files):
        if cancelled():
            break
        if i % 200 == 0:
            progress(0.05 + 0.6 * i / total, f"reviewing files {i}/{total}")
        rel = f"{rel_dir}/{fname}" if rel_dir != "." else fname
        full = root / rel
        ext = PurePosixPath(fname).suffix.lower()
        res.files_scanned += 1
        if ext in LANG_EXT:
            res.languages[LANG_EXT[ext]] = res.languages.get(LANG_EXT[ext], 0) + 1
        try:
            size = full.stat().st_size
        except OSError:
            continue
        # Java archives: identify embedded libraries
        if ext in (".jar", ".war", ".ear"):
            if size < 150_000_000:
                comps = manifests.parse_jar(rel, full.read_bytes())
                res.components.extend(comps)
            continue
        if ext in BINARY_EXT or size > TEXT_LIMIT:
            continue
        parser = manifests.parser_for(fname)
        text = None
        if parser:
            try:
                text = full.read_text("utf-8", "ignore")
                comps = parser(rel, text)
                res.components.extend(comps)
                res.manifests.append(rel)
                if comps:
                    res.snippets.append({"path": rel, "kind": "manifest", "text": text[:6000]})
            except Exception as e:
                log(f"could not parse {rel}: {type(e).__name__}: {e}")
        if ext in (".js", ".css") and (_is_minified_lib(rel) or ext == ".js"):
            text = text or full.read_text("utf-8", "ignore")
            for c in match_js(text, fname, rel):
                c.source = "vendored-js"
                res.components.append(c)
        if ext in BINARY_EXT:
            continue
        # code / config rules
        if text is None:
            if ext not in LANG_EXT and ext not in (".xml", ".properties", ".yml", ".yaml", ".config", ".json", ".ini", ".env", ".html", ".htm", ".conf") and fname not in (".env",):
                continue
            if fname.endswith(".min.js"):
                continue
            text = full.read_text("utf-8", "ignore")
        for rid, rx, globs, sev, title, kb in _RULES:
            if globs and not (fname.endswith(globs) or fname in globs):
                continue
            if rid.startswith(("hardcoded", "generic-password", "private-key")) and re.search(r"(?:test|spec|example|sample|fixture|mock)", rel, re.I):
                continue
            for m in rx.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                line = text.splitlines()[line_no - 1] if text else ""
                hit = rule_hits.setdefault(rid, {"rid": rid, "severity": sev, "title": title, "kb": kb, "locations": []})
                if len(hit["locations"]) < 25:
                    redacted = re.sub(r"(['\"])[^'\"]{4,}(['\"])", r"\1***\2", line.strip()) if kb == "secrets" else line.strip()
                    hit["locations"].append({"path": rel, "line": line_no, "code": redacted[:240]})
                    if kb != "secrets" and len(res.snippets) < 60:
                        lines = text.splitlines()
                        lo, hi = max(0, line_no - 6), min(len(lines), line_no + 5)
                        res.snippets.append({"path": rel, "kind": rid, "line": line_no, "text": "\n".join(lines[lo:hi])})
                break_after = rid == "python2-syntax"
                if break_after:
                    break
    for hit in rule_hits.values():
        locs = hit["locations"]
        res.findings.append({
            "category": "code", "severity": hit["severity"], "title": hit["title"], "kb": hit["kb"], "rule": hit["rid"],
            "location": f"{locs[0]['path']}:{locs[0]['line']}" + (f" (+{len(locs)-1} more)" if len(locs) > 1 else ""),
            "locations": locs, "evidence": locs[0]["code"],
        })
    return res


def new_workdir(base: Path) -> Path:
    d = base / uuid.uuid4().hex[:12]
    d.mkdir(parents=True)
    return d
