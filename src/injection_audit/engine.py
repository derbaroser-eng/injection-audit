"""Repository orchestration: discovery, language dispatch, honest inventory."""
import hashlib
import os
import re

from .model import FileResult
from .python_analyzer import PythonAnalyzer

LANG_BY_EXT = {
    ".py": "python",
    ".sh": "bash", ".bash": "bash", ".zsh": "bash", ".ksh": "bash",
    ".mk": "bash", ".mak": "bash", ".make": "bash", ".cmake": "bash",
}
SHELL_BASENAMES = {"makefile", "gnumakefile", "dockerfile", "procfile",
                   "justfile", "rakefile", "brewfile"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".mypy_cache",
             ".pytest_cache", "dist", "build", ".hg", ".svn", "vendor"}
MAX_BYTES = 2_000_000


def language_for(path):
    """Return the analyser language for a path, or None.

    Extension first, then well-known shell build-entry filenames, then an
    extensionless executable whose shebang names a shell interpreter.
    """
    name = os.path.basename(str(path))
    ext = os.path.splitext(name)[1].lower()
    lang = LANG_BY_EXT.get(ext)
    if lang:
        return lang
    lowered = name.lower()
    if lowered in SHELL_BASENAMES:
        return "bash"
    if ext:
        return None
    try:
        with open(path, "rb") as handle:
            head = handle.readline(256)
    except OSError:
        return None
    if not head.startswith(b"#!"):
        return None
    if re.search(rb"(^|/)(sh|bash|zsh|dash|ksh|ash)\b", head):
        return "bash"
    return None


def _analyze(code, lang, rel, digest, platform_hint=None):
    if lang == "python":
        analyzer = PythonAnalyzer(code, rel, platform=platform_hint)
    elif lang == "bash":
        from .bash_analyzer import BashAnalyzer
        analyzer = BashAnalyzer(code, rel, platform=platform_hint)
    else:
        return FileResult(path=rel, language=lang, content_sha256=digest,
                          skipped_reason="no analyser available")
    findings, error = analyzer.analyze()
    if error:
        return FileResult(path=rel, language=lang, content_sha256=digest, error=error)
    for finding in findings:
        finding.file = rel
        finding.content_sha256 = digest
    return FileResult(path=rel, language=lang, content_sha256=digest, findings=findings)


def analyze_text(code, filename="snippet.py", platform_hint=None):
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
    ext = os.path.splitext(str(filename))[1].lower()
    lang = LANG_BY_EXT.get(ext, "python")
    return _analyze(code, lang, filename, digest, platform_hint=platform_hint)


def _read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def _classify(raw):
    """Return a skip reason or None."""
    if len(raw) > MAX_BYTES:
        return f"size {len(raw)} bytes exceeds {MAX_BYTES}"
    if b"\x00" in raw[:8192]:
        return "binary content"
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return "not valid UTF-8"
    return None


def analyze_file(path, rel=None, platform_hint=None):
    rel = rel or os.path.basename(str(path))
    lang = language_for(path)
    try:
        raw = _read_bytes(path)
    except OSError as exc:
        return FileResult(path=rel, language=lang or "",
                          skipped_reason=f"unreadable: {exc.strerror}")
    digest = hashlib.sha256(raw).hexdigest()
    reason = _classify(raw)
    if reason == "not valid UTF-8" and lang is not None:
        # A source file we recognise must be accounted for HONESTLY: decode
        # lossily and let the parser record the failure as an error, rather
        # than dropping the file from the report entirely.
        return _analyze(raw.decode("utf-8", errors="replace"), lang, rel, digest,
                        platform_hint=platform_hint)
    if reason:
        return FileResult(path=rel, language=lang or "", content_sha256=digest,
                          skipped_reason=reason)
    if lang is None:
        ext = os.path.splitext(str(path))[1].lower() or "(none)"
        return FileResult(path=rel, language="", content_sha256=digest,
                          skipped_reason=f"unsupported extension {ext!r}")
    return _analyze(raw.decode("utf-8"), lang, rel, digest, platform_hint=platform_hint)


def _walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            yield os.path.join(dirpath, name), name


def analyze_repo(root, langs=None, platform_hint=None):
    root = os.path.abspath(str(root))
    results = []
    for path, name in _walk(root):
        lang = language_for(path)
        if lang is None or (langs and lang not in langs):
            continue
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        result = analyze_file(path, rel=rel, platform_hint=platform_hint)
        if result.skipped_reason:
            continue
        results.append(result)
    return sorted(results, key=lambda r: r.path)


def inventory_repo(root):
    """Honest coverage input: every file accounted for, with reasons."""
    root = os.path.abspath(str(root))
    by_extension = {}
    skipped = []
    analysable = []
    total = 0
    for path, name in _walk(root):
        total += 1
        ext = os.path.splitext(name)[1].lower() or "(none)"
        by_extension[ext] = by_extension.get(ext, 0) + 1
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        lang = language_for(path)
        try:
            raw = _read_bytes(path)
        except OSError as exc:
            skipped.append({"path": rel, "reason": f"unreadable: {exc.strerror}"})
            continue
        reason = _classify(raw)
        if reason:
            skipped.append({"path": rel, "reason": reason})
            continue
        if lang is None:
            skipped.append({"path": rel, "reason": f"unsupported extension {ext!r}"})
            continue
        analysable.append(rel)
    return {
        "files_total": total,
        "by_extension": dict(sorted(by_extension.items())),
        "analysable_paths": sorted(analysable),
        "skipped": skipped,
    }
