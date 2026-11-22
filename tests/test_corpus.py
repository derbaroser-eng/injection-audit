"""End-to-end tests over the committed mixed-language demo corpus."""
from pathlib import Path

from injection_audit.engine import analyze_repo, inventory_repo

ROOT = Path(__file__).resolve().parents[1] / "corpus" / "demo-app"


def test_corpus_finds_expected_rules():
    results = analyze_repo(ROOT)
    found = sorted({f.rule_id for r in results for f in r.findings})
    assert "SIA-78-01" in found
    assert "SIA-78-03" in found
    assert "SIA-78-10" in found
    assert "SIA-78-11" in found
    assert "SIA-78-12" in found


def test_corpus_coverage_is_honest():
    inventory = inventory_repo(ROOT)
    reasons = " | ".join(item["reason"] for item in inventory["skipped"])
    assert inventory["files_total"] == 6
    assert "unsupported extension" in reasons
    assert "binary" in reasons
    errors = [r.path for r in analyze_repo(ROOT) if r.error]
    assert errors == ["broken.py"]


def test_corpus_safe_lines_are_not_findings():
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "shlex.quote" in app
    results = {r.path: r for r in analyze_repo(ROOT)}
    lines = {f.line for f in results["app.py"].findings}
    assert 11 not in lines  # build_greeting's shlex-quoted f-string
    assert 21 not in lines  # status()'s constant argv list
    assert 16 in lines and 27 in lines
