"""The artefact must name the exact rule catalogue it applied, and stay stable."""
import re

from injection_audit.model import FileResult, Finding
from injection_audit.report import build_report, render_markdown, ruleset_digest
from injection_audit.rules import RULE_META


def _report():
    finding = Finding(rule_id="SIA-78-01", cwe="CWE-78", severity="high",
                      line=3, col=0, evidence='os.system("rm " + x)',
                      sink="os.system()", source="sys.argv",
                      message="os.system() executes attacker-influenced text.")
    result = FileResult(path="app.py", language="python", content_sha256="a" * 64,
                        findings=[finding])
    return build_report([result], "demo")


def test_ruleset_digest_is_stable_and_shaped():
    digest = ruleset_digest()
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert digest == ruleset_digest()


def test_ruleset_digest_covers_every_rule():
    before = ruleset_digest()
    original = dict(RULE_META)
    try:
        RULE_META["SIA-99-99"] = ("CWE-000", "info", "probe")
        assert ruleset_digest() != before
    finally:
        RULE_META.clear()
        RULE_META.update(original)
    assert ruleset_digest() == before


def test_report_records_the_ruleset():
    report = _report()
    ruleset = report["tool"]["ruleset"]
    assert ruleset["rule_count"] == len(RULE_META)
    assert ruleset["sha256"] == ruleset_digest()


def test_markdown_shows_the_ruleset():
    text = render_markdown(_report())
    assert "Ruleset:" in text
    assert ruleset_digest() in text


def test_limitations_are_stated_in_the_artefact():
    coverage = _report()["coverage"]
    assert coverage["limitations"]
    joined = " ".join(coverage["limitations"])
    assert "not a full shell parser" in joined
    assert "getattr" in joined


def test_report_id_carries_the_ruleset():
    """Two engine versions must not collide on the same report id."""
    report = _report()
    assert report["report_id"].endswith(ruleset_digest()[:8])
    before = ruleset_digest()
    original = dict(RULE_META)
    try:
        RULE_META["SIA-99-99"] = ("CWE-000", "info", "probe")
        assert _report()["report_id"] != report["report_id"]
    finally:
        RULE_META.clear()
        RULE_META.update(original)
