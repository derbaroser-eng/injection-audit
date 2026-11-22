"""RED/GREEN tests for the dated, signed report artefact and the CLI."""
import datetime
import hashlib
import json

import pytest

from injection_audit import cli
from injection_audit.model import Finding, FileResult
from injection_audit.report import (DISCLAIMER, build_report, canonical_bytes,
                                    key_fingerprint, render_markdown,
                                    sign_report, verify_report)


def mk(path="pkg/app.py", findings=None, error=None, language="python"):
    return FileResult(path=path, language=language,
                      content_sha256=hashlib.sha256(path.encode()).hexdigest(),
                      findings=list(findings or []), error=error)


def finding(**overrides):
    data = dict(rule_id="SIA-78-03", cwe="CWE-78", severity="high",
                line=12, col=4, evidence='subprocess.run(f"ls {p}", shell=True)',
                sink="subprocess.run()", source="sys.argv[...]",
                message=("OS command injection (CWE-78): subprocess launched with "
                         "shell=True and attacker-influenced command text. "
                         "Data source: sys.argv[...]."),
                file="", content_sha256="")
    data.update(overrides)
    return Finding(**data)


# --------------------------------------------------------------- artefact ---

def test_report_is_dated_and_numbered():
    rep = build_report([mk(findings=[finding()]),
                        mk(path="b.py", findings=[finding(
                            rule_id="SIA-88-01", cwe="CWE-88", severity="low",
                            line=3, sink="subprocess.run()", message="arg")])],
                       "acme/api")
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    assert rep["delivery_date"] == today
    assert rep["report_id"].startswith(f"SIA-{today}-")
    assert rep["findings"][0]["id"] == "F-0001"
    assert rep["findings"][1]["id"] == "F-0002"
    assert rep["scope"]["findings_total"] == 2
    assert rep["schema"].startswith("injection-audit/report@")


def test_signature_roundtrip_and_tamper_detection():
    key = b"k" * 32
    rep = build_report([mk(findings=[finding()])], "repo")
    sign_report(rep, key)
    assert verify_report(rep, key)
    assert verify_report(json.loads(json.dumps(rep)), key)

    tampered = json.loads(json.dumps(rep))
    tampered["findings"][0]["evidence"] = "tampered"
    assert not verify_report(tampered, key)

    forged = json.loads(json.dumps(rep))
    forged["signature"]["value"] = "00" * 32
    assert not verify_report(forged, key)

    assert not verify_report(rep, b"x" * 32)
    assert not verify_report({"findings": []}, key)


def test_canonical_bytes_are_stable():
    rep = build_report([mk(findings=[finding()])], "repo")
    clone = json.loads(json.dumps(rep))
    assert canonical_bytes(rep) == canonical_bytes(clone)
    assert key_fingerprint(b"a" * 32) != key_fingerprint(b"b" * 32)


def test_content_hash_change_changes_report_id():
    first = build_report([mk(path="a.py")], "repo")
    changed = mk(path="a.py")
    changed.content_sha256 = "0" * 64
    second = build_report([changed], "repo")
    assert first["report_id"] != second["report_id"]
    assert first["scope"]["content_digest"] != second["scope"]["content_digest"]


def test_coverage_is_stated_honestly():
    inventory = {
        "files_total": 5,
        "by_extension": {".py": 3, ".txt": 2},
        "analysable_paths": ["a.py"],
        "skipped": [{"path": "notes.txt", "reason": "unsupported extension '.txt'"}],
    }
    rep = build_report([mk(path="a.py")], "repo", inventory=inventory)
    coverage = rep["coverage"]
    assert coverage["stated_honestly"] is True
    assert coverage["files_total"] == 5
    assert coverage["by_extension"][".txt"] == 2
    assert coverage["skipped"][0]["reason"]
    assert coverage["limitations"]
    assert coverage["parse_errors"] == []
    errored = build_report([mk(path="bad.py", error="syntax error: '('")], "repo")
    assert errored["coverage"]["parse_errors"][0]["path"] == "bad.py"


def test_disclaimer_and_absence_of_compliance_claims():
    rep = build_report([mk(findings=[finding()])], "repo")
    assert "not a compliance certification" in rep["disclaimer"]
    assert "not a guarantee" in rep["disclaimer"]
    for item in rep["findings"]:
        low = item["message"].lower()
        assert "certif" not in low and "guarantee" not in low and "complian" not in low


def test_markdown_renders_every_artefact_property():
    rep = build_report([mk(findings=[finding()])], "repo")
    sign_report(rep, b"k" * 32)
    md = render_markdown(rep)
    assert rep["report_id"] in md
    assert rep["delivery_date"] in md
    assert "F-0001" in md and "SIA-78-03" in md
    assert rep["findings"][0]["content_sha256"] in md
    assert "Coverage" in md and "Limitations" in md
    assert rep["disclaimer"] in md
    assert rep["signature"]["value"] in md


def test_markdown_without_findings():
    rep = build_report([mk()], "repo")
    assert "No findings were recorded" in render_markdown(rep)


# -------------------------------------------------------------------- CLI ---

def test_cli_init_scan_verify_end_to_end(tmp_path):
    repo = tmp_path / "demo-repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import os, sys\nos.system('echo ' + sys.argv[1])\n", encoding="utf-8")
    (repo / "README.md").write_text("# demo\n", encoding="utf-8")
    key = tmp_path / "keys" / "audit.key"
    assert cli.main(["init-key", "--out", str(key)]) == 0
    out = tmp_path / "out"
    assert cli.main(["scan", str(repo), "--out", str(out),
                     "--key-file", str(key)]) == 0
    reports = list(out.glob("report-*.json"))
    assert len(reports) == 1
    rep = json.loads(reports[0].read_text(encoding="utf-8"))
    assert rep["scope"]["findings_total"] >= 1
    assert rep["coverage"]["files_total"] == 2
    assert any(item["path"].endswith("README.md")
               for item in rep["coverage"]["skipped"])
    assert list(out.glob("report-*.md"))
    assert list(out.glob("report-*.json.sig"))
    assert cli.main(["verify", str(reports[0]), "--key-file", str(key)]) == 0


def test_cli_scan_without_key_exits_3(tmp_path, monkeypatch):
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.delenv("INJECTION_AUDIT_KEY", raising=False)
    assert cli.main(["scan", str(repo), "--out", str(tmp_path / "o")]) == 3


def test_cli_verify_tampered_report_exits_1(tmp_path):
    key_file = tmp_path / "k.bin"
    key_file.write_bytes(b"q" * 32)
    rep = sign_report(build_report([mk(findings=[finding()])], "repo"), b"q" * 32)
    rep["findings"][0]["line"] = 999
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(rep), encoding="utf-8")
    assert cli.main(["verify", str(bad), "--key-file", str(key_file)]) == 1


def test_cli_usage_error_exits_2():
    with pytest.raises(SystemExit) as excinfo:
        cli.main([])
    assert excinfo.value.code == 2
