"""Regression tests for every defect found in the independent review."""
import json

from injection_audit.bash_analyzer import BashAnalyzer
from injection_audit.engine import analyze_text
from injection_audit.model import Finding, FileResult
from injection_audit.report import build_report, sign_report, verify_report


def rules(code, **kwargs):
    return sorted({f.rule_id for f in analyze_text(code, **kwargs).findings})


def test_from_import_quote_is_sanitizer():
    code = ("from shlex import quote\n"
            "import subprocess, sys\n"
            'subprocess.run(f"echo {quote(sys.argv[1])}", shell=True)\n')
    assert rules(code) == []


def test_request_get_json_is_source():
    code = ("import os\n"
            "from flask import request\n"
            "os.system('ping ' + request.get_json()['host'])\n")
    assert "SIA-78-01" in rules(code)


def test_method_call_interprocedural():
    code = ("import os, sys\n"
            "class C:\n"
            "    def run(self, cmd):\n"
            '        os.system("echo " + cmd)\n'
            "C().run(sys.argv[1])\n")
    assert "SIA-78-01" in rules(code)


def test_getoutput_is_shell_sink():
    found = [f for f in analyze_text(
        "import subprocess, sys\nsubprocess.getoutput('ls ' + sys.argv[1])\n"
    ).findings if f.rule_id == "SIA-78-03"]
    assert found and found[0].severity == "high"


def test_bare_sys_argv_is_source():
    code = "import subprocess, sys\nsubprocess.run(' '.join(sys.argv), shell=True)\n"
    assert "SIA-78-03" in rules(code)


def test_attribute_assignment_is_tracked():
    code = ("import os, sys\n"
            "class X: pass\n"
            "obj = X()\n"
            "obj.cmd = sys.argv[1]\n"
            "os.system(obj.cmd)\n")
    assert "SIA-78-01" in rules(code)


def test_subscript_assignment_is_tracked():
    code = ("import os, sys\n"
            "d = {}\n"
            "d['cmd'] = sys.argv[1]\n"
            "os.system(d['cmd'])\n")
    assert "SIA-78-01" in rules(code)


def test_shell_flag_via_variable():
    code = ("import subprocess, sys\n"
            "s = True\n"
            'subprocess.run(f"ls {sys.argv[1]}", shell=s)\n')
    assert "SIA-78-03" in rules(code)


def test_absolute_interpreter_path():
    findings, _ = BashAnalyzer('#!/bin/sh\n/bin/sh -c "$1"\n', "x.sh").analyze()
    assert any(f.rule_id == "SIA-78-11" for f in findings)


def test_absolute_ssh_path():
    findings, _ = BashAnalyzer(
        '#!/bin/sh\n/usr/bin/ssh host "ls $1"\n', "x.sh").analyze()
    assert any(f.rule_id == "SIA-78-12" for f in findings)


def test_signature_metadata_is_bound():
    key = b"k" * 32
    finding = Finding(rule_id="SIA-78-01", cwe="CWE-78", severity="high",
                      line=1, col=0, evidence="os.system(x)", sink="os.system()",
                      source="sys.argv", message="m")
    report = sign_report(build_report(
        [FileResult(path="a.py", language="python", content_sha256="0" * 64,
                    findings=[finding])], "repo"), key)
    for field, value in (("alg", "none"), ("key_id", "forged"),
                         ("payload_sha256", "0" * 64)):
        tampered = json.loads(json.dumps(report))
        tampered["signature"][field] = value
        assert not verify_report(tampered, key)
