"""Regression tests for every defect found in the independent review.

Each test is a defect that was demonstrated with real engine output, not a
hypothetical. The engine is a paid audit artefact: a false positive is a
correctness bug, because it puts a wrong finding into a signed report.
"""
import json
import textwrap

from injection_audit.bash_analyzer import BashAnalyzer
from injection_audit.engine import analyze_repo, analyze_text, inventory_repo
from injection_audit.report import build_report, sign_report, verify_report


def py(code):
    return analyze_text(textwrap.dedent(code), filename="snippet.py")


def pyrules(code):
    return sorted({f.rule_id for f in py(code).findings})


def sh(code):
    return BashAnalyzer(textwrap.dedent(code), "snippet.sh").analyze()[0]


def shrules(code):
    return sorted({f.rule_id for f in sh(code)})


# ---------------- 1/3. alias bindings must respect scope and statement order ----------

def test_parameter_shadows_module_alias():
    assert pyrules(
        """
        import subprocess as sp
        import sys
        class Fake:
            def run(self, cmd, shell=False):
                return cmd
        def dispatch(sp):
            sp.run("ls " + sys.argv[1], shell=True)
        dispatch(Fake())
        """
    ) == []


def test_local_assignment_shadows_module_alias():
    assert pyrules(
        """
        import subprocess as sp
        import sys
        def dispatch():
            sp = safe_runner
            sp.run("ls " + sys.argv[1], shell=True)
        """
    ) == []


def test_binding_follows_statement_order():
    """A rebinding after the call must not erase the sink seen at the call."""
    assert "SIA-78-03" in pyrules(
        """
        import subprocess, sys
        f = subprocess.run
        f("ls " + sys.argv[1], shell=True)
        f = safe.run
        """
    )


def test_later_import_does_not_apply_to_earlier_code():
    assert pyrules(
        """
        import sys
        sp.run("ls " + sys.argv[1], shell=True)
        import subprocess as sp
        """
    ) == []


# ---------------- 2. web-source attribution must not over-approximate ----------------

def test_django_version_is_not_a_request_source():
    assert pyrules(
        """
        import subprocess, django
        subprocess.run("echo " + django.VERSION, shell=True)
        """
    ) == []


def test_flask_request_attribute_is_still_a_source():
    assert "SIA-78-03" in pyrules(
        """
        import subprocess
        from flask import request
        subprocess.run("echo " + request.args["host"], shell=True)
        """
    )


# ---------------- 4. a constant script path with tainted arguments ------------------

def test_constant_script_path_with_tainted_argument_is_clean():
    assert shrules(
        """
        #!/bin/sh
        read name
        bash ./greet.sh "$name"
        """
    ) == []


def test_nonconstant_script_path_is_still_flagged():
    assert "SIA-78-15" in shrules(
        """
        #!/bin/sh
        read script
        bash "$script"
        """
    )


# ---------------- 5. keywords quoted as data are not commands -----------------------

def test_quoted_echo_of_sudo_is_not_a_finding():
    assert shrules('#!/bin/sh\nread x\necho "use sudo $x carefully"\n') == []


def test_quoted_echo_of_shell_is_not_a_finding():
    assert shrules('#!/bin/sh\nread v\necho "run sh $v now"\n') == []


def test_real_run_as_before_a_quote_is_still_flagged():
    assert "SIA-78-13" in shrules(
        '#!/bin/sh\nread dest\nsudo rm -rf "$dest"\n'
    )


# ---------------- 6. -exec quoted as -name data -------------------------------------

def test_find_exec_token_inside_quotes_is_not_a_finding():
    assert shrules(
        """
        #!/bin/sh
        read pat
        find . -name "-exec" -o -name "$pat"
        """
    ) == []


def test_real_find_exec_is_still_flagged():
    assert "SIA-88-04" in shrules(
        '#!/bin/sh\nread t\nfind . -maxdepth 1 -exec rm -f "$t" {} \\; \n'
    )


# ---------------- 7. honest coverage for a lossily decoded source file --------------

def test_invalid_utf8_source_is_counted_as_analysed(tmp_path):
    (tmp_path / "bad.py").write_bytes(
        b'import os\nos.system("echo " + x)  # \xff\xfe comment\n')
    inventory = inventory_repo(tmp_path)
    assert inventory["analysable_paths"] == ["bad.py"]
    assert inventory["lossy_decode"] == ["bad.py"]
    assert inventory["skipped"] == []
    results = analyze_repo(tmp_path)
    assert len(results) == 1 and results[0].path == "bad.py"
    report = build_report(results, "lossy")
    coverage = report["coverage"]
    assert coverage["files_total"] == 1
    assert coverage["analysable"] == ["bad.py"]
    assert coverage["parse_errors"] == []


# ---------------- 8. a malformed signature must be rejected, not crash --------------

def _signed():
    report = build_report([], "empty")
    return sign_report(report, b"k" * 32)


def test_verify_rejects_non_string_signature_value():
    report = _signed()
    report["signature"]["value"] = None
    assert verify_report(report, b"k" * 32) is False


def test_verify_rejects_numeric_signature_value():
    report = _signed()
    report["signature"]["value"] = 12345
    assert verify_report(report, b"k" * 32) is False


def test_verify_rejects_structural_garbage():
    for bad in ({}, [], 7):
        report = _signed()
        report["signature"] = bad
        assert verify_report(report, b"k" * 32) is False


def test_verify_rejects_non_string_payload_digest():
    report = _signed()
    report["signature"]["payload_sha256"] = None
    assert verify_report(report, b"k" * 32) is False


def test_signed_report_still_verifies_after_the_guards():
    key = b"k" * 32
    assert verify_report(_signed(), key) is True
    assert json.loads(json.dumps(_signed()))["signature"]["alg"] == "HMAC-SHA256"
