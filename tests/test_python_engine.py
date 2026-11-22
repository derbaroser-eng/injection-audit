"""RED tests for the Python taint engine. Run: python -m pytest -q"""
import hashlib
import textwrap

import pytest

from injection_audit.engine import analyze_text, analyze_file, analyze_repo


def res(code, **kw):
    kw.setdefault("filename", "snippet.py")
    return analyze_text(textwrap.dedent(code), **kw)


def rules(code, **kw):
    return sorted({f.rule_id for f in res(code, **kw).findings})


def one(code, rule, **kw):
    fs = [f for f in res(code, **kw).findings if f.rule_id == rule]
    assert fs, f"expected {rule}, got {rules(code, **kw)}"
    return fs[0]


# ---------------- CWE-78 sinks ----------------

def test_os_system_from_argv():
    f = one(
        """
        import os, sys
        os.system("rm -rf " + sys.argv[1])
        """,
        "SIA-78-01",
    )
    assert f.line == 3 and "os.system" in f.evidence
    assert "sys.argv" in f.source


def test_os_popen_from_environ():
    f = one(
        """
        import os
        os.popen(os.environ["CMD"]).read()
        """,
        "SIA-78-02",
    )
    assert "os.environ" in f.source


def test_subprocess_shell_true_fstring():
    f = one(
        """
        import os, subprocess
        branch = os.getenv("BRANCH")
        subprocess.run(f"git checkout {branch}", shell=True)
        """,
        "SIA-78-03",
    )
    assert f.severity == "high" and f.cwe == "CWE-78"


def test_subprocess_percent_format():
    f = one(
        """
        import subprocess, sys
        subprocess.Popen("deploy %s" % sys.argv[1], shell=True)
        """,
        "SIA-78-03",
    )
    assert "sys.argv" in f.source


def test_subprocess_format_method_and_concat():
    code = (
        "import subprocess, sys\n"
        "user = sys.argv[1]\n"
        'subprocess.check_output("echo {}".format(user), shell=True)\n'
    )
    assert "SIA-78-03" in rules(code)


def test_asyncio_create_subprocess_shell():
    f = one(
        """
        import asyncio, sys
        asyncio.create_subprocess_shell(f"ls {sys.argv[1]}")
        """,
        "SIA-78-04",
    )
    assert f.line == 3


def test_exec_family():
    code = (
        "import os, sys\n"
        'os.execl("/bin/sh", "sh", sys.argv[1])\n'
    )
    assert "SIA-78-05" in rules(code)


def test_eval_of_tainted_expression():
    f = one(
        """
        import sys
        eval(sys.argv[1])
        """,
        "SIA-95-01",
    )
    assert f.cwe == "CWE-95"


# ---------------- taint propagation ----------------

def test_interprocedural_parameter_taint():
    f = one(
        """
        import os, sys
        def run(cmd_name):
            os.system("run " + cmd_name)
        run(sys.argv[1])
        """,
        "SIA-78-01",
    )
    assert f.line == 4 and "sys.argv" in f.source


def test_return_value_propagates():
    code = (
        "import os, sys\n"
        "def get():\n"
        "    return sys.argv[1]\n"
        "cmd = get()\n"
        "os.system('echo ' + cmd)\n"
    )
    assert "SIA-78-01" in rules(code)


def test_open_of_user_path_taints_contents():
    code = (
        "import os, sys\n"
        "data = open(sys.argv[1]).read()\n"
        "os.system('grep -R x ' + data)\n"
    )
    assert "SIA-78-01" in rules(code)


def test_request_args_source():
    code = (
        "import os\n"
        "from flask import request\n"
        'os.system("ping " + request.args.get("host"))\n'
    )
    assert "SIA-78-01" in rules(code)


def test_argparse_namespace_taint():
    code = (
        "import argparse, os\n"
        "p = argparse.ArgumentParser()\n"
        "args = p.parse_args()\n"
        "os.system('echo ' + args.name)\n"
    )
    assert "SIA-78-01" in rules(code)


def test_taint_through_join_and_list():
    code = (
        "import subprocess, sys\n"
        'subprocess.run(" ".join(["git", "checkout", sys.argv[1]]), shell=True)\n'
    )
    assert "SIA-78-03" in rules(code)


# ---------------- CWE-88 argument injection ----------------

def test_argv_injection_is_reported_low():
    f = one(
        """
        import subprocess, sys
        subprocess.run(["git", "checkout", sys.argv[1]], shell=False)
        """,
        "SIA-88-01",
    )
    assert f.severity == "low"
    assert "option" in f.message.lower() or "argument" in f.message.lower()


def test_tainted_program_name_is_medium():
    f = one(
        """
        import subprocess, sys
        subprocess.run([sys.argv[1], "arg"], shell=False)
        """,
        "SIA-88-02",
    )
    assert f.severity == "medium"


def test_msys_argv_expansion_flagged_on_windows():
    f = one(
        """
        import os, subprocess
        d = os.environ["TARGET"]
        subprocess.run("cd " + d + " && make", shell=True)
        """,
        "SIA-88-03",
        platform_hint="Windows",
    )
    assert f.severity == "info"
    assert "MSYS" in f.message


def test_msys_rule_absent_on_posix():
    r = rules(
        """
        import os, subprocess
        d = os.environ["TARGET"]
        subprocess.run("cd " + d + " && make", shell=True)
        """,
        platform_hint="Linux",
    )
    assert "SIA-88-03" not in r


# ---------------- clean code stays clean ----------------

def test_constant_command_is_clean():
    assert rules("import os\nos.system('ls -la')\n") == []


def test_argv_list_constant_is_clean():
    assert rules(
        "import subprocess\nsubprocess.run(['git', 'status', '--porcelain'])\n"
    ) == []


def test_shlex_quote_sanitizes():
    assert rules(
        """
        import shlex, subprocess, sys
        name = sys.argv[1]
        subprocess.run(f"echo {shlex.quote(name)}", shell=True)
        """
    ) == []


def test_safe_helper_without_shell_is_clean():
    assert rules(
        """
        import shellguard as sg
        import sys
        sg.run(["echo", sys.argv[1]])
        """
    ) == []


# ---------------- robustness / metadata ----------------

def test_syntax_error_is_recorded_not_raised():
    r = res("def broken(:\n    pass\n")
    assert r.error and "syntax" in r.error.lower()
    assert r.findings == []


def test_content_hash_matches_bytes():
    code = "import os\nos.system('ls')\n"
    r = res(code)
    assert r.content_sha256 == hashlib.sha256(code.encode()).hexdigest()


def test_evidence_quotes_the_offending_line():
    code = "import os, sys\nos.system('rm -rf ' + sys.argv[1])\n"
    f = one(code, "SIA-78-01")
    assert f.evidence.strip() == "os.system('rm -rf ' + sys.argv[1])"
    assert f.sink.startswith("os.system")


def test_findings_sorted_by_line():
    code = (
        "import os, sys\n"
        "os.system('a' + sys.argv[1])\n"
        "os.system('b' + sys.argv[2])\n"
    )
    fs = res(code).findings
    assert [f.line for f in fs] == sorted(f.line for f in fs)


def test_finding_fields_are_populated():
    f = one(
        "import os, sys\nos.system('x' + sys.argv[1])\n", "SIA-78-01"
    )
    assert f.rule_id and f.cwe and f.severity and f.message
    assert f.file == "snippet.py" and f.line >= 1 and f.col >= 0


# ---------------- repo level ----------------

def test_repo_scans_python_and_skips_other_extensions(tmp_path):
    (tmp_path / "a.py").write_text("import os, sys\nos.system('x' + sys.argv[1])\n")
    (tmp_path / "notes.txt").write_text("os.system('fake')\n")
    (tmp_path / "img.bin").write_bytes(b"\x00\x01os.system('fake')")
    results = analyze_repo(tmp_path)
    paths = {r.path for r in results}
    assert any(p.endswith("a.py") for p in paths)
    assert not any(p.endswith(".txt") for p in paths)
    assert not any(p.endswith(".bin") for p in paths)


def test_repo_records_parse_failure_as_coverage(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n")
    results = analyze_repo(tmp_path)
    assert len(results) == 1
    assert results[0].error
