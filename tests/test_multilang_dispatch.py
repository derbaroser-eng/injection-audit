"""RED tests for multi-language dispatch and shell-disguised commands.

The report is per-REPOSITORY, so every supported language must actually be
analysed, and a repository that hides shell work in extensionless scripts or
Makefiles must not get a clean-looking report by accident.
"""
import textwrap

from injection_audit.engine import analyze_repo, analyze_text, inventory_repo


def res(code, **kw):
    kw.setdefault("filename", "snippet.py")
    return analyze_text(textwrap.dedent(code), **kw)


def rules(code, **kw):
    return sorted({f.rule_id for f in res(code, **kw).findings})


# ---------------- language dispatch ----------------

def test_analyze_text_dispatches_by_extension(tmp_path):
    sh = tmp_path / "run.sh"
    sh.write_text('#!/bin/sh\nsh -c "$1"\n', encoding="utf-8")
    result = analyze_text(sh.read_text(encoding="utf-8"), filename=str(sh))
    assert result.language == "bash"
    assert any(f.rule_id == "SIA-78-11" for f in result.findings)


def test_makefile_is_analysed_as_shell(tmp_path):
    (tmp_path / "Makefile").write_text(
        'build:\n\tsh -c "$(CMD)"\n', encoding="utf-8")
    results = analyze_repo(tmp_path)
    assert len(results) == 1, results
    assert results[0].language == "bash"
    assert any(f.rule_id == "SIA-78-11" for f in results[0].findings)


def test_extensionless_executable_is_analysed(tmp_path):
    script = tmp_path / "deploy"
    script.write_text('#!/bin/sh\nread p\neval "$p"\n', encoding="utf-8")
    results = analyze_repo(tmp_path)
    assert any(r.path == "deploy" and r.language == "bash" for r in results)
    assert any(f.rule_id == "SIA-78-10" for r in results for f in r.findings)


def test_python_does_not_scan_shell_heredocs(tmp_path):
    """A Python file containing a shell heredoc is not evidence of a shell bug."""
    # The triple-quoted block is shell TEMPLATE data, not code: the eval inside
    # it must never be reported as a shell finding. The canary is a genuine
    # tainted os.system() call so we prove the Python analyser still ran.
    # (A constant os.system() is intentionally clean — see
    #  test_constant_command_is_clean in test_python_engine.py.)
    source = (
        "import os, sys\n"
        "TEMPLATE = '''\n"
        "set -e\n"
        'eval "$1"\n'
        "'''\n"
        "os.system('echo ' + sys.argv[1])\n"
    )
    result = analyze_text(source, filename="template.py")
    assert [f.rule_id for f in result.findings] == ["SIA-78-01"]


# ---------------- shells disguised as interpreter arguments ----------------

def test_sh_c_flag_is_a_shell_sink():
    code = (
        "import subprocess, sys\n"
        'subprocess.run(["sh", "-c", "cat " + sys.argv[1]])\n'
    )
    assert "SIA-78-03" in rules(code)


def test_sh_dash_c_short_flag_is_a_shell_sink():
    code = (
        "import subprocess, sys\n"
        "cmd = \"cat \" + sys.argv[1]\n"
        'subprocess.Popen(["/bin/bash", "-c", cmd])\n'
    )
    assert "SIA-78-03" in rules(code)


def test_tainted_command_without_dash_c_stays_argument_injection():
    code = (
        "import subprocess, sys\n"
        'subprocess.run(["sh", "cat " + sys.argv[1]])\n'
    )
    found = rules(code)
    assert "SIA-78-03" not in found
    assert "SIA-88-02" in found


def test_constant_shell_script_is_clean():
    assert rules(
        'import subprocess\nsubprocess.run(["sh", "-c", "make all"])\n'
    ) == []


def test_unknown_interpreter_with_dash_c_is_not_called_a_shell():
    assert "SIA-78-03" not in rules(
        "import subprocess, sys\n"
        'subprocess.run(["mytool", "-c", "run " + sys.argv[1]])\n'
    )


def test_tainted_arg_to_interpreter_still_reports_option_injection():
    code = (
        "import subprocess, sys\n"
        'subprocess.run(["sh", "-c", "cat " + sys.argv[1]])\n'
    )
    assert "SIA-88-01" in rules(code)


# ---------------- engine robustness ----------------

def test_os_system_without_arguments_does_not_crash():
    r = res("import os\nos.system()\n")
    assert r.error is None and r.findings == []


def test_starred_argv_elements_are_inspected():
    code = (
        "import subprocess, sys\n"
        "extra = [sys.argv[1]]\n"
        "subprocess.run(['git', 'checkout', *extra], shell=False)\n"
    )
    assert "SIA-88-01" in rules(code)


def test_unparsable_file_is_reported_as_parse_error(tmp_path):
    (tmp_path / "junk.py").write_bytes(b"def \xff\xfe(: pass\n")
    results = analyze_repo(tmp_path)
    assert results and results[0].error


def test_inventory_agrees_with_dispatch_for_shell_entrypoints(tmp_path):
    """Coverage must not call a file 'skipped' that the analyser actually read.

    A signed report whose findings cite a Makefile but whose coverage block
    lists that same Makefile as unsupported is internally contradictory.
    """
    (tmp_path / "Makefile").write_text('build:\n\tsh -c "$(CMD)"\n', encoding="utf-8")
    (tmp_path / "deploy").write_text('#!/bin/sh\nread x\neval "$x"\n', encoding="utf-8")
    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")
    analysed = {r.path for r in analyze_repo(tmp_path)}
    inventory = inventory_repo(tmp_path)
    analysable = set(inventory["analysable_paths"])
    skipped = {item["path"] for item in inventory["skipped"]}
    assert {"Makefile", "deploy"} <= analysed
    assert analysed <= analysable, analysed - analysable
    assert not (analysed & skipped), analysed & skipped
