"""RED tests: keyword-form sinks and interpreter flags in the Python engine."""
import textwrap

from injection_audit.engine import analyze_text


def res(code):
    return analyze_text(textwrap.dedent(code), filename="snippet.py")


def rules(code):
    return sorted({f.rule_id for f in res(code).findings})


def one(code, rule):
    fs = [f for f in res(code).findings if f.rule_id == rule]
    assert fs, f"expected {rule}, got {rules(code)}"
    return fs[0]


def test_executable_keyword_is_a_program_name_sink():
    f = one(
        """
        import subprocess, sys
        subprocess.Popen(["/bin/ls"], executable=sys.argv[1])
        """,
        "SIA-88-02",
    )
    assert "sys.argv" in f.source


def test_executable_constant_is_clean():
    assert rules(
        """
        import subprocess
        subprocess.Popen(["/bin/ls"], executable="/bin/ls")
        """
    ) == []


def test_args_keyword_with_shell_true():
    assert "SIA-78-03" in rules(
        """
        import subprocess, os
        subprocess.run(args="echo " + os.environ["CMD"], shell=True)
        """
    )


def test_dash_c_in_long_flag_form():
    """`bash -lc <tainted>` is still a re-parsed command string."""
    assert "SIA-78-03" in rules(
        """
        import subprocess, sys
        subprocess.run(["/bin/bash", "-lc", sys.argv[1]])
        """
    )


def test_env_assignment_then_shell_true():
    """Taint learned from an environment lookup reaches a later shell call."""
    assert "SIA-78-03" in rules(
        """
        import subprocess, os
        cmd = os.getenv("CMD")
        subprocess.call(cmd, shell=True)
        """
    )


def test_chained_method_on_tainted_value_is_still_tracked():
    assert "SIA-78-01" in rules(
        """
        import os, subprocess
        name = subprocess.check_output(["echo", os.environ["U"]]).decode().strip()
        os.system("kill " + name)
        """
    )


def test_shell_false_literal_suppresses_shell_rule_but_keeps_argv():
    findings = res(
        """
        import subprocess, sys
        subprocess.run(["git", "checkout", sys.argv[1]], shell=False)
        """
    ).findings
    ids = sorted(f.rule_id for f in findings)
    assert "SIA-78-03" not in ids
    assert "SIA-88-01" in ids


def test_starred_tainted_list_into_shell():
    assert "SIA-78-03" in rules(
        """
        import subprocess, sys
        args = sys.argv[1:]
        subprocess.run(["sh", "-c", *args], shell=True)
        """
    )


def test_getattr_indirection_is_not_claimed_as_clean():
    """`getattr(subprocess, 'run')(...)` is unresolved, so no shell rule fires.

    The report must stay silent rather than assert a weakness it cannot prove.
    """
    assert "SIA-78-03" not in rules(
        """
        import subprocess, os
        getattr(subprocess, "run")(os.environ["CMD"], shell=True)
        """
    )


def test_executable_via_alias_resolution():
    assert "SIA-88-02" in rules(
        """
        import subprocess as sp, sys
        sp.Popen(["/bin/ls"], executable=sys.argv[1])
        """
    )
