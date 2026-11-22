"""RED tests: import/member alias resolution must not hide sinks.

A scanner that only matches the literal dotted name `subprocess.run` misses the
same sink behind `import subprocess as sp`, `from subprocess import run`, or a
local rebinding. Those are ordinary Python and are common in real codebases, so
they are false negatives a paid audit report cannot contain.
"""
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


def test_module_alias_import():
    f = one(
        """
        import subprocess as sp
        import sys
        sp.run(f"ls {sys.argv[1]}", shell=True)
        """,
        "SIA-78-03",
    )
    assert f.sink == "subprocess.run()"  # resolved to the real API, not the alias


def test_from_import_bare_name():
    f = one(
        """
        from subprocess import run
        import os
        run("echo " + os.environ["X"], shell=True)
        """,
        "SIA-78-03",
    )
    assert "os.environ" in f.source


def test_from_import_renamed_member():
    assert "SIA-78-03" in rules(
        """
        from subprocess import Popen as P
        import sys
        P("cat %s" % sys.argv[1], shell=True)
        """
    )


def test_os_system_via_alias():
    assert "SIA-78-01" in rules(
        """
        import os as operating_system
        import sys
        operating_system.system(sys.argv[1])
        """
    )


def test_local_rebinding_of_sink():
    assert "SIA-78-03" in rules(
        """
        import subprocess, sys
        run = subprocess.run
        run("echo " + sys.argv[1], shell=True)
        """
    )


def test_asyncio_shell_via_alias():
    assert "SIA-78-04" in rules(
        """
        import asyncio as aio
        import sys
        aio.create_subprocess_shell("run " + sys.argv[1])
        """
    )


def test_eval_via_builtins_from_import():
    assert "SIA-95-01" in rules(
        """
        from builtins import eval
        import sys
        eval(sys.argv[1])
        """
    )


def test_exec_sink_via_alias():
    assert "SIA-78-05" in rules(
        """
        import os as o
        import sys
        o.execvp(sys.argv[1], [sys.argv[1]])
        """
    )


def test_unrelated_name_is_not_resolved():
    """A local variable that merely shares a sink's bare name stays clean."""
    assert rules(
        """
        run = print
        run("hello")
        """
    ) == []


def test_alias_does_not_leak_into_other_modules():
    """Bindings are per-module; a snippet without the import is unaffected."""
    assert rules(
        """
        import sys
        run("echo " + sys.argv[1], shell=True)
        """
    ) == []


# ---------------- sources reached through an alias ----------------

def test_taint_source_via_module_alias():
    f = one(
        """
        import os as operating_system
        import subprocess
        subprocess.run(operating_system.getenv("CMD"), shell=True)
        """,
        "SIA-78-03",
    )
    assert "os.getenv" in f.source


def test_taint_source_via_from_import_alias():
    f = one(
        """
        from os import getenv as env_value
        import subprocess
        subprocess.run(env_value("CMD"), shell=True)
        """,
        "SIA-78-03",
    )
    assert "os.getenv" in f.source


def test_argv_subscript_via_module_alias():
    assert "SIA-78-03" in rules(
        """
        import sys as system
        import subprocess
        subprocess.run("ls " + system.argv[1], shell=True)
        """
    )


def test_environ_get_via_from_import():
    assert "SIA-78-03" in rules(
        """
        from os import environ
        import subprocess
        subprocess.run(environ.get("CMD"), shell=True)
        """
    )


def test_request_attribute_via_alias_stays_a_source():
    assert "SIA-78-01" in rules(
        """
        from flask import request as req
        import os
        os.system("ping " + req.args["host"])
        """
    )


def test_alias_bound_to_unrelated_call_is_not_a_source():
    assert rules(
        """
        import subprocess
        from math import sqrt as getenv
        subprocess.run("echo " + str(getenv(4)), shell=True)
        """
    ) == []
