"""RED tests: shell run-as helpers, sourced scripts and word-splitting helpers."""
import textwrap

from injection_audit.bash_analyzer import BashAnalyzer


def res(code):
    return BashAnalyzer(textwrap.dedent(code), "snippet.sh").analyze()[0]


def rules(code):
    return sorted({f.rule_id for f in res(code)})


def one(code, rule):
    fs = [f for f in res(code) if f.rule_id == rule]
    assert fs, f"expected {rule}, got {rules(code)}"
    return fs[0]


# ---------------- run-as helpers (sudo / doas / su) ----------------

def test_sudo_with_expansion():
    f = one(
        """
        #!/bin/sh
        read dest
        sudo rm -rf $dest
        """,
        "SIA-78-13",
    )
    assert "$dest" in f.source


def test_doas_with_expansion():
    assert "SIA-78-13" in rules(
        '#!/bin/sh\nread src\ndoas cp $src /etc\n'
    )


def test_sudo_sh_dash_c_is_both_shell_and_run_as():
    found = rules(
        """
        #!/bin/sh
        read payload
        sudo sh -c "$payload"
        """
    )
    assert "SIA-78-11" in found
    assert "SIA-78-13" in found


def test_su_dash_c_is_a_run_as_finding():
    assert "SIA-78-13" in rules(
        '#!/bin/sh\nread payload\nsu deploy -c "$payload"\n'
    )


def test_bare_su_login_is_clean():
    assert rules("#!/bin/sh\nsu deploy\n") == []


def test_sudo_constant_is_clean():
    assert rules("#!/bin/sh\nsudo rm -rf /tmp/cache\n") == []


def test_sudo_with_quoted_constant_is_clean():
    assert rules("#!/bin/sh\nsudo systemctl restart 'nginx'\n") == []


# ---------------- sourced / interpreted script paths ----------------

def test_dot_sources_expansion():
    f = one(
        """
        #!/bin/sh
        read dir
        . "$dir/lib.sh"
        """,
        "SIA-78-15",
    )
    assert "$dir" in f.source


def test_source_keyword_with_variable():
    assert "SIA-78-15" in rules(
        '#!/bin/sh\nread base\nsource $base/common.sh\n'
    )


def test_interpreter_reading_nonconstant_script():
    assert "SIA-78-15" in rules(
        """
        #!/bin/sh
        read script
        bash "$script"
        """
    )


def test_source_constant_is_clean():
    assert rules("#!/bin/sh\nsource ./lib.sh\n") == []


def test_dot_source_constant_is_clean():
    assert rules("#!/bin/sh\n. /etc/profile\n") == []


# ---------------- word-splitting helpers ----------------

def test_xargs_receives_tainted_text():
    f = one(
        """
        #!/bin/sh
        read pat
        cat list.txt | xargs grep -l "$pat"
        """,
        "SIA-88-04",
    )
    assert "grep" in f.sink or f.line == 4


def test_find_exec_receives_tainted_text():
    assert "SIA-88-04" in rules(
        r"""
        #!/bin/sh
        read target
        find . -maxdepth 2 -exec rm -f "$target" {} \;
        """
    )


def test_find_taint_before_exec_is_not_flagged():
    """Data reaching -name is not executed; the engine must not claim it is."""
    assert rules(
        """
        #!/bin/sh
        read pat
        find . -name "$pat" -print
        """
    ) == []


def test_find_exec_constant_is_clean():
    assert rules(
        r'#!/bin/sh' + "\n" + r'find . -maxdepth 1 -exec rm -f {} \;' + "\n"
    ) == []


def test_new_rules_are_in_the_catalogue():
    from injection_audit.rules import RULE_META
    for rule in ("SIA-78-13", "SIA-78-15", "SIA-88-04"):
        assert rule in RULE_META, f"{rule} missing from RULE_META"
        cwe, severity, _ = RULE_META[rule]
        assert cwe.startswith("CWE-"), rule
        assert severity in ("info", "low", "medium", "high"), rule
