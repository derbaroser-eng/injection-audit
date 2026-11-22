"""Tests for the Bash/sh analyser and repo-level shell coverage."""
from injection_audit.bash_analyzer import BashAnalyzer
from injection_audit.engine import analyze_repo


def rules(code):
    findings, _ = BashAnalyzer(code, "snippet.sh").analyze()
    return sorted({f.rule_id for f in findings})


def test_eval_of_read_variable():
    assert "SIA-78-10" in rules('#!/bin/sh\nread name\neval "$name"\n')


def test_eval_of_command_substitution():
    assert "SIA-78-10" in rules('#!/bin/sh\neval "$(cat /tmp/payload)"\n')


def test_eval_constant_is_clean():
    assert rules('#!/bin/sh\neval "echo hello"\n') == []


def test_interpreter_dash_c_with_positional():
    assert "SIA-78-11" in rules('#!/bin/sh\nsh -c "$1"\n')


def test_interpreter_dash_c_constant_is_clean():
    assert rules("#!/bin/sh\nbash -c 'echo hi'\n") == []


def test_ssh_command_expansion():
    assert "SIA-78-12" in rules(
        '#!/bin/sh\nread dir\nssh deploy@host "ls $dir"\n')


def test_ssh_constant_is_clean():
    assert rules('#!/bin/sh\nssh deploy@host "ls /var/log"\n') == []


def test_assignment_from_expansion_is_tracked():
    assert "SIA-78-10" in rules(
        '#!/bin/sh\npayload=$(cat /tmp/x)\neval "$payload"\n')


def test_repo_scans_shell_scripts_only_for_known_extensions(tmp_path):
    (tmp_path / "run.sh").write_text('#!/bin/sh\nsh -c "$1"\n', encoding="utf-8")
    (tmp_path / "notes.txt").write_text('eval "$x"\n', encoding="utf-8")
    results = analyze_repo(tmp_path)
    assert len(results) == 1
    assert results[0].language == "bash"
    assert any(f.rule_id == "SIA-78-11" for f in results[0].findings)
