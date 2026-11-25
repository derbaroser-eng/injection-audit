"""Acceptance tests: README.md must match the real suite counted from source.

The public README is the first thing a buyer reads. Its stated test count is
locked to the suite counted from source, excluding this meta-test file, so the
claim cannot drift away from reality as tests are added or removed.
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
TESTS = ROOT / "tests"
META_TESTS = {"test_docs.py"}


def _count_tests():
    total = 0
    for path in sorted(TESTS.glob("test_*.py")):
        if path.name in META_TESTS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        total += sum(
            1 for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        )
    return total


def test_readme_stated_test_count_is_real():
    stated = re.search(r"\b(\d+) tests cover\b", README.read_text(encoding="utf-8"))
    assert stated, "README does not state a test count"
    assert int(stated.group(1)) == _count_tests(), \
        "README test count does not match the suite counted from source"
