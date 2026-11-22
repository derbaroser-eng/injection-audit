"""Heuristic Bash/sh analyser for eval, interpreter -c and remote-command sinks."""
import re

from .model import Finding
from .rules import RULE_META, message_for

_EXPANSION = re.compile(r"\$\(|\$\{|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?]|`[^`]*`")
_PATH = r"(?:[^\s;&|()\"']*/)?"
_EVAL = re.compile(r"(?:^|[\s;])eval\b(.*)$")
_INTERP_C = re.compile(r"(?:^|[\s;])" + _PATH +
                       r"(bash|sh|zsh|dash|ksh)\b\s+((?:-\w+\s+)*)-c\s+(.+)$")
_SSH = re.compile(r"(?:^|[\s;])" + _PATH +
                  r"ssh\b\s+(?:-\S+\s+)*(\S+)\s+(.+)$")
_READ = re.compile(r"\bread\b\s+([A-Za-z_][A-Za-z0-9_]*)")
_ASSIGN_TAINT = re.compile(
    r"^\s*(?:local\s+|export\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
# run-as helpers: sudo/doas always, su only when it carries an explicit -c
_RUNAS = re.compile(r"(?:^|[\s;=|])(sudo|doas)\b\s*(.*)$", re.IGNORECASE)
_SU = re.compile(r"(?:^|[\s;=|])su\b\s*(.*)$")
_SU_COMMAND = re.compile(r"(?:^|\s)(?:-c|--command)(?=\s|$)")
# `source FILE`, `. FILE` and an interpreter reading a script path directly
_SOURCE_CMD = re.compile(
    r"""(?:^|[\s;=])(?:source|\.)\s+("[^"]*"|'[^']*'|\S+)""")
_INTERP_ANY = re.compile(r"(?:^|[\s;])" + _PATH +
                         r"(bash|sh|zsh|dash|ksh)\b\s*((?:-[A-Za-z]+\s+)*)(.+)$")
# helpers that word-split and glob their arguments
_XARGS = re.compile(r"(?:^|[\s;=|])(xargs)\b\s*(.*)$")
_FIND_EXEC = re.compile(r"(?:^|[\s;=|])(find)\b.*?-(exec|execdir)\b\s*(.*)$")


class BashAnalyzer:
    """Deliberately conservative. Every finding quotes the exact source line."""

    def __init__(self, source, filename, platform=None):
        self.src = source
        self.filename = filename
        self.lines = source.splitlines()
        self.findings = []
        self._seen = set()

    def analyze(self):
        tainted_vars = set()
        logical = []  # (start_line_no, text)
        buffer = ""
        start = 1
        for number, raw in enumerate(self.lines, 1):
            if not buffer:
                start = number
            if raw.rstrip().endswith("\\"):
                buffer += raw.rstrip()[:-1] + " "
                continue
            buffer += raw
            logical.append((start, buffer))
            buffer = ""
        if buffer:
            logical.append((start, buffer))

        for number, text in logical:
            stripped = text.strip()
            if stripped and not stripped.startswith("#"):
                self._check_line(number, text, tainted_vars)
            self._learn_assignments(text, tainted_vars)

        self.findings.sort(key=lambda f: (f.line, f.col, f.rule_id))
        return self.findings, None

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _expansions(text):
        return [m.group(0) for m in _EXPANSION.finditer(text)]

    def _add(self, rule_id, line_no, col, evidence, source):
        meta = RULE_META[rule_id]
        finding = Finding(rule_id=rule_id, cwe=meta[0], severity=meta[1],
                          line=line_no, col=col, evidence=" ".join(evidence.split()),
                          sink=rule_id, source=source,
                          message=message_for(rule_id, source))
        key = (finding.rule_id, finding.line, finding.col)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(finding)

    @staticmethod
    def _constant(text):
        return not _EXPANSION.search(text)

    def _tainted_expansions(self, text, tainted_vars):
        out = []
        for match in _EXPANSION.finditer(text):
            token = match.group(0)
            if token.startswith("$(") or token.startswith("`"):
                out.append(token)
                continue
            name = token.lstrip("$").strip("{}")
            if name.isdigit() or name in ("@", "*", "#", "?"):
                out.append(token)
            elif name in tainted_vars:
                out.append(token)
        return out

    def _learn_assignments(self, text, tainted_vars):
        match = _ASSIGN_TAINT.match(text)
        if match:
            name, value = match.group(1), match.group(2).strip()
            if self._expansions(value):
                tainted_vars.add(name)
        for read_match in _READ.finditer(text):
            tainted_vars.add(read_match.group(1))

    def _check_line(self, number, text, tainted_vars):
        eval_match = _EVAL.search(text)
        if eval_match:
            arg = eval_match.group(1).strip()
            bad = self._tainted_expansions(arg, tainted_vars)
            if bad or not self._constant(arg):
                self._add("SIA-78-10", number, eval_match.start(1),
                          text.strip(), ", ".join(bad) or "non-constant eval argument")
        interp = _INTERP_C.search(text)
        if interp:
            arg = interp.group(3).strip()
            bad = self._tainted_expansions(arg, tainted_vars)
            if bad or not self._constant(arg):
                self._add("SIA-78-11", number, interp.start(3),
                          text.strip(), ", ".join(bad) or "non-constant -c argument")
        ssh = _SSH.search(text)
        if ssh:
            arg = ssh.group(2).strip()
            bad = self._tainted_expansions(arg, tainted_vars)
            if bad:
                self._add("SIA-78-12", number, ssh.start(2),
                          text.strip(), ", ".join(bad))
        self._check_run_as(number, text, tainted_vars)
        self._check_sourced_script(number, text, tainted_vars)
        self._check_word_split_helpers(number, text, tainted_vars)

    def _check_run_as(self, number, text, tainted_vars):
        """sudo/doas/su executing non-constant command text."""
        match = _RUNAS.search(text)
        if match:
            remainder = match.group(2)
            bad = self._tainted_expansions(remainder, tainted_vars)
            if bad:
                self._add("SIA-78-13", number, match.start(2),
                          text.strip(), ", ".join(bad))
                return
        match = _SU.search(text)
        if not match:
            return
        remainder = match.group(1)
        if not _SU_COMMAND.search(remainder):
            # a bare `su user` opens a login shell; nothing here re-parses text
            return
        bad = self._tainted_expansions(remainder, tainted_vars)
        if bad:
            self._add("SIA-78-13", number, match.start(1),
                      text.strip(), ", ".join(bad))

    def _check_sourced_script(self, number, text, tainted_vars):
        """`source FILE`, `. FILE`, and an interpreter reading a script path."""
        match = _SOURCE_CMD.search(text)
        if match:
            arg = match.group(1)
            bad = self._tainted_expansions(arg, tainted_vars)
            if bad or not self._constant(arg):
                self._add("SIA-78-15", number, match.start(1),
                          text.strip(),
                          ", ".join(bad) or "non-constant script path")
            return
        interp = _INTERP_ANY.search(text)
        if not interp:
            return
        flags, arg = interp.group(2), interp.group(3).strip()
        if any("c" in flag[1:] for flag in flags.split() if flag.startswith("-")):
            return  # the -c form is already reported as SIA-78-11
        bad = self._tainted_expansions(arg, tainted_vars)
        if bad or not self._constant(arg):
            self._add("SIA-78-15", number, interp.start(3),
                      text.strip(),
                      ", ".join(bad) or "non-constant script path")

    def _check_word_split_helpers(self, number, text, tainted_vars):
        """xargs and find -exec receive attacker-influenced words."""
        match = _XARGS.search(text)
        if match:
            bad = self._tainted_expansions(match.group(2), tainted_vars)
            if bad:
                self._add("SIA-88-04", number, match.start(2),
                          text.strip(), ", ".join(bad))
        match = _FIND_EXEC.search(text)
        if match:
            bad = self._tainted_expansions(match.group(3), tainted_vars)
            if bad:
                self._add("SIA-88-04", number, match.start(3),
                          text.strip(), ", ".join(bad))
