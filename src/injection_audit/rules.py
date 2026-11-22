"""Concrete rule catalogue. Every finding maps to one of these rules."""

RULE_META = {
    "SIA-78-01": ("CWE-78", "high",
                  "os.system() executes a shell string built from attacker-influenced text."),
    "SIA-78-02": ("CWE-78", "high",
                  "os.popen() executes a shell string built from attacker-influenced text."),
    "SIA-78-03": ("CWE-78", "high",
                  "subprocess launched with shell=True and attacker-influenced command text."),
    "SIA-78-04": ("CWE-78", "high",
                  "asyncio.create_subprocess_shell() builds a shell command from attacker-influenced text."),
    "SIA-78-05": ("CWE-78", "high",
                  "os.exec*/os.spawn* received attacker-influenced program or argument text."),
    "SIA-78-10": ("CWE-78", "high",
                  "Shell script passes non-constant text to eval(); the string is re-parsed as shell syntax."),
    "SIA-78-11": ("CWE-78", "high",
                  "Shell interpreter invoked with -c and a non-constant command string."),
    "SIA-78-12": ("CWE-78", "medium",
                  "Remote command passed to ssh contains expansions that the remote shell re-parses."),
    "SIA-78-13": ("CWE-78", "high",
                  "Run-as helper (sudo/doas/su) invoked with non-constant command text; the command "
                  "string is executed after a privilege boundary and may be re-parsed by a shell."),
    "SIA-78-15": ("CWE-78", "medium",
                  "Shell sources or interprets a non-constant script path; the loaded content is "
                  "executed with the current privileges."),
    "SIA-88-01": ("CWE-88", "low",
                  "Attacker-influenced argument passed to a subprocess. With no shell this cannot spawn a "
                  "command, but a value beginning with '-' can be read as an option by the target program; "
                  "validate it or terminate option parsing with '--'."),
    "SIA-88-02": ("CWE-88", "medium",
                  "Attacker-influenced program name or bare-string command passed to a process launcher."),
    "SIA-88-03": ("CWE-88", "info",
                  "MSYS2/Git-Bash argv expansion hazard: on Windows the MSYS runtime rewrites '*', '?', '~' "
                  "and brace patterns in argv before the target program starts. Attacker-influenced text "
                  "reached a shell-invoking subprocess; pass an argv list instead."),
    "SIA-88-04": ("CWE-88", "medium",
                  "Attacker-influenced text reaches xargs word-splitting/globbing or a find -exec argument "
                  "list; the value may be split into several arguments, expanded as a glob, or read as an "
                  "option by the helper."),
    "SIA-95-01": ("CWE-95", "high",
                  "eval()/exec() executed attacker-influenced source text."),
}


def message_for(rule_id: str, source: str) -> str:
    return f"{RULE_META[rule_id][2]} Data source: {source}."
