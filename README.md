# injection-audit

A static analyser for shell and argument injection that emits a **dated, signed, tamper-evident audit report** instead of a loose JSON blob.

The report is the artifact: a deterministic ID per tree + date, numbered findings mapped to CWE classes, per-file SHA-256 of the exact source read, file:line evidence with the offending line quoted, honest coverage (analysed / skipped / unparsable, with reasons), and an HMAC-SHA256 signature over the canonical payload with the key fingerprint recorded.

Findings only. Never a compliance certificate or a guarantee. A fixed disclaimer to that effect lives inside every report.

## What it covers

- Python AST: taint sources (`sys.argv`, `os.environ`, `os.getenv`, `input()`, `request.*`, file/stdin/socket reads) and sinks (`os.system`, `os.popen`, `subprocess*`, `eval`/`exec`, `create_subprocess_shell`), with a bounded interprocedural fixpoint.
- Bash: `eval`, `bash -c`, `sh -c` with non-constant expansions.
- Known limits, printed in every report: intra-procedural taint with a conservative branch union, limited alias tracking through containers and attributes, no JS/TS AST, no cross-module dataflow, no CI gating.

## Usage

```
injection-audit init-key --out ./key.txt
injection-audit scan ./app --key-file ./key.txt --label my-repo
injection-audit verify report-<id>.json
```

`scan` writes three files: a JSON report, a Markdown report, and a detached `.sig`. `verify` checks the HMAC over the canonical payload and re-derives the payload hash. No network calls, no accounts, no phone-home. Python 3, standard library only.

## Exit codes

`0` analysed (findings allowed) · `2` usage · `3` signing key missing · `1` crash.

## Example finding

On a deliberately broken six-file demo app the scanner produced 8 findings (5 Python, 3 Bash), including:

```
F-0002  CWE-88  app.py:7
  subprocess.run(f"ping -c 1 {host}", shell=True)
```

The report records the SHA-256 of `app.py`, the exact source line, and the rule that fired, so the finding can be reproduced and checked later.
