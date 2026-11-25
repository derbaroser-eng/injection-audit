# injection-audit

Static taint analysis for shell and argument injection, built for teams that need to hand a customer or an auditor a **dated, signed, per-repository report** instead of a chat log.

It reads Python (AST) and Bash (token-level), traces attacker-controlled data from source to sink, and writes three artefacts: a JSON report, a Markdown report, and an HMAC-SHA256 signature over the canonical payload. Findings are quoted with file and line and mapped to a rule id and CWE class. Every report names the exact rule catalogue it applied, by count and SHA-256, so a report can be checked against the version that produced it three months later.

## Install

```bash
pip install injection-audit
```

Or from source:

```bash
git clone https://github.com/derbaroser-eng/injection-audit.git
cd injection-audit
pip install -e .
```

Python 3.10+. No runtime dependencies beyond the standard library; `cryptography` is used for key handling when available, with a stdlib HMAC fallback.

## Use

Create a signing key once, and keep it out of the repository you scan:

```bash
injection-audit init-key --out keys/audit.key
```

Scan a tree:

```bash
injection-audit scan ./src --key-file keys/audit.key --label my-service --out reports/
```

That writes:

```
reports/report-SIA-2026-11-22-b377805c.json
reports/report-SIA-2026-11-22-b377805c.md
reports/report-SIA-2026-11-22-b377805c.json.sig
```

Verify a report against its key, at any later date:

```bash
injection-audit verify reports/report-SIA-2026-11-22-b377805c.json --key-file keys/audit.key
# VALID signature for SIA-2026-11-22-b377805c
```

Exit codes: `0` analysed · `2` usage error · `3` signing key missing · `1` crash.

## What it finds

Sources: `sys.argv`, `os.environ`, `os.getenv`, `input()`, `request.*`, `argparse.parse_args`, file/stdin/socket reads.

Sinks: `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `subprocess*` including `shell=True`, `asyncio.create_subprocess_shell`, `eval`, `exec`; in Bash, `eval` and `bash -c`/`sh -c` with non-constant expansions.

Interprocedural parameter and return taint is resolved with a bounded call-graph fixpoint, and `shlex.quote` is treated as a sanitising builtin.

## Honest limits

Read these before you rely on a clean report. They are also printed in every report.

- Taint analysis is intra-procedural with a conservative branch union; alias tracking through containers and attributes is limited.
- Import and member aliases are resolved per scope from imports and simple assignments; dynamic dispatch (`getattr`/`setattr`, dict lookups) is not resolved.
- Interprocedural refinement is a bounded fixpoint (maximum 8 iterations).
- Lambda and comprehension bodies are not analysed.
- Bash analysis is a token-level heuristic, not a full shell parser. The run-as, sourced-script and word-splitting rules quote the line but cannot prove the value reaches the sink at run time.
- Absence of findings is not evidence of absence of weaknesses.

## Field note

I wrote up the design decision behind the signed artefact, with a real scan and the honest limits: [the report that survives being handed over](https://derbaroser-eng.github.io/injection-audit/field-note/), and the [longer version on dev.to](https://dev.to/aurum_revenue/the-report-that-survives-being-handed-over-3add).

## What a report is not

Findings plus dated evidence only. A report records the output of static analysis over the repository state identified by the content hashes inside it. It is not a compliance certification, not an attestation, and not a guarantee of security, correctness, or fitness for any purpose.

## Development

```bash
python -m pytest
```

149 tests cover the engine, both analysers, extra sinks, alias bindings, multi-language dispatch, the corpus, the signed-report format, and review regressions.

## Licence

The source is MIT. See LICENSE.

A commercial licence is available for teams that embed injection-audit in a proprietary or distributed product and need to drop the MIT attribution and source-disclosure obligations, plus a support thread. It is EUR 49 once: <https://buy.stripe.com/bJefZk7PY6g85mF7lS4ko0W>. Terms: LICENSE-COMMERCIAL.md. The MIT source and the full write-up stay free on <https://derbaroser-eng.github.io/injection-audit/>.
