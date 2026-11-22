# SPEC — injection-audit (artefact-first shell/argument injection audit engine)

## What it does
Static taint analysis (Python AST first, Bash second) that emits a DATED, SIGNED,
PER-REPOSITORY audit report. Findings only — never a compliance claim.

## Artefact properties (the sellable part)
- report_id + delivery date (UTC), deterministic per tree+date
- numbered findings F-0001…, each mapped to a concrete rule and CWE class
- per-file SHA-256 content hash (reproducible, tamper-evident)
- exact file:line evidence with the offending source quoted
- coverage stated honestly: analysed / skipped / unparsable, with reasons
- HMAC-SHA256 signature over the canonical report payload + key fingerprint
- fixed disclaimer: findings + dated evidence only, no certification/guarantee

## Engine
- Python: ast parse; taint sources (sys.argv, os.environ, os.getenv, input(),
  request.*, argparse parse_args, file/stdin/socket reads); sinks (os.system,
  os.popen, os.exec*/spawn*, subprocess* incl. shell=True, asyncio
  create_subprocess_shell, eval/exec); sanitizing builtins (shlex.quote).
  Interprocedural param/return taint via call-graph fixpoint.
- Bash: eval / bash -c / sh -c with non-constant expansions.
- Non-Goal v1: no JS/TS AST, no dataflow across modules, no CI gating.

## Exit codes
0 analysed (findings allowed) · 2 usage · 3 signing key missing · 1 crash.
