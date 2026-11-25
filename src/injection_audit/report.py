"""The sellable artefact: a dated, signed, per-repository audit report."""
import datetime
import hashlib
import hmac
import json
import platform as _platform

from ._meta import ENGINE, NAME, SCHEMA, VERSION
from .rules import RULE_META

DISCLAIMER = (
    "Findings plus dated evidence only. This report records the output of static "
    "analysis over the repository state identified by the content hashes below. "
    "It is not a compliance certification, not an attestation, and not a guarantee "
    "of security, correctness, or fitness for any purpose."
)

LIMITATIONS = [
    "Taint analysis is intra-procedural with a conservative branch union; alias "
    "tracking through containers and attributes is limited.",
    "Import and member aliases are resolved per scope from imports and simple "
    "assignments; dynamic dispatch (getattr/setattr, dict lookups), star imports "
    "and class-body rebindings are not resolved.",
    "Lambda and comprehension bodies are not analysed, and an assignment "
    "expression (walrus) does not update the taint environment mid-expression.",
    "Interprocedural refinement is a bounded fixpoint (maximum 8 iterations).",
    "Bash analysis is a token-level heuristic, not a full shell parser; the "
    "run-as, sourced-script and word-splitting rules quote the line but cannot "
    "prove the value reaches the sink at run time.",
    "Absence of findings is not evidence of absence of weaknesses.",
]


def ruleset_digest():
    """Hash of the rule catalogue, so a report names the exact rules it applied."""
    blob = json.dumps({key: list(value) for key, value in sorted(RULE_META.items())},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def canonical_bytes(report):
    """Byte-exact serialisation covered by the signature.

    Signature metadata (algorithm, key id, key fingerprint) is included in the
    covered bytes, so it is authenticated too; only the MAC itself and the
    payload digest are set aside while the digest is computed.
    """
    payload = {key: value for key, value in report.items() if key != "signature"}
    signature = report.get("signature")
    if isinstance(signature, dict):
        payload["signature"] = {key: value for key, value in signature.items()
                                if key not in ("value", "payload_sha256")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def key_fingerprint(key: bytes) -> str:
    return "sha256:" + hashlib.sha256(key).hexdigest()[:32]


def sign_report(report, key: bytes, key_id: str = "audit-signing-key"):
    report["signature"] = {
        "alg": "HMAC-SHA256",
        "key_id": key_id,
        "key_fingerprint": key_fingerprint(key),
        "payload_sha256": "",
    }
    payload = canonical_bytes(report)
    report["signature"]["payload_sha256"] = hashlib.sha256(payload).hexdigest()
    report["signature"]["value"] = hmac.new(
        key, canonical_bytes(report), hashlib.sha256).hexdigest()
    return report


def verify_report(report, key: bytes) -> bool:
    """Verify the HMAC. Malformed input is a rejection, never an exception."""
    if not isinstance(key, (bytes, bytearray)):
        return False
    signature = report.get("signature")
    if not isinstance(signature, dict):
        return False
    value = signature.get("value")
    digest = signature.get("payload_sha256")
    if not isinstance(value, str) or not isinstance(digest, str):
        return False
    if signature.get("alg") != "HMAC-SHA256":
        return False
    if signature.get("key_fingerprint") != key_fingerprint(bytes(key)):
        return False
    payload = canonical_bytes(report)
    if digest != hashlib.sha256(payload).hexdigest():
        return False
    expected = hmac.new(bytes(key), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, value)


def build_report(file_results, root_label, inventory=None, generated_at=None,
                 platform=None):
    now = generated_at or datetime.datetime.now(datetime.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    date = now.strftime("%Y-%m-%d")

    ordered = []
    for result in sorted(file_results, key=lambda r: r.path):
        for finding in sorted(result.findings, key=lambda f: (f.line, f.col, f.rule_id)):
            ordered.append((result, finding))

    hash_lines = [f"{r.path}:{r.content_sha256}" for r in sorted(file_results, key=lambda r: r.path)
                  if r.content_sha256]
    content_digest = hashlib.sha256("\n".join(hash_lines).encode("utf-8")).hexdigest()

    findings = []
    by_language = {}
    for number, (result, finding) in enumerate(ordered, 1):
        by_language[result.language] = by_language.get(result.language, 0) + 1
        findings.append({
            "id": f"F-{number:04d}",
            "rule_id": finding.rule_id,
            "cwe": finding.cwe,
            "severity": finding.severity,
            "file": finding.file or result.path,
            "line": finding.line,
            "col": finding.col,
            "content_sha256": finding.content_sha256 or result.content_sha256,
            "evidence": finding.evidence,
            "sink": finding.sink,
            "source": finding.source,
            "message": finding.message,
        })

    errors = [{"path": r.path, "error": r.error}
              for r in sorted(file_results, key=lambda r: r.path) if r.error]
    coverage_in = inventory or {
        "files_total": len(file_results),
        "by_extension": {},
        "analysable_paths": [r.path for r in file_results],
        "skipped": [],
    }

    return {
        "schema": SCHEMA,
        "report_id": f"SIA-{date}-{content_digest[:8]}-{ruleset_digest()[:8]}",
        "delivery_date": date,
        "generated_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "tool": {"name": NAME, "version": VERSION, "engine": ENGINE,
                 "ruleset": {"rule_count": len(RULE_META),
                             "sha256": ruleset_digest()}},
        "scanner": {"platform": platform or _platform.system(),
                    "method": "static analysis; no analysed code was executed"},
        "scope": {
            "repository": root_label,
            "files_analysed": len(file_results),
            "files_with_findings": len({r.path for r, _ in ordered}),
            "findings_total": len(findings),
            "content_digest": content_digest,
        },
        "coverage": {
            "stated_honestly": True,
            "files_total": coverage_in.get("files_total"),
            "by_extension": coverage_in.get("by_extension", {}),
            "analysable": coverage_in.get("analysable_paths", []),
            "lossy_decode": coverage_in.get("lossy_decode", []),
            "skipped": coverage_in.get("skipped", []),
            "parse_errors": errors,
            "findings_by_language": dict(sorted(by_language.items())),
            "limitations": list(LIMITATIONS),
        },
        "findings": findings,
        "disclaimer": DISCLAIMER,
    }


def render_markdown(report) -> str:
    lines = [
        f"# Injection Audit Report {report['report_id']}",
        "",
        f"**Delivery date:** {report['delivery_date']}  ",
        f"**Repository:** {report['scope']['repository']}  ",
        f"**Tool:** {report['tool']['name']} v{report['tool']['version']} "
        f"({report['tool']['engine']})  ",
        f"**Ruleset:** {report['tool']['ruleset']['rule_count']} rules, "
        f"SHA-256 `{report['tool']['ruleset']['sha256']}`  ",
        f"**Scope:** {report['scope']['files_analysed']} files analysed, "
        f"{report['scope']['findings_total']} numbered findings  ",
        f"**Content digest:** `{report['scope']['content_digest']}`",
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("No findings were recorded for the analysed files.")
    for finding in report["findings"]:
        lines += [
            f"### {finding['id']} — {finding['rule_id']} ({finding['cwe']}, "
            f"{finding['severity']})",
            f"- **File:** `{finding['file']}:{finding['line']}`",
            f"- **Content SHA-256:** `{finding['content_sha256']}`",
            f"- **Evidence:** `{finding['evidence']}`",
            f"- **Sink:** `{finding['sink']}`",
            f"- **Data source:** `{finding['source']}`",
            f"- **Detail:** {finding['message']}",
            "",
        ]
    coverage = report["coverage"]
    lines += [
        "## Coverage (stated honestly)",
        "",
        f"- Files seen: {coverage.get('files_total')}",
        f"- Extensions: {json.dumps(coverage.get('by_extension', {}), sort_keys=True)}",
        f"- Analysable files: {len(coverage.get('analysable', []))}",
        f"- Decoded lossily (non-UTF-8 source): {len(coverage.get('lossy_decode', []))}",
        f"- Parse errors: {len(coverage.get('parse_errors', []))}",
    ]
    for item in coverage.get("skipped", []):
        lines.append(f"- Skipped `{item['path']}`: {item['reason']}")
    for item in coverage.get("parse_errors", []):
        lines.append(f"- Could not analyse `{item['path']}`: {item['error']}")
    lines.append("- Limitations:")
    for item in coverage.get("limitations", []):
        lines.append(f"  - {item}")
    signature = report.get("signature", {})
    lines += [
        "",
        "## Signature",
        "",
        f"- Algorithm: {signature.get('alg', 'unsigned')}",
        f"- Key fingerprint: `{signature.get('key_fingerprint', 'n/a')}`",
        f"- Payload SHA-256: `{signature.get('payload_sha256', 'n/a')}`",
        f"- Value: `{signature.get('value', 'n/a')}`",
        "",
        "## Verify this report",
        "",
        "```bash",
        "python -m injection_audit verify report.json --key-file keys/audit.key",
        "```",
        "",
        "## Disclaimer",
        "",
        report["disclaimer"],
        "",
    ]
    return "\n".join(lines)
