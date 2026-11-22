"""CLI: scan a repository, sign the artefact, verify a signature."""
import argparse
import json
import os
import secrets
import sys

from ._meta import NAME, VERSION
from .engine import analyze_repo, inventory_repo
from .report import build_report, render_markdown, sign_report, verify_report


class KeyMissing(Exception):
    pass


def load_key(key_file=None, env_name="INJECTION_AUDIT_KEY"):
    if key_file:
        try:
            with open(key_file, "rb") as handle:
                raw = handle.read().strip()
        except OSError as exc:
            raise KeyMissing(f"cannot read key file {key_file}: {exc.strerror}")
    else:
        value = os.environ.get(env_name)
        if not value:
            raise KeyMissing(f"no signing key: pass --key-file or set {env_name}")
        raw = value.strip().encode("utf-8")
    if len(raw) in (64, 128) and all(c in b"0123456789abcdefABCDEF" for c in raw):
        return bytes.fromhex(raw.decode("ascii"))
    return raw


def cmd_init_key(args):
    directory = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(directory, exist_ok=True)
    with open(args.out, "w", encoding="ascii") as handle:
        handle.write(secrets.token_hex(32) + "\n")
    try:
        os.chmod(args.out, 0o600)
    except OSError:
        pass
    print(f"wrote signing key {args.out} (keep it secret)")
    return 0


def cmd_scan(args):
    if not os.path.isdir(args.root):
        print(f"error: root is not a directory: {args.root}", file=sys.stderr)
        return 2
    key = load_key(args.key_file, args.key_env)
    results = analyze_repo(args.root, langs=args.lang or None)
    inventory = inventory_repo(args.root)
    label = args.label or os.path.basename(os.path.abspath(args.root))
    report = build_report(results, label, inventory)
    sign_report(report, key)
    os.makedirs(args.out, exist_ok=True)
    base = os.path.join(args.out, f"report-{report['report_id']}")
    json_path = base + ".json"
    md_path = base + ".md"
    sig_path = base + ".json.sig"
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    with open(md_path, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(report))
    with open(sig_path, "w", encoding="ascii") as handle:
        handle.write(report["signature"]["value"] + "\n")
    print(f"{report['report_id']}  findings={report['scope']['findings_total']} "
          f"files={report['scope']['files_analysed']}")
    print(f"json      : {json_path}")
    print(f"markdown  : {md_path}")
    print(f"signature : {sig_path}")
    return 0


def cmd_verify(args):
    try:
        with open(args.report, encoding="utf-8") as handle:
            report = json.load(handle)
    except OSError as exc:
        print(f"error: cannot read report: {exc.strerror}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: report is not valid JSON: {exc}", file=sys.stderr)
        return 2
    key = load_key(args.key_file, args.key_env)
    if verify_report(report, key):
        print(f"VALID signature for {report.get('report_id', 'unknown report')}")
        return 0
    print("INVALID: signature does not match this report or key", file=sys.stderr)
    return 1


def build_parser():
    parser = argparse.ArgumentParser(
        prog="injection_audit",
        description="Dated, signed, per-repository shell-injection audit reports.")
    parser.add_argument("--version", action="version", version=f"{NAME} {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyse a repository and write the signed artefact")
    scan.add_argument("root")
    scan.add_argument("--out", default="audit-out")
    scan.add_argument("--key-file")
    scan.add_argument("--key-env", default="INJECTION_AUDIT_KEY")
    scan.add_argument("--label", help="repository label recorded in the report")
    scan.add_argument("--lang", action="append", choices=["python", "bash"])

    init = sub.add_parser("init-key", help="generate a signing key")
    init.add_argument("--out", default="keys/audit.key")

    verify = sub.add_parser("verify", help="verify a report signature")
    verify.add_argument("report")
    verify.add_argument("--key-file")
    verify.add_argument("--key-env", default="INJECTION_AUDIT_KEY")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init-key":
            return cmd_init_key(args)
        if args.command == "scan":
            return cmd_scan(args)
        return cmd_verify(args)
    except KeyMissing as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # pragma: no cover - defensive top level
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
