"""injection-audit: dated, signed, per-repository shell/argument injection audits."""
from .model import Finding, FileResult
from .engine import analyze_text, analyze_file, analyze_repo, inventory_repo

from ._meta import ENGINE, NAME, VERSION
from .report import build_report, sign_report, verify_report, render_markdown

__all__ = ["Finding", "FileResult", "analyze_text", "analyze_file",
           "analyze_repo", "inventory_repo", "build_report", "sign_report",
           "verify_report", "render_markdown", "NAME", "VERSION", "ENGINE"]
__version__ = VERSION
