"""Shared data model for every analyser."""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    rule_id: str
    cwe: str
    severity: str
    line: int
    col: int
    evidence: str
    sink: str
    source: str
    message: str
    file: str = ""
    content_sha256: str = ""


@dataclass
class FileResult:
    path: str
    language: str
    content_sha256: str = ""
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None
    skipped_reason: Optional[str] = None
