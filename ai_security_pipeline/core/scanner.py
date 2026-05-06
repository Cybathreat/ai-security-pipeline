"""Base scanner interface and result types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: str
    location: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "location": self.location,
            "remediation": self.remediation,
            "references": self.references,
            "metadata": self.metadata,
        }


@dataclass
class ScanResult:
    scanner_name: str
    target: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def filter_by_min_severity(self, min_severity: Severity) -> "ScanResult":
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if min_severity not in order:
            return self
        idx = order.index(min_severity)
        allowed = set(order[idx:])
        self.findings = [f for f in self.findings if f.severity in allowed]
        return self


class BaseScanner(ABC):
    """Abstract base for all security scanners."""

    name: str = "base"
    description: str = ""
    version: str = "0.1.0"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._findings: List[Finding] = []
        self._errors: List[str] = []

    @abstractmethod
    def scan(self, target: Any) -> ScanResult:
        """Execute the scan and return results."""
        ...

    def add_finding(self, finding: Finding) -> None:
        self._findings.append(finding)

    def add_error(self, error: str) -> None:
        self._errors.append(error)

    def _build_result(self, target: str) -> ScanResult:
        return ScanResult(
            scanner_name=self.name,
            target=str(target),
            findings=list(self._findings),
            errors=list(self._errors),
        )
