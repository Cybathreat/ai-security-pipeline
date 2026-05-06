"""Base auditor interface for audit / test modules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .scanner import Finding, Severity


@dataclass
class AuditResult:
    auditor_name: str
    target: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    passed: bool = True

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def filter_by_min_severity(self, min_severity: Severity) -> "AuditResult":
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if min_severity not in order:
            return self
        idx = order.index(min_severity)
        allowed = set(order[idx:])
        self.findings = [f for f in self.findings if f.severity in allowed]
        return self


class BaseAuditor(ABC):
    """Abstract base for all security auditors."""

    name: str = "base"
    description: str = ""
    version: str = "0.1.0"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._findings: List[Finding] = []
        self._errors: List[str] = []

    @abstractmethod
    def audit(self, target: Any) -> AuditResult:
        """Execute the audit and return results."""
        ...

    def add_finding(self, finding: Finding) -> None:
        self._findings.append(finding)

    def add_error(self, error: str) -> None:
        self._errors.append(error)

    def _build_result(self, target: str) -> AuditResult:
        return AuditResult(
            auditor_name=self.name,
            target=str(target),
            findings=list(self._findings),
            errors=list(self._errors),
            passed=len([f for f in self._findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]) == 0,
        )
