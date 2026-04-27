"""Pipeline orchestration for chaining scans and audits."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type, Union

from .scanner import BaseScanner, ScanResult
from .auditor import BaseAuditor, AuditResult
from .reporter import Reporter, OutputFormat


@dataclass
class PipelineConfig:
    name: str = "default"
    modules: List[str] = field(default_factory=list)
    output_formats: List[str] = field(default_factory=lambda: ["json", "markdown"])
    output_dir: str = "./reports"
    min_severity: str = "low"
    settings: Dict[str, Any] = field(default_factory=dict)


class Pipeline:
    """Orchestrates multiple security modules."""

    def __init__(self, config: PipelineConfig):
        self.config = config
        self._scanners: Dict[str, Type[BaseScanner]] = {}
        self._auditors: Dict[str, Type[BaseAuditor]] = {}
        self._results: List[Union[ScanResult, AuditResult]] = []
        self._reporter = Reporter(output_dir=config.output_dir)

    def register_scanner(self, name: str, scanner_cls: Type[BaseScanner]) -> None:
        self._scanners[name] = scanner_cls

    def register_auditor(self, name: str, auditor_cls: Type[BaseAuditor]) -> None:
        self._auditors[name] = auditor_cls

    def run(self, targets: Dict[str, Any]) -> List[Union[ScanResult, AuditResult]]:
        self._results = []
        for module_name in self.config.modules:
            target = targets.get(module_name)
            if module_name in self._scanners and target is not None:
                scanner = self._scanners[module_name](self.config.settings.get(module_name))
                result = scanner.scan(target)
                self._results.append(result)
            elif module_name in self._auditors and target is not None:
                auditor = self._auditors[module_name](self.config.settings.get(module_name))
                result = auditor.audit(target)
                self._results.append(result)
        return self._results

    def report(self, fmt: Optional[OutputFormat] = None) -> List[str]:
        if not self._results:
            return []
        if fmt:
            return [self._reporter.report(self._results, fmt=fmt)]
        paths = []
        for f in self.config.output_formats:
            try:
                paths.append(self._reporter.report(self._results, fmt=OutputFormat(f)))
            except ValueError:
                continue
        return paths
