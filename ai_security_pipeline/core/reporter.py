"""Report generation in multiple formats."""

import json
from dataclasses import asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from .scanner import Finding, ScanResult, Severity
from .auditor import AuditResult


class OutputFormat(Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


class Reporter:
    """Generate reports from scan/audit results."""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir

    def report(
        self,
        results: Union[ScanResult, AuditResult, List[Union[ScanResult, AuditResult]]],
        fmt: OutputFormat = OutputFormat.JSON,
        filename: Optional[str] = None,
    ) -> str:
        if not isinstance(results, list):
            results = [results]

        if fmt == OutputFormat.JSON:
            content = self._to_json(results)
            ext = "json"
        elif fmt == OutputFormat.MARKDOWN:
            content = self._to_markdown(results)
            ext = "md"
        elif fmt == OutputFormat.SARIF:
            content = self._to_sarif(results)
            ext = "sarif"
        else:
            raise ValueError(f"Unsupported format: {fmt}")

        if filename is None:
            filename = f"report_{datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.{ext}"

        filepath = f"{self.output_dir}/{filename}"
        with open(filepath, "w") as f:
            f.write(content)
        return filepath

    def _to_json(self, results: List[Union[ScanResult, AuditResult]]) -> str:
        data = []
        for result in results:
            d = asdict(result)
            d["timestamp"] = d["timestamp"].isoformat() if isinstance(d.get("timestamp"), datetime) else str(d.get("timestamp"))
            data.append(d)
        return json.dumps(data, indent=2, default=str)

    def _to_markdown(self, results: List[Union[ScanResult, AuditResult]]) -> str:
        lines = ["# AI Security Pipeline Report\n", f"Generated: {datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}Z\n"]
        for result in results:
            name = getattr(result, "scanner_name", getattr(result, "auditor_name", "unknown"))
            lines.append(f"\n## {name} — {result.target}\n")
            lines.append(f"**Findings:** {len(result.findings)} | **Errors:** {len(result.errors)}\n")
            if result.findings:
                lines.append("| Severity | Rule | Title | Location |\n")
                lines.append("|----------|------|-------|----------|\n")
                for f in result.findings:
                    loc = f.location or "N/A"
                    lines.append(f"| {f.severity.value.upper()} | {f.rule_id} | {f.title} | {loc} |\n")
            else:
                lines.append("_No findings._\n")
        return "".join(lines)

    def _to_sarif(self, results: List[Union[ScanResult, AuditResult]]) -> str:
        runs = []
        for result in results:
            rules = []
            rule_ids = set()
            findings = []
            for finding in result.findings:
                if finding.rule_id not in rule_ids:
                    rules.append({
                        "id": finding.rule_id,
                        "name": finding.title,
                        "shortDescription": {"text": finding.description},
                    })
                    rule_ids.add(finding.rule_id)
                findings.append({
                    "ruleId": finding.rule_id,
                    "message": {"text": finding.description},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.location or "unknown"}}}],
                })
            runs.append({
                "tool": {"driver": {"name": getattr(result, "scanner_name", getattr(result, "auditor_name", "ai-security-pipeline")), "rules": rules}},
                "results": findings,
            })
        return json.dumps({"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": runs}, indent=2)
