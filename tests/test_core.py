"""Tests for core framework."""

import json
import os
from datetime import datetime

import pytest

from ai_security_pipeline.core.scanner import BaseScanner, Finding, ScanResult, Severity
from ai_security_pipeline.core.auditor import BaseAuditor, AuditResult
from ai_security_pipeline.core.reporter import Reporter, OutputFormat
from ai_security_pipeline.core.pipeline import Pipeline, PipelineConfig


class DummyScanner(BaseScanner):
    name = "dummy_scanner"

    def scan(self, target):
        self.add_finding(Finding(
            rule_id="TEST-001",
            title="Test finding",
            description="A test finding.",
            severity=Severity.HIGH,
            category="test",
        ))
        return self._build_result(target)


class DummyAuditor(BaseAuditor):
    name = "dummy_auditor"

    def audit(self, target):
        self.add_finding(Finding(
            rule_id="TEST-002",
            title="Test audit finding",
            description="A test audit finding.",
            severity=Severity.MEDIUM,
            category="test",
        ))
        return self._build_result(target)


class TestSeverity:
    def test_severity_order(self):
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL


class TestFinding:
    def test_finding_creation(self):
        finding = Finding(
            rule_id="RULE-001",
            title="Title",
            description="Desc",
            severity=Severity.HIGH,
            category="cat",
        )
        assert finding.rule_id == "RULE-001"
        assert finding.severity == Severity.HIGH


class TestScanResult:
    def test_severity_counts(self):
        result = ScanResult(
            scanner_name="test",
            target="t",
            findings=[
                Finding("R1", "T1", "D1", Severity.HIGH, "c"),
                Finding("R2", "T2", "D2", Severity.LOW, "c"),
            ],
        )
        counts = result.severity_counts
        assert counts["high"] == 1
        assert counts["low"] == 1
        assert counts["critical"] == 0


class TestReporter:
    def test_json_report(self, tmp_path):
        reporter = Reporter(output_dir=str(tmp_path))
        result = ScanResult(
            scanner_name="s",
            target="t",
            findings=[Finding("R", "T", "D", Severity.MEDIUM, "c")],
        )
        path = reporter.report(result, fmt=OutputFormat.JSON)
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data[0]["scanner_name"] == "s"

    def test_markdown_report(self, tmp_path):
        reporter = Reporter(output_dir=str(tmp_path))
        result = ScanResult(
            scanner_name="s",
            target="t",
            findings=[Finding("R", "T", "D", Severity.HIGH, "c")],
        )
        path = reporter.report(result, fmt=OutputFormat.MARKDOWN)
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "# AI Security Pipeline Report" in content

    def test_sarif_report(self, tmp_path):
        reporter = Reporter(output_dir=str(tmp_path))
        result = ScanResult(
            scanner_name="s",
            target="t",
            findings=[Finding("R", "T", "D", Severity.CRITICAL, "c")],
        )
        path = reporter.report(result, fmt=OutputFormat.SARIF)
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"


class TestPipeline:
    def test_register_and_run(self, tmp_path):
        cfg = PipelineConfig(name="test", modules=["dummy"], output_dir=str(tmp_path))
        pipeline = Pipeline(cfg)
        pipeline.register_scanner("dummy", DummyScanner)
        results = pipeline.run({"dummy": {"test": True}})
        assert len(results) == 1
        assert results[0].scanner_name == "dummy_scanner"

    def test_report_generation(self, tmp_path):
        cfg = PipelineConfig(
            name="test",
            modules=["dummy"],
            output_formats=["json"],
            output_dir=str(tmp_path),
        )
        pipeline = Pipeline(cfg)
        pipeline.register_scanner("dummy", DummyScanner)
        pipeline.run({"dummy": {}})
        paths = pipeline.report()
        assert len(paths) == 1
        assert os.path.exists(paths[0])
