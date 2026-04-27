"""Tests for security modules."""

import pytest

from ai_security_pipeline.modules.mcp_security.scanner import MCPSecurityScanner
from ai_security_pipeline.modules.llm_runtime.scanner import LLMRuntimeScanner
from ai_security_pipeline.modules.jailbreak.auditor import JailbreakAuditor


class TestMCPSecurityScanner:
    def test_scan_finds_issues(self):
        scanner = MCPSecurityScanner()
        result = scanner.scan({
            "auth": {"enabled": False},
            "sandbox": {"enabled": False},
            "secrets": {"hardcoded": True},
        })
        assert len(result.findings) >= 3
        severities = [f.severity.value for f in result.findings]
        assert "critical" in severities

    def test_scan_clean_config(self):
        scanner = MCPSecurityScanner()
        result = scanner.scan({
            "auth": {"enabled": True, "type": "token"},
            "sandbox": {"enabled": True},
            "secrets": {"hardcoded": False},
        })
        assert len(result.findings) == 2  # exfiltration + rate limiting defaults


class TestLLMRuntimeScanner:
    def test_scan_finds_issues(self):
        scanner = LLMRuntimeScanner()
        result = scanner.scan({
            "model": {"signature_verification": False},
            "inference": {"input_validation": False},
        })
        assert len(result.findings) >= 4

    def test_scan_clean_config(self):
        scanner = LLMRuntimeScanner()
        result = scanner.scan({
            "model": {"signature_verification": True},
            "inference": {"input_validation": True},
            "memory": {"isolation": True},
            "api": {"https_only": True},
        })
        assert len(result.findings) == 0


class TestJailbreakAuditor:
    def test_audit_finds_issues(self):
        auditor = JailbreakAuditor()
        result = auditor.audit({
            "model": "gpt-4",
            "prompt_injection_filter": False,
            "safety_filter": False,
        })
        assert len(result.findings) >= 7  # 5 techniques + 2 filters

    def test_audit_clean_config(self):
        auditor = JailbreakAuditor()
        result = auditor.audit({
            "model": "gpt-4",
            "prompt_injection_filter": True,
            "safety_filter": True,
        })
        assert len(result.findings) == 5  # only info-level technique tests
