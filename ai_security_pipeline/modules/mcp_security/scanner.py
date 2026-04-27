"""MCP Security Scanner implementation."""

from typing import Any, Dict, Optional

from ...core.scanner import BaseScanner, Finding, ScanResult, Severity


class MCPSecurityScanner(BaseScanner):
    """Scanner for MCP server security issues."""

    name = "mcp_security"
    description = "MCP server security scanner"
    version = "0.1.0"

    def scan(self, target: Any) -> ScanResult:
        self._findings = []
        self._errors = []
        config = target if isinstance(target, dict) else {}

        self._check_auth(config)
        self._check_sandbox(config)
        self._check_exfiltration(config)
        self._check_rate_limiting(config)
        self._check_secrets(config)
        self._check_supply_chain(config)

        return self._build_result(str(target))

    def _check_auth(self, config: Dict[str, Any]) -> None:
        auth = config.get("auth", {})
        if not auth.get("enabled", False):
            self.add_finding(Finding(
                rule_id="MCP-AUTH-001",
                title="Authentication disabled",
                description="MCP server has authentication disabled.",
                severity=Severity.CRITICAL,
                category="authentication",
                remediation="Enable authentication on all MCP endpoints.",
            ))
        if auth.get("type") == "none":
            self.add_finding(Finding(
                rule_id="MCP-AUTH-002",
                title="Weak authentication type",
                description="Authentication type is set to 'none'.",
                severity=Severity.HIGH,
                category="authentication",
                remediation="Use token-based or OAuth2 authentication.",
            ))

    def _check_sandbox(self, config: Dict[str, Any]) -> None:
        sandbox = config.get("sandbox", {})
        if not sandbox.get("enabled", False):
            self.add_finding(Finding(
                rule_id="MCP-SBX-001",
                title="Sandboxing disabled",
                description="Tool sandboxing is not enabled.",
                severity=Severity.HIGH,
                category="sandbox",
                remediation="Enable container-based sandboxing for tool execution.",
            ))

    def _check_exfiltration(self, config: Dict[str, Any]) -> None:
        data = config.get("data_handling", {})
        if not data.get("classification", False):
            self.add_finding(Finding(
                rule_id="MCP-EXF-001",
                title="Missing data classification",
                description="Data classification is not configured.",
                severity=Severity.MEDIUM,
                category="data_exfiltration",
                remediation="Implement data classification policies.",
            ))

    def _check_rate_limiting(self, config: Dict[str, Any]) -> None:
        rl = config.get("rate_limiting", {})
        if not rl.get("enabled", False):
            self.add_finding(Finding(
                rule_id="MCP-RL-001",
                title="Rate limiting disabled",
                description="Rate limiting is not enabled on MCP endpoints.",
                severity=Severity.MEDIUM,
                category="rate_limiting",
                remediation="Enable rate limiting to prevent abuse.",
            ))

    def _check_secrets(self, config: Dict[str, Any]) -> None:
        secrets = config.get("secrets", {})
        if secrets.get("hardcoded", False):
            self.add_finding(Finding(
                rule_id="MCP-SEC-001",
                title="Hardcoded secrets detected",
                description="Hardcoded credentials found in configuration.",
                severity=Severity.CRITICAL,
                category="secrets",
                remediation="Use environment variables or secret management.",
            ))

    def _check_supply_chain(self, config: Dict[str, Any]) -> None:
        deps = config.get("dependencies", {})
        if deps.get("unpinned", False):
            self.add_finding(Finding(
                rule_id="MCP-SC-001",
                title="Unpinned dependencies",
                description="Dependencies are not pinned to specific versions.",
                severity=Severity.LOW,
                category="supply_chain",
                remediation="Pin all dependencies to exact versions.",
            ))
