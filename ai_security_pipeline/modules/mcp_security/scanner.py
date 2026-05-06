"""MCP Security Scanner implementation."""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from ...core.scanner import BaseScanner, Finding, ScanResult, Severity


class MCPSecurityScanner(BaseScanner):
    """Scanner for MCP server security issues."""

    name = "mcp_security"
    description = "MCP server security scanner"
    version = "1.0.0"

    # Common hardcoded secret patterns
    SECRET_PATTERNS = [
        (r'sk-[a-zA-Z0-9]{48}', "OpenAI API key"),
        (r'gh[pousr]_[A-Za-z0-9_]{36,}', "GitHub token"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
        (r'[a-zA-Z0-9+/]{40}={0,2}', "Base64 secret (potential)"),
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private key"),
        (r'api[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}', "API key"),
        (r'password\s*[:=]\s*["\']?[^"\'\s]{8,}', "Hardcoded password"),
        (r'token\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,}', "Hardcoded token"),
    ]

    # Supply chain risk patterns
    SUPPLY_CHAIN_PATTERNS = [
        (r'git\+https?://[^\s"\']+', "Unverified git source"),
        (r'https?://[^/]+\.(zip|tar\.gz|tgz|whl)', "Direct binary download"),
    ]

    def scan(self, target: Any) -> ScanResult:
        self._findings = []
        self._errors = []
        config = target if isinstance(target, dict) else {}
        target_name = config.get("name", str(target))

        try:
            self._check_auth(config)
            self._check_sandbox(config)
            self._check_exfiltration(config)
            self._check_rate_limiting(config)
            self._check_secrets(config)
            self._check_supply_chain(config)
            self._check_permissions(config)
            self._check_logging(config)
        except Exception as e:
            self.add_error(f"Scan error: {e}")

        return self._build_result(target_name)

    def _check_auth(self, config: Dict[str, Any]) -> None:
        auth = config.get("auth", {})
        if not auth.get("enabled", False):
            self.add_finding(Finding(
                rule_id="MCP-AUTH-001",
                title="Authentication disabled",
                description="MCP server has authentication disabled. Any client can connect without credentials.",
                severity=Severity.CRITICAL,
                category="authentication",
                remediation="Enable authentication on all MCP endpoints. Use token-based or OAuth2 authentication.",
                references=["https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/"],
            ))
        elif auth.get("type") == "none":
            self.add_finding(Finding(
                rule_id="MCP-AUTH-002",
                title="Weak authentication type",
                description="Authentication type is explicitly set to 'none'. This allows unrestricted access.",
                severity=Severity.HIGH,
                category="authentication",
                remediation="Use token-based (Bearer), OAuth2, or mTLS authentication.",
                references=["https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/"],
            ))
        elif auth.get("type") == "basic":
            self.add_finding(Finding(
                rule_id="MCP-AUTH-003",
                title="Basic authentication in use",
                description="HTTP Basic Auth detected. Credentials are sent in Base64 with every request and vulnerable to interception.",
                severity=Severity.HIGH,
                category="authentication",
                remediation="Migrate to token-based or OAuth2 authentication. If basic auth is required, enforce HTTPS-only.",
            ))

        # Check for weak auth settings
        if auth.get("allow_anonymous", False):
            self.add_finding(Finding(
                rule_id="MCP-AUTH-004",
                title="Anonymous access allowed",
                description="The MCP server allows anonymous (unauthenticated) requests alongside authenticated ones.",
                severity=Severity.HIGH,
                category="authentication",
                remediation="Disable anonymous access. Require authentication for all endpoints.",
            ))

    def _check_sandbox(self, config: Dict[str, Any]) -> None:
        sandbox = config.get("sandbox", {})
        if not sandbox.get("enabled", False):
            self.add_finding(Finding(
                rule_id="MCP-SBX-001",
                title="Sandboxing disabled",
                description="Tool sandboxing is not enabled. Arbitrary code execution from MCP tools is unrestricted.",
                severity=Severity.HIGH,
                category="sandbox",
                remediation="Enable container-based sandboxing (e.g., Docker, gVisor) for tool execution.",
                references=["https://docs.docker.com/engine/security/"],
            ))

        sandbox_type = sandbox.get("type", "none")
        if sandbox_type == "none" or sandbox_type == "process":
            self.add_finding(Finding(
                rule_id="MCP-SBX-002",
                title="Weak sandbox type",
                description=f"Sandbox type is '{sandbox_type}', which provides minimal isolation. Process-level isolation can be bypassed.",
                severity=Severity.MEDIUM,
                category="sandbox",
                remediation="Use container-based (Docker) or VM-based (Firecracker, gVisor) sandboxing.",
            ))

        if not sandbox.get("network_restricted", False):
            self.add_finding(Finding(
                rule_id="MCP-SBX-003",
                title="Unrestricted network in sandbox",
                description="Sandboxed tools have unrestricted network access, enabling SSRF and data exfiltration.",
                severity=Severity.HIGH,
                category="sandbox",
                remediation="Apply network policies to restrict outbound connections from sandboxes.",
            ))

    def _check_exfiltration(self, config: Dict[str, Any]) -> None:
        data = config.get("data_handling", {})
        if not data.get("classification", False):
            self.add_finding(Finding(
                rule_id="MCP-EXF-001",
                title="Missing data classification",
                description="Data classification policies are not configured. Sensitive data may be leaked via MCP tool outputs.",
                severity=Severity.MEDIUM,
                category="data_exfiltration",
                remediation="Implement data classification (public, internal, confidential, restricted) and enforce access controls.",
            ))

        if not data.get("output_filtering", False):
            self.add_finding(Finding(
                rule_id="MCP-EXF-002",
                title="Output filtering disabled",
                description="Tool output is not filtered or sanitized. Sensitive data in tool responses may leak to the LLM or user.",
                severity=Severity.HIGH,
                category="data_exfiltration",
                remediation="Implement output filtering and PII detection on tool responses.",
            ))

        allowed_domains = data.get("allowed_domains", [])
        if allowed_domains == ["*"] or not allowed_domains:
            self.add_finding(Finding(
                rule_id="MCP-EXF-003",
                title="Unrestricted external data access",
                description="MCP server allows tools to fetch data from any external domain, enabling data exfiltration.",
                severity=Severity.HIGH,
                category="data_exfiltration",
                remediation="Maintain an explicit allowlist of trusted domains for external data access.",
            ))

    def _check_rate_limiting(self, config: Dict[str, Any]) -> None:
        rl = config.get("rate_limiting", {})
        if not rl.get("enabled", False):
            self.add_finding(Finding(
                rule_id="MCP-RL-001",
                title="Rate limiting disabled",
                description="Rate limiting is not enabled on MCP endpoints. Vulnerable to brute force and DoS attacks.",
                severity=Severity.MEDIUM,
                category="rate_limiting",
                remediation="Enable rate limiting (e.g., 100 req/min per client) on all MCP endpoints.",
            ))

        reqs_per_min = rl.get("requests_per_minute", 0)
        if reqs_per_min > 1000 or reqs_per_min == 0:
            self.add_finding(Finding(
                rule_id="MCP-RL-002",
                title="Excessive rate limit",
                description=f"Rate limit is {reqs_per_min} req/min, which is too high to provide meaningful protection.",
                severity=Severity.LOW,
                category="rate_limiting",
                remediation="Set reasonable rate limits: 100-300 req/min for standard clients, burst limits for batch operations.",
            ))

    def _check_secrets(self, config: Dict[str, Any]) -> None:
        config_text = json.dumps(config, default=str)
        secrets = config.get("secrets", {})

        if secrets.get("hardcoded", False):
            self.add_finding(Finding(
                rule_id="MCP-SEC-001",
                title="Hardcoded secrets detected",
                description="Configuration indicates hardcoded credentials are present in source code or config files.",
                severity=Severity.CRITICAL,
                category="secrets",
                remediation="Move secrets to environment variables, secret managers (HashiCorp Vault, AWS Secrets Manager), or encrypted config.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
            ))

        # Pattern-based secret detection
        for pattern, secret_type in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, config_text, re.IGNORECASE):
                matched = match.group()
                # Skip very short matches that are likely false positives
                if len(matched) < 12:
                    continue
                self.add_finding(Finding(
                    rule_id="MCP-SEC-002",
                    title=f"Potential {secret_type} in config",
                    description=f"Detected potential {secret_type} pattern in configuration: '{matched[:20]}...'",
                    severity=Severity.CRITICAL,
                    category="secrets",
                    remediation="Remove hardcoded secrets. Use environment variables or a secret manager.",
                    location=f"config offset {match.start()}",
                ))

    def _check_supply_chain(self, config: Dict[str, Any]) -> None:
        deps = config.get("dependencies", {})

        if deps.get("unpinned", False):
            self.add_finding(Finding(
                rule_id="MCP-SC-001",
                title="Unpinned dependencies",
                description="Dependencies are not pinned to specific versions. Vulnerable to dependency confusion and supply chain attacks.",
                severity=Severity.MEDIUM,
                category="supply_chain",
                remediation="Pin all dependencies to exact versions with cryptographic hashes (SHA-256).",
                references=["https://owasp.org/www-project-software-component-verification-standard/"],
            ))

        dep_list = deps.get("packages", [])
        for dep in dep_list:
            dep_str = str(dep)
            for pattern, risk in self.SUPPLY_CHAIN_PATTERNS:
                if re.search(pattern, dep_str, re.IGNORECASE):
                    self.add_finding(Finding(
                        rule_id="MCP-SC-002",
                        title="Unverified dependency source",
                        description=f"Dependency '{dep_str[:60]}...' sourced from unverified location. Risk of malicious package injection.",
                        severity=Severity.HIGH,
                        category="supply_chain",
                        remediation="Use official package registries (PyPI, npm). Verify package signatures and checksums.",
                    ))
                    break

        # Check for typosquatting indicators
        dep_names = [str(d).split("==")[0].split("@")[0].strip().lower() for d in dep_list]
        suspicious = [d for d in dep_names if self._is_typosquatting_candidate(d)]
        for pkg in suspicious:
            self.add_finding(Finding(
                rule_id="MCP-SC-003",
                title="Potential typosquatting dependency",
                description=f"Dependency '{pkg}' may be a typosquatted package name targeting a popular library.",
                severity=Severity.MEDIUM,
                category="supply_chain",
                remediation=f"Verify the package '{pkg}' on the official registry. Check download counts and maintainer reputation.",
            ))

    def _check_permissions(self, config: Dict[str, Any]) -> None:
        perms = config.get("permissions", {})
        if perms.get("filesystem", "read") == "write" and perms.get("filesystem_path", "/") == "/":
            self.add_finding(Finding(
                rule_id="MCP-PERM-001",
                title="Unrestricted filesystem write access",
                description="MCP server allows unrestricted filesystem write access to the root directory.",
                severity=Severity.CRITICAL,
                category="permissions",
                remediation="Restrict filesystem access to specific directories. Use read-only access where possible.",
            ))

        if perms.get("command_execution", False):
            self.add_finding(Finding(
                rule_id="MCP-PERM-002",
                title="Arbitrary command execution allowed",
                description="MCP server permits arbitrary command execution from tools without restrictions.",
                severity=Severity.CRITICAL,
                category="permissions",
                remediation="Disable arbitrary command execution. Use allowlists for permitted commands and arguments.",
            ))

    def _check_logging(self, config: Dict[str, Any]) -> None:
        logging = config.get("logging", {})
        if not logging.get("enabled", False):
            self.add_finding(Finding(
                rule_id="MCP-LOG-001",
                title="Logging disabled",
                description="Security logging is not enabled. Failed authentication, policy violations, and anomalies are not recorded.",
                severity=Severity.MEDIUM,
                category="logging",
                remediation="Enable comprehensive security logging for all MCP operations including auth events and tool executions.",
            ))

        if logging.get("mask_secrets", True) is False:
            self.add_finding(Finding(
                rule_id="MCP-LOG-002",
                title="Secrets not masked in logs",
                description="Logging configuration does not mask secrets. API keys and tokens may be logged in plaintext.",
                severity=Severity.HIGH,
                category="logging",
                remediation="Enable secret masking/redaction in log output.",
            ))

    @staticmethod
    def _is_typosquatting_candidate(name: str) -> bool:
        """Heuristic: flag names that are close to common packages with slight variations."""
        common = {"requests", "numpy", "pandas", "flask", "django", "urllib3", "cryptography",
                  "fastapi", "sqlalchemy", "pytest", "click", "rich", "httpx", "aiohttp",
                  "mcp", "openai", "anthropic", "langchain"}
        for pkg in common:
            if name == pkg:
                continue
            if len(name) > 3 and (name in pkg or pkg in name):
                return True
            # Check Levenshtein distance for typosquatting
            if abs(len(name) - len(pkg)) <= 2:
                diff = sum(1 for a, b in zip(name, pkg) if a != b)
                diff += abs(len(name) - len(pkg))
                if diff <= 2:
                    return True
        return False
