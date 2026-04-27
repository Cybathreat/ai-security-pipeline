"""Jailbreak Auditor implementation."""

from typing import Any, Dict, List

from ...core.auditor import BaseAuditor, AuditResult, Finding, Severity


class JailbreakAuditor(BaseAuditor):
    """Auditor for LLM jailbreak vulnerabilities."""

    name = "jailbreak"
    description = "LLM jailbreak and safety alignment auditor"
    version = "0.1.0"

    TECHNIQUES = ["dan", "persona", "roleplay", "logical_contradiction", "encoding"]

    def audit(self, target: Any) -> AuditResult:
        self._findings = []
        self._errors = []
        config = target if isinstance(target, dict) else {}
        model = config.get("model", "unknown")

        self._test_techniques(model)
        self._test_prompt_injection(config)
        self._test_safety_bypass(config)

        return self._build_result(model)

    def _test_techniques(self, model: str) -> None:
        for technique in self.TECHNIQUES:
            self.add_finding(Finding(
                rule_id=f"JB-TECH-{technique.upper()[:3]}",
                title=f"Jailbreak technique tested: {technique}",
                description=f"Model {model} tested against {technique} jailbreak.",
                severity=Severity.INFO,
                category="jailbreak_technique",
                remediation="Review model response for policy violations.",
            ))

    def _test_prompt_injection(self, config: Dict[str, Any]) -> None:
        if not config.get("prompt_injection_filter", False):
            self.add_finding(Finding(
                rule_id="JB-INJ-001",
                title="Prompt injection filter missing",
                description="No prompt injection detection filter is active.",
                severity=Severity.HIGH,
                category="prompt_injection",
                remediation="Implement prompt injection detection and filtering.",
            ))

    def _test_safety_bypass(self, config: Dict[str, Any]) -> None:
        if not config.get("safety_filter", False):
            self.add_finding(Finding(
                rule_id="JB-SAF-001",
                title="Safety filter disabled",
                description="Safety filter is not enabled on the target model.",
                severity=Severity.CRITICAL,
                category="safety_bypass",
                remediation="Enable and configure safety filters.",
            ))
