"""LLM Runtime Scanner implementation."""

from typing import Any, Dict

from ...core.scanner import BaseScanner, Finding, ScanResult, Severity


class LLMRuntimeScanner(BaseScanner):
    """Scanner for LLM runtime security issues."""

    name = "llm_runtime"
    description = "LLM runtime security scanner"
    version = "0.1.0"

    def scan(self, target: Any) -> ScanResult:
        self._findings = []
        self._errors = []
        config = target if isinstance(target, dict) else {}

        self._check_model_loading(config)
        self._check_inference(config)
        self._check_memory_safety(config)
        self._check_api_hardening(config)

        return self._build_result(str(target))

    def _check_model_loading(self, config: Dict[str, Any]) -> None:
        model = config.get("model", {})
        if not model.get("signature_verification", False):
            self.add_finding(Finding(
                rule_id="LLM-ML-001",
                title="Model signature not verified",
                description="Model file signature verification is disabled.",
                severity=Severity.HIGH,
                category="model_loading",
                remediation="Enable cryptographic signature verification for model files.",
            ))

    def _check_inference(self, config: Dict[str, Any]) -> None:
        inference = config.get("inference", {})
        if not inference.get("input_validation", False):
            self.add_finding(Finding(
                rule_id="LLM-INF-001",
                title="Input validation disabled",
                description="Inference input validation is not enabled.",
                severity=Severity.HIGH,
                category="inference",
                remediation="Enable input validation and sanitization.",
            ))

    def _check_memory_safety(self, config: Dict[str, Any]) -> None:
        memory = config.get("memory", {})
        if not memory.get("isolation", False):
            self.add_finding(Finding(
                rule_id="LLM-MEM-001",
                title="Memory isolation disabled",
                description="Model memory isolation is not configured.",
                severity=Severity.MEDIUM,
                category="memory_safety",
                remediation="Enable memory isolation between inference requests.",
            ))

    def _check_api_hardening(self, config: Dict[str, Any]) -> None:
        api = config.get("api", {})
        if not api.get("https_only", False):
            self.add_finding(Finding(
                rule_id="LLM-API-001",
                title="HTTP allowed",
                description="API accepts unencrypted HTTP connections.",
                severity=Severity.MEDIUM,
                category="api_hardening",
                remediation="Enforce HTTPS-only connections.",
            ))
