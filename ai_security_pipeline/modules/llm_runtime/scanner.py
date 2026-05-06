"""LLM Runtime Scanner implementation."""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from ...core.scanner import BaseScanner, Finding, ScanResult, Severity


class LLMRuntimeScanner(BaseScanner):
    """Scanner for LLM runtime security issues."""

    name = "llm_runtime"
    description = "LLM runtime security scanner"
    version = "1.0.0"

    # Known vulnerable model file signatures (placeholder - real ones would be a database)
    KNOWN_VULNERABLE_HASHES: set = set()

    # Prompt injection patterns
    INJECTION_PATTERNS = [
        r'ignore\s+(all\s+)?(previous|above)\s+instructions',
        r'system\s*:.*override',
        r'\{\{.*?\}\}',  # Template injection
        r'disregard\s+.*safety',
        r'jailbreak|DAN|Developer\s+Mode',
        r'pretend\s+to\s+be',
        r'new\s+instruction\s*:\s*',
        r'role\s*:\s*system',
    ]

    def scan(self, target: Any) -> ScanResult:
        self._findings = []
        self._errors = []
        config = target if isinstance(target, dict) else {}
        target_name = config.get("model_name", config.get("endpoint", str(target)))

        try:
            self._check_model_loading(config)
            self._check_inference(config)
            self._check_memory_safety(config)
            self._check_api_hardening(config)
            self._check_input_validation(config)
            self._check_output_safety(config)
        except Exception as e:
            self.add_error(f"Scan error: {e}")

        return self._build_result(target_name)

    def _check_model_loading(self, config: Dict[str, Any]) -> None:
        model = config.get("model", {})
        model_path = model.get("path", "")

        if not model.get("signature_verification", False):
            self.add_finding(Finding(
                rule_id="LLM-ML-001",
                title="Model signature not verified",
                description="Model file signature verification is disabled. Tampered or malicious model files can be loaded.",
                severity=Severity.HIGH,
                category="model_loading",
                remediation="Enable cryptographic signature verification for all model files using SHA-256 or stronger.",
                references=["https://www.nist.gov/itl/applied-cybersecurity/software-supply-chain-security"],
            ))

        if not model.get("checksum_verification", False) and model_path:
            self.add_finding(Finding(
                rule_id="LLM-ML-002",
                title="Model checksum not verified",
                description="Model file integrity checksum verification is disabled.",
                severity=Severity.HIGH,
                category="model_loading",
                remediation="Verify model file checksums (SHA-256) against a trusted registry before loading.",
            ))

        # Check for known vulnerable hashes
        if model_path and model.get("hash"):
            file_hash = model.get("hash")
            if file_hash in self.KNOWN_VULNERABLE_HASHES:
                self.add_finding(Finding(
                    rule_id="LLM-ML-003",
                    title="Known vulnerable model hash detected",
                    description=f"Model hash {file_hash} matches a known vulnerable model file.",
                    severity=Severity.CRITICAL,
                    category="model_loading",
                    remediation="Replace with a patched model version. Check model vendor security advisories.",
                ))

        # Symlink attack check
        if model_path and model.get("follow_symlinks", True):
            self.add_finding(Finding(
                rule_id="LLM-ML-004",
                title="Symlink following enabled for model files",
                description="Model loader follows symbolic links. An attacker can redirect model loading to arbitrary files.",
                severity=Severity.HIGH,
                category="model_loading",
                remediation="Disable symlink following for model files. Validate canonical paths.",
            ))

        # Unsafe deserialization
        if model.get("serialization_format") in ["pickle", "joblib", "dill"]:
            self.add_finding(Finding(
                rule_id="LLM-ML-005",
                title="Unsafe model serialization format",
                description=f"Model uses {model.get('serialization_format')} serialization which can execute arbitrary code during loading.",
                severity=Severity.CRITICAL,
                category="model_loading",
                remediation="Use SafeTensors or ONNX for model serialization. Avoid pickle/Joblib for untrusted models.",
                references=["https://huggingface.co/docs/safetensors/index"],
            ))

    def _check_inference(self, config: Dict[str, Any]) -> None:
        inference = config.get("inference", {})
        if not inference.get("input_validation", False):
            self.add_finding(Finding(
                rule_id="LLM-INF-001",
                title="Input validation disabled",
                description="Inference input validation is not enabled. Malformed or adversarial inputs can crash or manipulate the model.",
                severity=Severity.HIGH,
                category="inference",
                remediation="Enable input validation: length limits, character filtering, schema validation.",
            ))

        if not inference.get("output_filtering", False):
            self.add_finding(Finding(
                rule_id="LLM-INF-002",
                title="Output filtering disabled",
                description="Inference output is not filtered. The model may generate harmful, toxic, or sensitive content.",
                severity=Severity.MEDIUM,
                category="inference",
                remediation="Implement output filtering for toxicity, PII, and policy violations.",
            ))

        # Check for temperature/top_p manipulation vulnerabilities
        if inference.get("temperature", 0.7) > 1.5:
            self.add_finding(Finding(
                rule_id="LLM-INF-003",
                title="Excessive inference temperature",
                description=f"Inference temperature is {inference.get('temperature')}, which increases output randomness and may bypass safety filters.",
                severity=Severity.LOW,
                category="inference",
                remediation="Set temperature to 0.7 or below for production use. Use top_p <= 0.9.",
            ))

        max_tokens = inference.get("max_tokens", 0)
        if max_tokens == 0 or max_tokens > 8192:
            self.add_finding(Finding(
                rule_id="LLM-INF-004",
                title="Unbounded token generation",
                description=f"max_tokens is {max_tokens if max_tokens > 0 else 'unlimited'}, allowing potentially unbounded generation.",
                severity=Severity.LOW,
                category="inference",
                remediation="Set a reasonable max_tokens limit (e.g., 2048) to control cost and output.",
            ))

    def _check_memory_safety(self, config: Dict[str, Any]) -> None:
        memory = config.get("memory", {})
        if not memory.get("isolation", False):
            self.add_finding(Finding(
                rule_id="LLM-MEM-001",
                title="Memory isolation disabled",
                description="Model memory isolation is not configured. Cross-request data leakage between users is possible.",
                severity=Severity.MEDIUM,
                category="memory_safety",
                remediation="Enable memory isolation between inference requests. Use separate process pools or containers per user.",
            ))

        if not memory.get("kv_cache_clearing", True):
            self.add_finding(Finding(
                rule_id="LLM-MEM-002",
                title="KV cache not cleared between requests",
                description="Key-value cache is retained across requests, potentially leaking conversation context.",
                severity=Severity.HIGH,
                category="memory_safety",
                remediation="Clear KV cache after each request. Implement session isolation.",
            ))

        if memory.get("shared_memory", False):
            self.add_finding(Finding(
                rule_id="LLM-MEM-003",
                title="Shared memory between inference sessions",
                description="Multiple inference sessions share memory space. One session can read another's data.",
                severity=Severity.CRITICAL,
                category="memory_safety",
                remediation="Use process-level or container-level isolation. Disable shared memory.",
            ))

        max_mem = memory.get("max_memory_gb", 0)
        if max_mem == 0 or max_mem > 64:
            self.add_finding(Finding(
                rule_id="LLM-MEM-004",
                title="Unbounded memory allocation",
                description=f"Memory limit is {max_mem if max_mem > 0 else 'unlimited'} GB. Risk of OOM and denial of service.",
                severity=Severity.MEDIUM,
                category="memory_safety",
                remediation="Set max_memory_gb to a reasonable limit (e.g., 16-32 GB) for the workload.",
            ))

    def _check_api_hardening(self, config: Dict[str, Any]) -> None:
        api = config.get("api", {})
        if not api.get("https_only", False):
            self.add_finding(Finding(
                rule_id="LLM-API-001",
                title="HTTP allowed",
                description="API accepts unencrypted HTTP connections. Model weights, inputs, and outputs are transmitted in plaintext.",
                severity=Severity.MEDIUM,
                category="api_hardening",
                remediation="Enforce HTTPS-only connections. Redirect HTTP to HTTPS.",
            ))

        if not api.get("authentication", False):
            self.add_finding(Finding(
                rule_id="LLM-API-002",
                title="API authentication disabled",
                description="Inference API does not require authentication. Anyone can consume model resources.",
                severity=Severity.CRITICAL,
                category="api_hardening",
                remediation="Require API key or OAuth2 authentication for all inference endpoints.",
            ))

        if not api.get("rate_limiting", False):
            self.add_finding(Finding(
                rule_id="LLM-API-003",
                title="API rate limiting disabled",
                description="No rate limiting on inference API. Vulnerable to abuse and cost overruns.",
                severity=Severity.MEDIUM,
                category="api_hardening",
                remediation="Implement per-client rate limiting (e.g., 100 req/min) and token quotas.",
            ))

        if api.get("cors", "*") == "*":
            self.add_finding(Finding(
                rule_id="LLM-API-004",
                title="Permissive CORS policy",
                description="CORS is set to allow all origins (*). CSRF and unauthorized cross-origin requests are possible.",
                severity=Severity.MEDIUM,
                category="api_hardening",
                remediation="Restrict CORS to specific trusted origins. Remove wildcard CORS.",
            ))

    def _check_input_validation(self, config: Dict[str, Any]) -> None:
        validation = config.get("input_validation", {})
        if not validation.get("enabled", False):
            self.add_finding(Finding(
                rule_id="LLM-VAL-001",
                title="Input validation disabled",
                description="No input validation on inference requests. Adversarial inputs can cause crashes or unexpected behavior.",
                severity=Severity.HIGH,
                category="input_validation",
                remediation="Enable input validation: schema validation, length limits, encoding checks.",
            ))

        # Check for common prompt injection patterns in config (test data)
        config_text = json.dumps(config, default=str)
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, config_text, re.IGNORECASE):
                self.add_finding(Finding(
                    rule_id="LLM-VAL-002",
                    title="Prompt injection pattern in config",
                    description=f"Detected prompt injection-related pattern in configuration matching: {pattern[:50]}",
                    severity=Severity.MEDIUM,
                    category="input_validation",
                    remediation="Sanitize all user inputs. Implement prompt injection detection filters.",
                ))
                break  # One finding is enough for config

    def _check_output_safety(self, config: Dict[str, Any]) -> None:
        output = config.get("output_safety", {})
        if not output.get("toxicity_filter", False):
            self.add_finding(Finding(
                rule_id="LLM-OUT-001",
                title="Toxicity filtering disabled",
                description="Model output is not filtered for toxic or harmful content.",
                severity=Severity.MEDIUM,
                category="output_safety",
                remediation="Enable toxicity classification and filtering on model outputs.",
            ))

        if not output.get("pii_detection", False):
            self.add_finding(Finding(
                rule_id="LLM-OUT-002",
                title="PII detection disabled",
                description="Model output is not scanned for leaked personally identifiable information.",
                severity=Severity.MEDIUM,
                category="output_safety",
                remediation="Enable PII detection and redaction in model outputs before returning to users.",
            ))

        if output.get("log_outputs", True) and not output.get("mask_pii_in_logs", True):
            self.add_finding(Finding(
                rule_id="LLM-OUT-003",
                title="PII not masked in output logs",
                description="Model outputs are logged without PII masking, risking data exposure in logs.",
                severity=Severity.HIGH,
                category="output_safety",
                remediation="Mask or redact PII in logged model outputs.",
            ))
