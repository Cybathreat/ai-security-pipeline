# AI Security Pipeline

A unified security framework integrating MCP server scanning, LLM runtime detection, and AI jailbreak testing.

## Overview

AI Security Pipeline consolidates three critical AI security domains into a single, modular tool:

1. **MCP Security Scanner** — Audit MCP servers for auth weaknesses, sandbox misconfigurations, data exfiltration vectors, secrets leakage, and supply chain risks
2. **LLM Runtime Detector** — Detect model loading attacks, inference-time exploits, memory safety issues, and API misconfigurations
3. **AI Jailbreak Framework** — Test LLM safety alignment, generate adversarial payloads, fingerprint models, and fuzz APIs

## Features

- **Unified CLI** — Single entry point for all security operations
- **Modular Architecture** — Pluggable modules, use only what you need
- **Multiple Output Formats** — JSON, Markdown, SARIF for CI/CD integration
- **Configuration-Driven** — YAML configs for repeatable scans
- **Pipeline Orchestration** — Chain multiple scans into automated workflows
- **Comprehensive Testing** — 90%+ test coverage

## Installation

```bash
git clone https://github.com/cybathreat/ai-security-pipeline.git
cd ai-security-pipeline
pip install -r requirements.txt
```

## Usage

### Run Full Pipeline
```bash
python -m ai_security_pipeline scan --config config/default.yaml --output reports/
```

### Run Specific Modules
```bash
# MCP security audit
python -m ai_security_pipeline scan --module mcp --target config/mcp.yaml

# LLM runtime check
python -m ai_security_pipeline scan --module llm --model-path ./model.bin

# Jailbreak test
python -m ai_security_pipeline audit --module jailbreak --target gpt-4
```

### Generate Reports
```bash
# SARIF for GitHub Advanced Security
python -m ai_security_pipeline report --input results.json --format sarif --output report.sarif

# Markdown for human review
python -m ai_security_pipeline report --input results.json --format markdown --output report.md
```

### Configuration
```yaml
# config/default.yaml
pipeline:
  name: "Full Security Audit"
  modules:
    - mcp_security
    - llm_runtime
    - jailbreak

output:
  formats: [json, markdown]
  directory: ./reports
  min_severity: medium
```

## Architecture

```
ai_security_pipeline/
├── core/           # Framework engine (scanner, auditor, reporter, pipeline)
├── modules/        # Security modules
│   ├── mcp_security/
│   ├── llm_runtime/
│   └── jailbreak/
├── utils/          # Logging and helpers
└── cli.py          # Unified command-line interface
```

## Modules

### MCP Security
- Authentication scanner (weak auth, hardcoded credentials)
- Sandbox validator (command injection, path traversal, SSRF)
- Data exfiltration detector
- Rate limiting analyzer
- Secrets detection (API keys, tokens, private keys)
- Supply chain security (CVE, typosquatting, dependency confusion)

### LLM Runtime
- Model loading attack detection (tampered models, symlink attacks)
- Inference attack detection (prompt injection, jailbreaks)
- Memory safety validation
- API hardening checks
- Rate limiting and abuse prevention

### Jailbreak Testing
- Jailbreak technique library (DAN, persona adoption, logical contradictions)
- Prompt injection testing framework
- Adversarial payload generator
- Safety bypass detection
- Model fingerprinting
- API fuzzer

## Development

```bash
# Run tests
pytest tests/ -v --cov=ai_security_pipeline --cov-report=term-missing

# Lint
pylint ai_security_pipeline/

# Type check
mypy ai_security_pipeline/
```

## License

MIT License — See LICENSE file

## Author

Cybathreat (Ahmed Chiboub) — Cyberian Defenses
https://github.com/cybathreat
