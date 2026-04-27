"""Unified CLI for AI Security Pipeline."""

import sys
from pathlib import Path
from typing import Optional

import click

from .config import Config
from .core.pipeline import Pipeline, PipelineConfig
from .core.reporter import OutputFormat
from .utils.logger import get_logger

logger = get_logger("cli")


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """AI Security Pipeline — Unified AI Security Framework."""
    pass


@cli.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Pipeline configuration file (YAML)")
@click.option("--module", "-m", multiple=True, help="Specific module to run")
@click.option("--target", "-t", help="Target for the module")
@click.option("--output", "-o", default="./reports", help="Output directory")
@click.option("--format", "-f", "fmt", multiple=True, default=["json", "markdown"], help="Output format(s)")
@click.option("--min-severity", default="low", help="Minimum severity to report")
def scan(config, module, target, output, fmt, min_severity):
    """Run security scans."""
    if config:
        cfg = Config.from_yaml(config)
    else:
        modules = list(module) or ["mcp_security", "llm_runtime"]
        cfg = PipelineConfig(
            name="scan",
            modules=modules,
            output_formats=list(fmt),
            output_dir=output,
            min_severity=min_severity,
        )

    pipeline = Pipeline(cfg)
    _register_modules(pipeline)

    targets = {}
    for mod in cfg.modules:
        targets[mod] = target or mod

    results = pipeline.run(targets)
    paths = pipeline.report()
    click.echo(f"Scanned {len(results)} module(s). Reports: {paths}")


@cli.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Pipeline configuration file")
@click.option("--module", "-m", multiple=True, help="Specific module to run")
@click.option("--target", "-t", help="Target for the module")
@click.option("--output", "-o", default="./reports", help="Output directory")
@click.option("--format", "-f", "fmt", multiple=True, default=["json", "markdown"], help="Output format(s)")
def audit(config, module, target, output, fmt):
    """Run security audits."""
    if config:
        cfg = Config.from_yaml(config)
    else:
        modules = list(module) or ["jailbreak"]
        cfg = PipelineConfig(
            name="audit",
            modules=modules,
            output_formats=list(fmt),
            output_dir=output,
        )

    pipeline = Pipeline(cfg)
    _register_modules(pipeline)

    targets = {}
    for mod in cfg.modules:
        targets[mod] = target or mod

    results = pipeline.run(targets)
    paths = pipeline.report()
    click.echo(f"Audited {len(results)} module(s). Reports: {paths}")


@cli.command()
@click.option("--input", "-i", "input_file", required=True, help="Input results file")
@click.option("--format", "-f", "fmt", default="markdown", help="Output format")
@click.option("--output", "-o", required=True, help="Output file path")
def report(input_file, fmt, output):
    """Generate report from results."""
    import json
    from .core.reporter import Reporter

    with open(input_file, "r") as f:
        data = json.load(f)

    reporter = Reporter(output_dir=str(Path(output).parent))
    from .core.scanner import ScanResult, Finding, Severity
    from .core.auditor import AuditResult

    results = []
    for item in data:
        if "scanner_name" in item:
            result = ScanResult(
                scanner_name=item["scanner_name"],
                target=item["target"],
                findings=[
                    Finding(
                        rule_id=f["rule_id"],
                        title=f["title"],
                        description=f["description"],
                        severity=Severity(f["severity"]),
                        category=f["category"],
                        location=f.get("location"),
                        remediation=f.get("remediation"),
                        references=f.get("references", []),
                        metadata=f.get("metadata", {}),
                    )
                    for f in item.get("findings", [])
                ],
                errors=item.get("errors", []),
            )
            results.append(result)

    reporter.report(results, fmt=OutputFormat(fmt), filename=Path(output).name)
    click.echo(f"Report written to {output}")


def _register_modules(pipeline):
    """Register all available modules."""
    try:
        from .modules.mcp_security.scanner import MCPSecurityScanner
        pipeline.register_scanner("mcp_security", MCPSecurityScanner)
    except ImportError as e:
        logger.warning("MCP security scanner not available: %s", e)

    try:
        from .modules.llm_runtime.scanner import LLMRuntimeScanner
        pipeline.register_scanner("llm_runtime", LLMRuntimeScanner)
    except ImportError as e:
        logger.warning("LLM runtime scanner not available: %s", e)

    try:
        from .modules.jailbreak.auditor import JailbreakAuditor
        pipeline.register_auditor("jailbreak", JailbreakAuditor)
    except ImportError as e:
        logger.warning("Jailbreak auditor not available: %s", e)


if __name__ == "__main__":
    cli()
