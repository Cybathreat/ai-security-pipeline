"""Configuration management."""

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class Config:
    pipeline_name: str = "default"
    modules: List[str] = field(default_factory=list)
    output_formats: List[str] = field(default_factory=lambda: ["json", "markdown"])
    output_dir: str = "./reports"
    min_severity: str = "low"
    settings: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str) -> "Config":
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        pipeline = data.get("pipeline", {})
        output = data.get("output", {})
        return cls(
            pipeline_name=pipeline.get("name", "default"),
            modules=pipeline.get("modules", []),
            output_formats=output.get("formats", ["json", "markdown"]),
            output_dir=output.get("directory", "./reports"),
            min_severity=output.get("min_severity", "low"),
            settings=data.get("settings", {}),
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        pipeline = data.get("pipeline", {})
        output = data.get("output", {})
        return cls(
            pipeline_name=pipeline.get("name", "default"),
            modules=pipeline.get("modules", []),
            output_formats=output.get("formats", ["json", "markdown"]),
            output_dir=output.get("directory", "./reports"),
            min_severity=output.get("min_severity", "low"),
            settings=data.get("settings", {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipeline": {
                "name": self.pipeline_name,
                "modules": self.modules,
            },
            "output": {
                "formats": self.output_formats,
                "directory": self.output_dir,
                "min_severity": self.min_severity,
            },
            "settings": self.settings,
        }
