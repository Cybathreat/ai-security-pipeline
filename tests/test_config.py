"""Tests for configuration management."""

import os

import pytest
import yaml

from ai_security_pipeline.config import Config


class TestConfig:
    def test_from_yaml(self, tmp_path):
        data = {
            "pipeline": {"name": "test", "modules": ["mcp"]},
            "output": {"formats": ["json"], "directory": "./out", "min_severity": "high"},
        }
        path = tmp_path / "config.yaml"
        with open(path, "w") as f:
            yaml.dump(data, f)

        cfg = Config.from_yaml(str(path))
        assert cfg.pipeline_name == "test"
        assert cfg.modules == ["mcp"]
        assert cfg.min_severity == "high"

    def test_from_dict(self):
        cfg = Config.from_dict({
            "pipeline": {"name": "d", "modules": ["a", "b"]},
            "output": {"formats": ["markdown"]},
        })
        assert cfg.pipeline_name == "d"
        assert cfg.output_formats == ["markdown"]

    def test_to_dict(self):
        cfg = Config(pipeline_name="p", modules=["m"])
        d = cfg.to_dict()
        assert d["pipeline"]["name"] == "p"
        assert d["pipeline"]["modules"] == ["m"]
