"""Tests for utilities."""

import os

from ai_security_pipeline.utils.helpers import sha256_file, severity_to_int, truncate_string, ensure_dir


class TestHelpers:
    def test_sha256_file(self, tmp_path):
        path = tmp_path / "test.txt"
        path.write_text("hello")
        h = sha256_file(str(path))
        assert len(h) == 64
        assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_severity_to_int(self):
        assert severity_to_int("critical") == 4
        assert severity_to_int("low") == 1
        assert severity_to_int("unknown") == 0

    def test_truncate_string(self):
        assert truncate_string("hello", 10) == "hello"
        assert len(truncate_string("hello world", 5)) == 8  # 5 + "..."

    def test_ensure_dir(self, tmp_path):
        path = tmp_path / "nested" / "dir"
        ensure_dir(str(path))
        assert os.path.isdir(path)
