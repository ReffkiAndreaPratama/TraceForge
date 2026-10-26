"""Unit tests for path safety helpers."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from traceforge.errors import ValidationError
from traceforge.security.paths import (
    is_within,
    resolve_existing_file,
    safe_join,
    sanitize_display_name,
)


class TestSanitizeDisplayName:
    def test_plain_name_is_kept(self) -> None:
        assert sanitize_display_name("hello-world.exe") == "hello-world.exe"

    def test_directory_components_are_removed(self) -> None:
        assert sanitize_display_name("../../etc/passwd") == "passwd"
        assert sanitize_display_name(r"C:\Windows\System32\cmd.exe") == "cmd.exe"

    def test_separators_are_replaced(self) -> None:
        name = sanitize_display_name("weird/name:here.txt")
        assert "/" not in name
        assert ":" not in name

    def test_control_characters_are_removed(self) -> None:
        name = sanitize_display_name("bad\x00name\x1b.txt")
        assert "\x00" not in name
        assert "\x1b" not in name

    def test_windows_reserved_names_are_escaped(self) -> None:
        assert sanitize_display_name("CON") == "_CON"
        assert sanitize_display_name("nul.txt") == "_nul.txt"

    def test_empty_name_falls_back(self) -> None:
        assert sanitize_display_name("") == "unnamed"
        assert sanitize_display_name("...") == "unnamed"

    def test_long_name_is_truncated(self) -> None:
        name = sanitize_display_name("a" * 500 + ".exe")
        assert len(name) <= 120


class TestSafeJoin:
    def test_join_under_root(self, tmp_path: Path) -> None:
        assert safe_join(tmp_path, "artifacts", "binary") == tmp_path / "artifacts" / "binary"

    def test_traversal_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError):
            safe_join(tmp_path, "..", "outside")

    def test_nested_traversal_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError):
            safe_join(tmp_path, "a", "b", "..", "..", "..", "escape")

    def test_absolute_path_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError):
            safe_join(tmp_path, os.path.abspath(os.sep + "etc"))

    def test_windows_drive_path_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError):
            safe_join(tmp_path, "C:\\Windows")

    def test_empty_component_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError):
            safe_join(tmp_path, "")


class TestIsWithin:
    def test_child_is_within(self, tmp_path: Path) -> None:
        assert is_within(tmp_path, tmp_path / "a" / "b") is True

    def test_sibling_is_outside(self, tmp_path: Path) -> None:
        assert is_within(tmp_path / "a", tmp_path / "b") is False

    def test_parent_is_outside(self, tmp_path: Path) -> None:
        assert is_within(tmp_path / "a" / "b", tmp_path / "a") is False


class TestResolveExistingFile:
    def test_regular_file_resolves(self, tmp_path: Path) -> None:
        target = tmp_path / "file.bin"
        target.write_bytes(b"x")
        assert resolve_existing_file(target) == target.resolve()

    def test_missing_file_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError):
            resolve_existing_file(tmp_path / "nope.bin")

    def test_directory_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError):
            resolve_existing_file(tmp_path)

    @pytest.mark.skipif(
        os.name == "nt", reason="creating symlinks requires privileges on Windows"
    )
    def test_symlink_is_rejected(self, tmp_path: Path) -> None:
        target = tmp_path / "real.bin"
        target.write_bytes(b"x")
        link = tmp_path / "link.bin"
        link.symlink_to(target)
        with pytest.raises(ValidationError):
            resolve_existing_file(link)
