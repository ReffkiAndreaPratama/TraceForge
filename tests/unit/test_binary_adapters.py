"""Unit tests for the binary format adapters."""

from __future__ import annotations

from pathlib import Path

import pytest

from traceforge.adapters.binary.elf import ELFAdapter
from traceforge.adapters.binary.fingerprint import fingerprint, select_adapter
from traceforge.adapters.binary.macho import MachOAdapter
from traceforge.adapters.binary.pe import PEAdapter
from traceforge.domain.enums import BinaryFormat, DiagnosticLevel
from traceforge.config import Limits


class TestAdapterSelection:
    def test_pe_is_recognised(self, pe_bytes: bytes) -> None:
        adapter = select_adapter(pe_bytes[:64])
        assert isinstance(adapter, PEAdapter)

    def test_elf_is_recognised(self, elf_bytes: bytes) -> None:
        adapter = select_adapter(elf_bytes[:64])
        assert isinstance(adapter, ELFAdapter)

    def test_unknown_data_is_not_selected(self) -> None:
        assert select_adapter(b"not a binary at all") is None

    def test_empty_input_is_not_selected(self) -> None:
        assert select_adapter(b"") is None


class TestPEAdapter:
    def test_structure_is_extracted(self, pe_file: Path) -> None:
        info = PEAdapter().parse(pe_file, head=pe_file.read_bytes()[:64])
        assert info.format == BinaryFormat.PE
        assert info.architecture == "x86"
        assert info.endianness == "little"
        assert info.is_executable is True
        assert info.subsystem == "windows_console"
        assert info.entry_point == "0x00001000"

    def test_sections_are_extracted(self, pe_file: Path) -> None:
        info = PEAdapter().parse(pe_file, head=pe_file.read_bytes()[:64])
        names = [section.name for section in info.sections]
        assert ".text" in names
        assert ".rdata" in names

    def test_section_entropy_is_computed(self, pe_file: Path) -> None:
        info = PEAdapter().parse(pe_file, head=pe_file.read_bytes()[:64])
        text = next(section for section in info.sections if section.name == ".text")
        assert text.entropy is not None
        assert text.entropy > 0.0

    def test_section_flags_are_decoded(self, pe_file: Path) -> None:
        info = PEAdapter().parse(pe_file, head=pe_file.read_bytes()[:64])
        text = next(section for section in info.sections if section.name == ".text")
        assert text.flags is not None
        assert "CODE" in text.flags

    def test_imports_are_extracted(self, pe_file: Path) -> None:
        info = PEAdapter().parse(pe_file, head=pe_file.read_bytes()[:64])
        assert "kernel32.dll!GetLastError" in info.imports
        assert "kernel32.dll!GetCurrentProcess" in info.imports
        assert "kernel32.dll" in info.libraries

    def test_parser_is_recorded(self, pe_file: Path) -> None:
        info = PEAdapter().parse(pe_file, head=pe_file.read_bytes()[:64])
        assert info.parser == "pefile"
        assert info.parser_version


class TestELFAdapter:
    def test_structure_is_extracted(self, elf_file: Path) -> None:
        info = ELFAdapter().parse(elf_file, head=elf_file.read_bytes()[:64])
        assert info.format == BinaryFormat.ELF
        assert info.architecture == "x86-64"
        assert info.endianness == "little"

    def test_sections_are_extracted(self, elf_file: Path) -> None:
        info = ELFAdapter().parse(elf_file, head=elf_file.read_bytes()[:64])
        names = [section.name for section in info.sections]
        assert ".text" in names
        assert ".dynamic" in names

    def test_needed_library_is_extracted(self, elf_file: Path) -> None:
        info = ELFAdapter().parse(elf_file, head=elf_file.read_bytes()[:64])
        assert "libtraceforge.so.1" in info.libraries

    def test_section_type_is_an_integer(self, elf_file: Path) -> None:
        info = ELFAdapter().parse(elf_file, head=elf_file.read_bytes()[:64])
        dynamic = next(s for s in info.sections if s.name == ".dynamic")
        assert isinstance(dynamic.characteristics, int)
        assert "DYNAMIC" in (dynamic.flags or "")

    def test_invalid_file_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.elf"
        path.write_bytes(b"\x7fELF" + b"\x00" * 32)
        with pytest.raises(ValueError):
            ELFAdapter().parse(path, head=path.read_bytes()[:64])


class TestFingerprint:
    def test_pe_fingerprint(self, pe_file: Path) -> None:
        result = fingerprint(pe_file)
        assert result.info.format == BinaryFormat.PE
        assert len(result.info.sha256) == 64
        assert result.info.size_bytes == pe_file.stat().st_size

    def test_strings_are_extracted(self, pe_file: Path) -> None:
        result = fingerprint(pe_file)
        assert "Hello from TraceForge" in result.info.strings

    def test_urls_and_domains_are_extracted(self, pe_file: Path) -> None:
        result = fingerprint(pe_file)
        assert "https://api.example.test/v1/users" in result.info.urls
        assert "api.example.test" in result.info.domains

    def test_unknown_format_produces_an_error_diagnostic(self, tmp_path: Path) -> None:
        path = tmp_path / "random.bin"
        path.write_bytes(b"just some random bytes that are not a container")
        result = fingerprint(path)
        assert result.info.format == BinaryFormat.UNKNOWN
        assert any(d.level == DiagnosticLevel.ERROR for d in result.diagnostics)

    def test_string_scan_truncation_is_reported(self, pe_file: Path) -> None:
        limits = Limits(max_string_scan_bytes=64)
        result = fingerprint(pe_file, limits=limits)
        assert result.scan_truncated is True
        assert any(d.code == "binary.scan_truncated" for d in result.diagnostics)

    def test_fingerprint_is_deterministic(self, pe_file: Path) -> None:
        first = fingerprint(pe_file)
        second = fingerprint(pe_file)
        assert first.info.sha256 == second.info.sha256
        assert first.info.strings == second.info.strings


class TestMachOAdapter:
    def test_unknown_data_is_rejected(self) -> None:
        assert MachOAdapter().supports(b"not mach-o") is False

    def test_magic_is_recognised(self) -> None:
        assert MachOAdapter().supports(b"\xcf\xfa\xed\xfe" + b"\x00" * 8) is True
