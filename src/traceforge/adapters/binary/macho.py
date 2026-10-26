"""Mach-O adapter.

The Mach-O header is parsed directly so that the adapter keeps working even
when LIEF is unavailable or its API changes between releases.  When LIEF *is*
available it is used to enrich the result with imported and exported symbols.
"""

from __future__ import annotations

import struct
from pathlib import Path

from traceforge.adapters.binary.strings import shannon_entropy
from traceforge.domain.enums import BinaryFormat, DiagnosticLevel
from traceforge.domain.models import BinaryInfo, BinarySection, Diagnostic

try:  # pragma: no cover - import guard
    import lief

    LIEF_AVAILABLE = True
    LIEF_VERSION = getattr(lief, "__version__", "unknown")
except ImportError:  # pragma: no cover - optional dependency
    lief = None  # type: ignore[assignment]
    LIEF_AVAILABLE = False
    LIEF_VERSION = None

#: Mach-O magic numbers.
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

#: Mach-O section attribute flags (S_ATTR_*).
SECTION_ATTRIBUTES: dict[int, str] = {
    0x80000000: "PURE_INSTRUCTIONS",
    0x40000000: "NO_TOC",
    0x20000000: "STRIP_STATIC_SYMS",
    0x10000000: "NO_DEAD_STRIP",
    0x08000000: "LIVE_SUPPORT",
    0x02000000: "SELF_MODIFYING_CODE",
    0x00004000: "SOME_INSTRUCTIONS",
    0x00002000: "EXT_RELOC",
    0x00001000: "LOC_RELOC",
}


def decode_section_attributes(value: int | None) -> str | None:
    """Render a Mach-O section attribute bitmask as a readable string."""
    if value is None:
        return None
    names = [name for bit, name in SECTION_ATTRIBUTES.items() if value & bit]
    if not names:
        return None
    return "|".join(sorted(names))

CPU_TYPES: dict[int, str] = {
    7: "x86",
    7 | 0x0100_0000: "x86-64",
    12: "arm",
    12 | 0x0100_0000: "arm64",
    0x0100_0007: "x86-64",
    0x0100_000C: "arm64",
}

FILE_TYPES: dict[int, str] = {
    1: "object",
    2: "executable",
    3: "fixed_vm_lib",
    4: "core",
    5: "preload",
    6: "dylib",
    7: "dylinker",
    8: "bundle",
    9: "dylib_stub",
    10: "dsym",
    11: "kext_bundle",
    12: "file_set",
}

MAX_SYMBOLS = 5000


class MachOAdapter:
    """Extract structural information from Mach-O files."""

    name = "traceforge.macho"
    version = "1.0.0"

    def supports(self, head: bytes) -> bool:
        if len(head) < 4:
            return False
        magic = struct.unpack(">I", head[:4])[0]
        return magic in {MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64, FAT_MAGIC, FAT_CIGAM}

    def parse(self, path: Path, *, head: bytes) -> BinaryInfo:
        diagnostics: list[Diagnostic] = []
        if len(head) < 28:
            raise ValueError("File is too small to contain a Mach-O header")

        magic_be = struct.unpack(">I", head[:4])[0]
        if magic_be in {FAT_MAGIC, FAT_CIGAM}:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.WARNING,
                    code="macho.fat",
                    message="Universal (fat) binary: only the first architecture is described",
                )
            )
            # Parse the first architecture slice of the fat header.
            nfat = struct.unpack(">I", head[4:8])[0]
            if nfat == 0 or len(head) < 8 + 20:
                raise ValueError("Universal binary header is truncated")
            offset = struct.unpack(">I", head[8:12])[0]
            with path.open("rb") as handle:
                handle.seek(offset)
                slice_head = handle.read(4096)
            return self._parse_thin(slice_head, path, diagnostics)

        return self._parse_thin(head, path, diagnostics)

    # ------------------------------------------------------------------
    def _parse_thin(
        self, head: bytes, path: Path, diagnostics: list[Diagnostic]
    ) -> BinaryInfo:
        if len(head) < 28:
            raise ValueError("Mach-O header is truncated")

        magic = struct.unpack("<I", head[:4])[0]
        if magic in {MH_MAGIC, MH_MAGIC_64}:
            endianness = "little"
        elif magic in {MH_CIGAM, MH_CIGAM_64}:
            endianness = "big"
        else:
            raise ValueError("Not a Mach-O binary")

        is_64 = magic in {MH_MAGIC_64, MH_CIGAM_64}
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
            "IIiIII", head[4:28]
        )

        architecture = CPU_TYPES.get(cputype & 0x00FF_FFFF, f"unknown({cputype})")
        file_type = FILE_TYPES.get(filetype, f"unknown({filetype})")

        sections: list[BinarySection] = []
        libraries: list[str] = []
        imports: list[str] = []
        exports: list[str] = []

        try:
            sections, libraries, imports, exports = self._parse_load_commands(
                path, endianness, is_64, ncmds
            )
        except Exception as exc:  # noqa: BLE001 - malformed load commands
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.WARNING,
                    code="macho.load_commands",
                    message=f"Could not fully parse Mach-O load commands: {exc}",
                )
            )

        if LIEF_AVAILABLE:
            self._enrich_with_lief(path, libraries, imports, exports, diagnostics)

        is_stripped = not any(s.name in {"__symbol_table", "__symtab"} for s in sections)

        return BinaryInfo(
            format=BinaryFormat.MACHO,
            sha256="",
            size_bytes=0,
            architecture=architecture,
            endianness=endianness,
            is_executable=filetype in {2, 6, 8},
            is_stripped=is_stripped,
            subsystem=file_type,
            compiler=None,
            entry_point=None,
            sections=tuple(sections),
            imports=tuple(imports),
            exports=tuple(exports),
            libraries=tuple(libraries),
            diagnostics=tuple(diagnostics),
            parser=self.name,
            parser_version=self.version,
        )

    # ------------------------------------------------------------------
    def _parse_load_commands(
        self, path: Path, endianness: str, is_64: bool, ncmds: int
    ) -> tuple[list[BinarySection], list[str], list[str], list[str]]:
        prefix = "<" if endianness == "little" else ">"
        sections: list[BinarySection] = []
        libraries: list[str] = []
        imports: list[str] = []
        exports: list[str] = []

        with path.open("rb") as handle:
            handle.seek(32 if is_64 else 28)
            for _ in range(ncmds):
                header = handle.read(8)
                if len(header) < 8:
                    break
                cmd, cmdsize = struct.unpack(prefix + "II", header)
                if cmdsize < 8:
                    break
                body = handle.read(cmdsize - 8)

                if cmd == 0x19:  # LC_SEGMENT_64
                    segname = body[:16].split(b"\x00")[0].decode("utf-8", errors="replace")
                    vmaddr, vmsize, fileoff, filesize = struct.unpack(
                        prefix + "4Q", body[16:48]
                    )
                    nsects = struct.unpack(prefix + "I", body[48:52])[0]
                    offset = 52
                    for _sect in range(nsects):
                        sect = body[offset : offset + 80]
                        if len(sect) < 80:
                            break
                        offset += 80
                        sectname = sect[:16].split(b"\x00")[0].decode("utf-8", errors="replace")
                        seg = sect[16:32].split(b"\x00")[0].decode("utf-8", errors="replace")
                        addr, size = struct.unpack(prefix + "2Q", sect[32:48])
                        attributes = struct.unpack(prefix + "I", sect[64:68])[0]
                        sections.append(
                            BinarySection(
                                name=f"{seg}.{sectname}" if seg else sectname,
                                virtual_address=addr,
                                virtual_size=size,
                                raw_size=size,
                                entropy=None,
                                characteristics=attributes,
                                flags=decode_section_attributes(attributes),
                            )
                        )
                    del vmaddr, vmsize, fileoff, filesize
                elif cmd == 0x01:  # LC_SEGMENT (32 bit)
                    segname = body[:16].split(b"\x00")[0].decode("utf-8", errors="replace")
                    nsects = struct.unpack(prefix + "I", body[48:52])[0]
                    offset = 52
                    for _sect in range(nsects):
                        sect = body[offset : offset + 68]
                        if len(sect) < 68:
                            break
                        offset += 68
                        sectname = sect[:16].split(b"\x00")[0].decode("utf-8", errors="replace")
                        seg = sect[16:32].split(b"\x00")[0].decode("utf-8", errors="replace")
                        addr, size = struct.unpack(prefix + "2I", sect[32:40])
                        attributes = struct.unpack(prefix + "I", sect[48:52])[0]
                        sections.append(
                            BinarySection(
                                name=f"{seg}.{sectname}" if seg else sectname,
                                virtual_address=addr,
                                virtual_size=size,
                                raw_size=size,
                                entropy=None,
                                characteristics=attributes,
                                flags=decode_section_attributes(attributes),
                            )
                        )
                elif cmd == 0x0C:  # LC_LOAD_DYLIB
                    name_offset = struct.unpack(prefix + "I", body[4:8])[0]
                    name = body[name_offset:].split(b"\x00")[0].decode("utf-8", errors="replace")
                    libraries.append(name)
                elif cmd == 0x80000018:  # LC_LOAD_DYLIB (64 bit)
                    name_offset = struct.unpack(prefix + "I", body[4:8])[0]
                    name = body[name_offset:].split(b"\x00")[0].decode("utf-8", errors="replace")
                    libraries.append(name)
                elif cmd == 0x0D:  # LC_ID_DYLIB
                    name_offset = struct.unpack(prefix + "I", body[4:8])[0]
                    name = body[name_offset:].split(b"\x00")[0].decode("utf-8", errors="replace")
                    libraries.append(name)

        return sections, libraries, imports, exports

    def _enrich_with_lief(
        self,
        path: Path,
        libraries: list[str],
        imports: list[str],
        exports: list[str],
        diagnostics: list[Diagnostic],
    ) -> None:
        try:
            parsed = lief.MachO.parse(str(path))
        except Exception as exc:  # noqa: BLE001 - lief raises bare exceptions
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.INFO,
                    code="macho.lief",
                    message=f"LIEF could not parse this Mach-O file: {exc}",
                )
            )
            return
        if parsed is None:
            return
        binary = parsed
        if hasattr(parsed, "at"):
            try:
                binary = parsed.at(0)
            except Exception:  # noqa: BLE001
                binary = parsed
        try:
            for lib in getattr(binary, "libraries", []) or []:
                name = getattr(lib, "name", None)
                if name and name not in libraries:
                    libraries.append(name)
            for symbol in getattr(binary, "imported_symbols", []) or []:
                name = getattr(symbol, "name", None)
                if name:
                    imports.append(name)
                    if len(imports) >= MAX_SYMBOLS:
                        break
            for symbol in getattr(binary, "exported_symbols", []) or []:
                name = getattr(symbol, "name", None)
                if name:
                    exports.append(name)
                    if len(exports) >= MAX_SYMBOLS:
                        break
        except Exception as exc:  # noqa: BLE001
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.INFO,
                    code="macho.lief",
                    message=f"LIEF symbol extraction failed: {exc}",
                )
            )


def section_entropy(data: bytes) -> float:
    """Convenience wrapper kept for symmetry with the other adapters."""
    return round(shannon_entropy(data), 4)
