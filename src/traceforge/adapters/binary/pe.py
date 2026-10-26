"""PE (Portable Executable) adapter, backed by :mod:`pefile`.

``pefile`` is an optional dependency: when it is not installed the adapter
reports a diagnostic instead of failing the whole analysis.
"""

from __future__ import annotations

from pathlib import Path

from traceforge.adapters.binary.strings import shannon_entropy
from traceforge.domain.enums import BinaryFormat, DiagnosticLevel
from traceforge.domain.models import BinaryInfo, BinarySection, Diagnostic

try:  # pragma: no cover - import guard
    import pefile

    PEFILE_AVAILABLE = True
    PEFILE_VERSION = getattr(pefile, "__version__", "unknown")
except ImportError:  # pragma: no cover - optional dependency
    pefile = None  # type: ignore[assignment]
    PEFILE_AVAILABLE = False
    PEFILE_VERSION = None

#: Machine type -> human readable architecture.
MACHINES: dict[int, str] = {
    0x014C: "x86",
    0x0166: "mips",
    0x01C0: "arm",
    0x01C4: "armv7",
    0x0200: "ia64",
    0x8664: "x86-64",
    0xAA64: "arm64",
    0x5032: "riscv32",
    0x5064: "riscv64",
}

SUBSYSTEMS: dict[int, str] = {
    1: "native",
    2: "windows_gui",
    3: "windows_console",
    5: "os2_console",
    7: "posix_console",
    9: "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
    14: "xbox",
}

MAX_IMPORTED_SYMBOLS = 5000

#: PE section characteristic flags (IMAGE_SCN_*).
SECTION_CHARACTERISTICS: dict[int, str] = {
    0x00000020: "CNT_CODE",
    0x00000040: "CNT_INITIALIZED_DATA",
    0x00000080: "CNT_UNINITIALIZED_DATA",
    0x00000200: "LNK_INFO",
    0x00000800: "LNK_REMOVE",
    0x00001000: "LNK_COMDAT",
    0x00004000: "NO_DEFER_SPEC_EXC",
    0x00008000: "GPREL",
    0x01000000: "LNK_NRELOC_OVFL",
    0x02000000: "MEM_DISCARDABLE",
    0x04000000: "MEM_NOT_CACHED",
    0x08000000: "MEM_NOT_PAGED",
    0x10000000: "MEM_SHARED",
    0x20000000: "MEM_EXECUTE",
    0x40000000: "MEM_READ",
    0x80000000: "MEM_WRITE",
}


def decode_section_characteristics(value: int | None) -> str | None:
    """Render a PE section flag bitmask as a readable string."""
    if value is None:
        return None
    names = [name for bit, name in SECTION_CHARACTERISTICS.items() if value & bit]
    if not names:
        return None
    return "|".join(sorted(names))


class PEAdapter:
    """Extract structural information from PE files."""

    name = "pefile"
    version = PEFILE_VERSION

    def supports(self, head: bytes) -> bool:
        return head.startswith(b"MZ")

    def parse(self, path: Path, *, head: bytes) -> BinaryInfo:
        if not PEFILE_AVAILABLE:
            raise RuntimeError("pefile is not installed")
        diagnostics: list[Diagnostic] = []

        try:
            pe = pefile.PE(str(path), fast_load=False)
        except pefile.PEFormatError as exc:
            raise ValueError(f"Not a valid PE file: {exc}") from exc

        try:
            return self._build_info(pe, diagnostics)
        finally:
            pe.close()

    # ------------------------------------------------------------------
    def _build_info(self, pe, diagnostics: list[Diagnostic]) -> BinaryInfo:
        file_header = pe.FILE_HEADER
        optional = getattr(pe, "OPTIONAL_HEADER", None)

        machine = file_header.Machine
        architecture = MACHINES.get(machine, f"unknown(0x{machine:04x})")

        magic = getattr(optional, "Magic", None)
        if magic == 0x10B:
            pe_kind = "pe32"
        elif magic == 0x20B:
            pe_kind = "pe32+"
        else:
            pe_kind = "unknown"

        subsystem = None
        if optional is not None:
            subsystem = SUBSYSTEMS.get(getattr(optional, "Subsystem", -1))

        entry_point = None
        if optional is not None and getattr(optional, "AddressOfEntryPoint", None) is not None:
            entry_point = f"0x{optional.AddressOfEntryPoint:08x}"

        sections: list[BinarySection] = []
        for section in getattr(pe, "sections", []) or []:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            raw_size = section.SizeOfRawData
            entropy_value: float | None = None
            try:
                data = section.get_data()
                if data:
                    entropy_value = round(shannon_entropy(data), 4)
            except Exception:  # noqa: BLE001 - section data may be truncated
                entropy_value = None
            characteristics = int(section.Characteristics)
            sections.append(
                BinarySection(
                    name=name or "<unnamed>",
                    virtual_address=section.VirtualAddress,
                    virtual_size=section.Misc_VirtualSize,
                    raw_size=raw_size,
                    entropy=entropy_value,
                    characteristics=characteristics,
                    flags=decode_section_characteristics(characteristics),
                )
            )

        imports: list[str] = []
        libraries: list[str] = []
        import_detail: list[str] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = (entry.dll or b"").decode("utf-8", errors="replace")
            libraries.append(dll)
            for symbol in entry.imports or []:
                if symbol.name:
                    name = symbol.name.decode("utf-8", errors="replace")
                    import_detail.append(f"{dll}!{name}")
                elif symbol.ordinal is not None:
                    import_detail.append(f"{dll}!ordinal_{symbol.ordinal}")
                if len(import_detail) >= MAX_IMPORTED_SYMBOLS:
                    break
            if len(import_detail) >= MAX_IMPORTED_SYMBOLS:
                break

        exports: list[str] = []
        for symbol in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
            if symbol.name:
                exports.append(symbol.name.decode("utf-8", errors="replace"))
            if len(exports) >= MAX_IMPORTED_SYMBOLS:
                break

        is_stripped: bool | None = None
        if sections:
            is_stripped = not any(s.name.lower() in {".symtab", ".debug"} for s in sections)

        compiler = self._detect_compiler(pe)

        for warning in pe.get_warnings() or []:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.WARNING,
                    code="pe.warning",
                    message=str(warning),
                    source="pefile",
                )
            )

        return BinaryInfo(
            format=BinaryFormat.PE,
            sha256="",  # filled in by the caller
            size_bytes=0,
            architecture=architecture,
            endianness="little",
            is_executable=True,
            is_stripped=is_stripped,
            subsystem=subsystem,
            compiler=compiler,
            entry_point=entry_point,
            sections=tuple(sections),
            imports=tuple(import_detail),
            exports=tuple(exports),
            libraries=tuple(libraries),
            diagnostics=tuple(diagnostics),
            parser=self.name,
            parser_version=self.version,
        )

    def _detect_compiler(self, pe) -> str | None:
        """Best-effort compiler / linker detection from the rich header."""
        try:
            pe.parse_rich_header()
        except Exception:  # noqa: BLE001 - the rich header is optional
            return None
        header = getattr(pe, "RICH_HEADER", None)
        if not header:
            return None
        values = header.values if isinstance(header.values, list) else []
        if not values:
            return None
        # The rich header records (compid, count) pairs.  The high 16 bits of
        # compid are the product id, the low 16 bits the build number.
        comp_ids = {value >> 16 for value in values if isinstance(value, int)}
        known = {
            0x00: "import0",
            0x01: "import0",
            0x02: "linker510",
            0x04: "cvtomf510",
            0x06: "linker600",
            0x07: "cvtomf600",
            0x0A: "linker620",
            0x0B: "cvtomf620",
            0x0C: "linker700",
            0x0D: "cvtomf700",
            0x0E: "linker710",
            0x0F: "cvtomf710",
            0x93: "utc1500_C",
            0x95: "utc1500_CPP",
            0xFF: "linker800",
            0x100: "cvtres800",
            0x101: "export800",
            0x102: "linker900",
            0x103: "cvtres900",
            0x104: "export900",
            0x105: "utc1600_C",
            0x106: "utc1600_CPP",
            0x107: "linker1000",
            0x108: "cvtres1000",
            0x109: "export1000",
            0x10A: "utc1700_C",
            0x10B: "utc1700_CPP",
        }
        for comp_id in sorted(comp_ids):
            if comp_id in known:
                return known[comp_id]
        return None
