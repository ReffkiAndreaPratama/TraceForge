"""ELF adapter, backed by :mod:`elftools`.

``pyelftools`` is an optional dependency: when it is not installed the adapter
reports a diagnostic instead of failing the whole analysis.
"""

from __future__ import annotations

from pathlib import Path

from traceforge.adapters.binary.strings import shannon_entropy
from traceforge.domain.enums import BinaryFormat, DiagnosticLevel
from traceforge.domain.models import BinaryInfo, BinarySection, Diagnostic

try:  # pragma: no cover - import guard
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    ELFTOOLS_AVAILABLE = True
    try:
        from importlib.metadata import version as _pkg_version

        ELFTOOLS_VERSION = _pkg_version("pyelftools")
    except Exception:  # noqa: BLE001 - metadata may be unavailable
        ELFTOOLS_VERSION = "unknown"
except ImportError:  # pragma: no cover - optional dependency
    ELFTOOLS_AVAILABLE = False
    ELFTOOLS_VERSION = None

MAX_SYMBOLS = 5000

#: ELF section type flags (SHT_*).
SECTION_TYPES: dict[int, str] = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    10: "SHLIB",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    16: "PREINIT_ARRAY",
    17: "GROUP",
    18: "SYMTAB_SHNDX",
}

#: ELF section flag bits (SHF_*).
SECTION_FLAGS: dict[int, str] = {
    0x1: "WRITE",
    0x2: "ALLOC",
    0x4: "EXECINSTR",
    0x10: "MERGE",
    0x20: "STRINGS",
    0x40: "INFO_LINK",
    0x80: "LINK_ORDER",
    0x200: "GROUP",
    0x400: "TLS",
}


def _section_flags(section_type: int, flags: int) -> str:
    """Render an ELF section type and flag bitmask as a readable string."""
    parts = [SECTION_TYPES.get(section_type, f"0x{section_type:x}")]
    for bit, name in sorted(SECTION_FLAGS.items()):
        if flags & bit:
            parts.append(name)
    return "|".join(parts)


#: ELF machine types (EM_*) mapped to a readable architecture name.
MACHINES: dict[str, str] = {
    "EM_NONE": "unknown",
    "EM_386": "x86",
    "EM_MIPS": "mips",
    "EM_ARM": "arm",
    "EM_X86_64": "x86-64",
    "EM_AARCH64": "arm64",
    "EM_RISCV": "riscv",
    "EM_PPC64": "ppc64",
    "EM_S390": "s390",
    "EM_LOONGARCH": "loongarch",
}


def _section_type_value(raw: object) -> int | None:
    """Normalise ``sh_type`` into an integer.

    ``pyelftools`` returns the symbolic name (``"SHT_PROGBITS"``) for known
    section types and the raw integer for unknown ones, depending on the
    container.  Both are accepted.
    """
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        name = raw.upper()
        for value, label in SECTION_TYPES.items():
            if name in {label, f"SHT_{label}"}:
                return value
        try:
            return int(raw, 0)
        except ValueError:
            return None
    return None


class ELFAdapter:
    """Extract structural information from ELF files."""

    name = "pyelftools"
    version = ELFTOOLS_VERSION

    def supports(self, head: bytes) -> bool:
        return head.startswith(b"\x7fELF")

    def parse(self, path: Path, *, head: bytes) -> BinaryInfo:
        if not ELFTOOLS_AVAILABLE:
            raise RuntimeError("pyelftools is not installed")
        diagnostics: list[Diagnostic] = []

        with path.open("rb") as handle:
            try:
                elf = ELFFile(handle)
            except Exception as exc:  # noqa: BLE001 - elftools raises bare Exception
                raise ValueError(f"Not a valid ELF file: {exc}") from exc

            header = elf.header
            raw_machine = str(header.get("e_machine", "unknown"))
            architecture = MACHINES.get(raw_machine, raw_machine)
            elf_type = str(header.get("e_type", "unknown"))
            endianness = "little" if elf.little_endian else "big"

            sections: list[BinarySection] = []
            for section in elf.iter_sections():
                name = section.name or "<unnamed>"
                entropy_value: float | None = None
                try:
                    data = section.data()
                    if data:
                        entropy_value = round(shannon_entropy(data), 4)
                except Exception:  # noqa: BLE001 - section data may be truncated
                    entropy_value = None
                section_type = _section_type_value(section["sh_type"])
                section_flags = int(section["sh_flags"])
                sections.append(
                    BinarySection(
                        name=name,
                        virtual_address=section["sh_addr"],
                        virtual_size=section["sh_size"],
                        raw_size=section["sh_size"],
                        entropy=entropy_value,
                        characteristics=section_type,
                        flags=(
                            _section_flags(section_type, section_flags)
                            if section_type is not None
                            else None
                        ),
                    )
                )

            libraries: list[str] = []
            for section in elf.iter_sections():
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if getattr(tag, "entry", None) is not None and tag.entry.d_tag == "DT_NEEDED":
                            libraries.append(str(tag.needed))
                    break

            symbols: list[str] = []
            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        name = symbol.name
                        if name:
                            symbols.append(name)
                        if len(symbols) >= MAX_SYMBOLS:
                            break
                if len(symbols) >= MAX_SYMBOLS:
                    break

            imports: list[str] = []
            dynamic_symbols = elf.get_section_by_name(".dynsym")
            if dynamic_symbols is not None:
                for symbol in dynamic_symbols.iter_symbols():
                    if symbol.name and symbol["st_shndx"] == "SHN_UNDEF":
                        imports.append(symbol.name)

            is_stripped = elf.get_section_by_name(".symtab") is None
            entry = header.get("e_entry")
            entry_point = f"0x{entry:x}" if isinstance(entry, int) else None

            if elf_type == "ET_REL":
                executable: bool | None = None
            else:
                executable = True

        return BinaryInfo(
            format=BinaryFormat.ELF,
            sha256="",
            size_bytes=0,
            architecture=architecture,
            endianness=endianness,
            is_executable=executable,
            is_stripped=is_stripped,
            subsystem="elf",
            compiler=None,
            entry_point=entry_point,
            sections=tuple(sections),
            imports=tuple(imports),
            exports=tuple(),
            symbols=tuple(symbols),
            libraries=tuple(libraries),
            diagnostics=tuple(diagnostics),
            parser=self.name,
            parser_version=self.version,
        )
