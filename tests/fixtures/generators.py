"""Synthetic binary and HAR fixture generators.

TraceForge ships **synthetic** fixtures only.  No real-world binary, capture
or credential is committed to this repository.

The generators below build small but structurally valid PE and ELF files so
that the format adapters can be exercised without shipping third-party
binaries.  The output is byte-for-byte deterministic.
"""

from __future__ import annotations

import json
import struct
from typing import Any

# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------
DOS_HEADER_SIZE = 0x40
PE_OFFSET = 0x80
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000

#: Strings embedded in the synthetic binary.  The bearer token is fake and
#: deliberately shaped like a real one so that redaction is exercised.
SAMPLE_STRINGS: tuple[bytes, ...] = (
    b"Hello from TraceForge",
    b"https://api.example.test/v1/users",
    b"api.example.test",
    b"config/settings.json",
    b"Error: could not connect to the server",
    b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0cmFjZWZvcmdlIn0.c2lnbmF0dXJl",
    b"login.example.org",
)


def _pad(data: bytes, alignment: int) -> bytes:
    remainder = len(data) % alignment
    if remainder == 0:
        return data
    return data + b"\x00" * (alignment - remainder)


def build_pe(*, extra_strings: tuple[bytes, ...] = ()) -> bytes:
    """Build a minimal but structurally valid 32-bit PE file.

    The file contains a ``.text`` section with sample strings and a
    ``.rdata`` section with an import directory referencing ``kernel32.dll``.
    """
    text_payload = b"".join(
        s + b"\x00" for s in (*SAMPLE_STRINGS, *extra_strings)
    )
    # Pad the code section with a recognisable non-string pattern so that the
    # entropy of the section is not trivially zero.
    text_payload += bytes(range(256))
    text_raw = _pad(text_payload, FILE_ALIGNMENT)

    # The .rdata section starts after the headers and the .text section.
    rdata_file_offset = FILE_ALIGNMENT + len(text_raw)

    # --- .rdata: import directory -------------------------------------
    # Layout (all offsets are relative to the start of .rdata):
    #   0x00  IMAGE_IMPORT_DESCRIPTOR[0]
    #   0x14  IMAGE_IMPORT_DESCRIPTOR[1]  (null terminator)
    #   0x30  Import Lookup Table (ILT)
    #   0x40  DLL name
    #   0x50  IMAGE_IMPORT_BY_NAME[0]
    #   0x60  IMAGE_IMPORT_BY_NAME[1]
    #   0x80  Import Address Table (IAT)
    rdata = bytearray(FILE_ALIGNMENT)

    def _write(buffer: bytearray, offset: int, value: bytes) -> None:
        """Write ``value`` at ``offset`` without resizing the buffer."""
        end = offset + len(value)
        buffer[offset:end] = value.ljust(end - offset, b"\x00")

    def _rva(offset: int) -> int:
        return 0x2000 + offset

    idt_offset = 0x00
    ilt_offset = 0x30
    dll_name_offset = 0x40
    name1_offset = 0x50
    name2_offset = 0x60
    iat_offset = 0x80

    struct.pack_into("<H", rdata, name1_offset, 0)  # hint
    _write(rdata, name1_offset + 2, b"GetLastError\x00")
    struct.pack_into("<H", rdata, name2_offset, 0)  # hint
    _write(rdata, name2_offset + 2, b"GetCurrentProcess\x00")
    _write(rdata, dll_name_offset, b"kernel32.dll\x00")

    # Import Lookup Table: two thunks then a null terminator.
    struct.pack_into(
        "<III", rdata, ilt_offset, _rva(name1_offset), _rva(name2_offset), 0
    )
    # Import Address Table: the loader copies the ILT here.
    struct.pack_into(
        "<III", rdata, iat_offset, _rva(name1_offset), _rva(name2_offset), 0
    )

    # Import Directory Table: one descriptor plus the null terminator.
    descriptor = struct.pack(
        "<IIIII",
        _rva(ilt_offset),  # OriginalFirstThunk
        0,  # TimeDateStamp
        0,  # ForwarderChain
        _rva(dll_name_offset),  # Name
        _rva(iat_offset),  # FirstThunk
    )
    rdata[idt_offset : idt_offset + 20] = descriptor
    # rdata[0x14:0x28] stays zero -> the null terminator descriptor.
    assert len(rdata) == FILE_ALIGNMENT, len(rdata)

    # --- headers -------------------------------------------------------
    header = bytearray(PE_OFFSET)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, PE_OFFSET)
    stub = b"This is a stub\r\n"
    header[0x40 : 0x40 + len(stub)] = stub
    assert len(header) == PE_OFFSET, len(header)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine: i386
        2,  # NumberOfSections
        0,  # TimeDateStamp (fixed for determinism)
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0xE0,  # SizeOfOptionalHeader
        0x0102,  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    data_directory = bytearray(16 * 8)
    struct.pack_into("<II", data_directory, 1 * 8, 0x2000, 60)  # Import directory

    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,  # Magic: PE32
        0,  # MajorLinkerVersion
        0,  # MinorLinkerVersion
        len(text_raw),  # SizeOfCode
        FILE_ALIGNMENT,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        0x1000,  # AddressOfEntryPoint
        0x1000,  # BaseOfCode
        0x2000,  # BaseOfData
        0x00400000,  # ImageBase
        SECTION_ALIGNMENT,  # SectionAlignment
        FILE_ALIGNMENT,  # FileAlignment
        4, 0,  # Operating system version
        0, 0,  # Image version
        4, 0,  # Subsystem version
        0,  # Win32VersionValue
        0x3000,  # SizeOfImage
        FILE_ALIGNMENT,  # SizeOfHeaders
        0,  # CheckSum
        3,  # Subsystem: console
        0,  # DllCharacteristics
        0x100000,  # SizeOfStackReserve
        0x1000,  # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,  # SizeOfHeapCommit
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )
    assert len(optional) == 96, len(optional)
    optional += bytes(data_directory)

    section_text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x200,  # VirtualSize
        0x1000,  # VirtualAddress
        len(text_raw),  # SizeOfRawData
        FILE_ALIGNMENT,  # PointerToRawData
        0,
        0,
        0,
        0,
        0x60000020,  # Characteristics: code | execute | read
    )
    section_rdata = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",
        FILE_ALIGNMENT,  # VirtualSize
        0x2000,  # VirtualAddress
        FILE_ALIGNMENT,  # SizeOfRawData
        rdata_file_offset,  # PointerToRawData
        0,
        0,
        0,
        0,
        0x40000040,  # Characteristics: initialized data | read
    )

    image = bytes(header) + b"PE\x00\x00" + coff + optional + section_text + section_rdata
    image = _pad(image, FILE_ALIGNMENT)
    return image + text_raw + bytes(rdata)


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------
def build_elf(*, extra_strings: tuple[bytes, ...] = ()) -> bytes:
    """Build a minimal but structurally valid 64-bit little-endian ELF file."""
    payload = b"".join(s + b"\x00" for s in (*SAMPLE_STRINGS, *extra_strings))
    payload += bytes(range(256))

    ehsize = 64
    phentsize = 56
    shentsize = 64

    text_rva = 0x1000
    dynstr_rva = 0x2000
    dynamic_rva = 0x2100
    shstr_rva = 0x2200

    # --- .dynstr -------------------------------------------------------
    dynstr = bytearray(b"\x00")
    needed_offset = len(dynstr)
    dynstr += b"libtraceforge.so.1\x00"
    soname_offset = len(dynstr)
    dynstr += b"traceforge.bin\x00"

    # --- .dynamic ------------------------------------------------------
    dynamic = bytearray()
    dynamic += struct.pack("<QQ", 1, needed_offset)  # DT_NEEDED
    dynamic += struct.pack("<QQ", 14, soname_offset)  # DT_SONAME
    dynamic += struct.pack("<QQ", 0, 0)  # DT_NULL

    # --- .shstrtab -----------------------------------------------------
    shstr = bytearray(b"\x00")
    text_name = len(shstr)
    shstr += b".text\x00"
    dynstr_name = len(shstr)
    shstr += b".dynstr\x00"
    dynamic_name = len(shstr)
    shstr += b".dynamic\x00"
    shstrtab_name = len(shstr)
    shstr += b".shstrtab\x00"

    # File layout: header | phdrs | text | dynstr | dynamic | shstrtab | shdrs
    offset = ehsize + 2 * phentsize
    text_offset = offset
    offset += len(payload)
    dynstr_offset = offset
    offset += len(dynstr)
    dynamic_offset = offset
    offset += len(dynamic)
    shstr_offset = offset
    offset += len(shstr)
    sh_offset = offset

    shnum = 5  # null, .text, .dynstr, .dynamic, .shstrtab
    shstrndx = 4
    #: Section header index of ``.dynstr``.  ``.dynamic`` must link to it so
    #: that consumers can resolve ``DT_NEEDED`` / ``DT_SONAME`` string offsets.
    dynstr_shndx = 2

    # Program headers
    ph_load = struct.pack(
        "<IIQQQQQQ",
        1,  # PT_LOAD
        5,  # PF_R | PF_X
        0,  # offset
        0,  # vaddr
        0,  # paddr
        sh_offset,  # filesz
        sh_offset,  # memsz
        0x1000,  # align
    )
    ph_dynamic = struct.pack(
        "<IIQQQQQQ",
        2,  # PT_DYNAMIC
        6,  # PF_R | PF_W
        dynamic_offset,
        dynamic_rva,
        dynamic_rva,
        len(dynamic),
        len(dynamic),
        8,
    )

    ident = bytes([0x7F]) + b"ELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type: ET_EXEC
        0x3E,  # e_machine: x86-64
        1,  # e_version
        text_rva,  # e_entry
        ehsize,  # e_phoff
        sh_offset,  # e_shoff
        0,  # e_flags
        ehsize,  # e_ehsize
        phentsize,  # e_phentsize
        2,  # e_phnum
        shentsize,  # e_shentsize
        shnum,  # e_shnum
        shstrndx,  # e_shstrndx
    )

    def _section(
        name_offset: int,
        sh_type: int,
        flags: int,
        addr: int,
        file_offset: int,
        size: int,
        link: int = 0,
        info: int = 0,
        align: int = 1,
        entsize: int = 0,
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            name_offset,
            sh_type,
            flags,
            addr,
            file_offset,
            size,
            link,
            info,
            align,
            entsize,
        )

    sections = b"".join(
        [
            _section(0, 0, 0, 0, 0, 0),  # SHT_NULL
            _section(text_name, 1, 0x6, text_rva, text_offset, len(payload), align=16),
            _section(dynstr_name, 3, 0x2, dynstr_rva, dynstr_offset, len(dynstr), align=1),
            _section(
                dynamic_name,
                6,  # SHT_DYNAMIC
                0x3,  # SHF_ALLOC | SHF_WRITE
                dynamic_rva,
                dynamic_offset,
                len(dynamic),
                link=dynstr_shndx,
                align=8,
                entsize=16,
            ),
            _section(shstrtab_name, 3, 0x0, 0, shstr_offset, len(shstr), align=1),
        ]
    )

    return (
        header
        + ph_load
        + ph_dynamic
        + payload
        + bytes(dynstr)
        + bytes(dynamic)
        + bytes(shstr)
        + sections
    )


# ---------------------------------------------------------------------------
# HAR
# ---------------------------------------------------------------------------
def build_har(
    *,
    entries: list[dict[str, Any]] | None = None,
    creator: str = "TraceForge fixtures",
) -> dict[str, Any]:
    """Build a HAR 1.2 document.

    When ``entries`` is omitted a small, representative capture is produced
    that contains a nested path parameter, a JSON body and a secret that must
    be redacted.
    """
    if entries is None:
        entries = [
            {
                "method": "GET",
                "url": "https://api.example.test/v1/users/42",
                "status": 200,
                "content_type": "application/json",
                "response": {"id": 42, "name": "Ada", "email": "ada@example.test", "roles": ["admin"]},
                "headers": {"Content-Type": "application/json"},
            },
            {
                "method": "GET",
                "url": "https://api.example.test/v1/users/43",
                "status": 200,
                "content_type": "application/json",
                "response": {"id": 43, "name": "Grace", "email": "grace@example.test", "roles": []},
                "headers": {"Content-Type": "application/json"},
            },
            {
                "method": "POST",
                "url": "https://api.example.test/v1/sessions?redirect=https://portal.example.test",
                "status": 201,
                "content_type": "application/json",
                "request": {"username": "ada", "password": "hunter2", "token": "abc123"},
                "response": {"session": "s-1", "expires_in": 3600},
                "headers": {"Content-Type": "application/json"},
            },
            {
                "method": "GET",
                "url": "https://api.example.test/v1/health",
                "status": 200,
                "content_type": "application/json",
                "response": {"status": "ok"},
                "headers": {"Content-Type": "application/json"},
            },
            {
                "method": "GET",
                "url": "https://api.example.test/v1/missing",
                "status": 404,
                "content_type": "application/json",
                "response": {"error": "not found"},
                "headers": {"Content-Type": "application/json"},
            },
        ]

    har_entries: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        headers = [
            {"name": name, "value": value}
            for name, value in (entry.get("headers") or {}).items()
        ]
        request_headers = [{"name": "User-Agent", "value": "TraceForge-Fixtures/1.0"}] + headers
        request_headers.append({"name": "Authorization", "value": "Bearer supersecrettoken"})

        query: list[dict[str, str]] = []
        url = entry["url"]
        if "?" in url:
            base, _, query_string = url.partition("?")
        else:
            base, query_string = url, ""
        for pair in query_string.split("&"):
            if not pair:
                continue
            name, _, value = pair.partition("=")
            query.append({"name": name, "value": value})

        request: dict[str, Any] = {
            "method": entry["method"],
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": request_headers,
            "queryString": query,
            "cookies": [],
            "headersSize": -1,
            "bodySize": 0,
        }
        if "request" in entry:
            request["postData"] = {
                "mimeType": "application/json",
                "text": json.dumps(entry["request"]),
            }
            request["bodySize"] = len(json.dumps(entry["request"]))

        response_text = json.dumps(entry.get("response", {}))
        response: dict[str, Any] = {
            "status": entry["status"],
            "statusText": "OK" if entry["status"] < 400 else "Error",
            "httpVersion": "HTTP/1.1",
            "headers": [
                {"name": "Content-Type", "value": entry.get("content_type", "application/json")},
                {"name": "Set-Cookie", "value": "session=abc; Path=/"},
            ],
            "cookies": [],
            "content": {
                "size": len(response_text),
                "mimeType": entry.get("content_type", "application/json"),
                "text": response_text,
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(response_text),
        }

        har_entries.append(
            {
                "pageref": "page_1",
                "startedDateTime": f"2024-01-01T00:00:{index:02d}.000Z",
                "time": 12.5,
                "request": request,
                "response": response,
                "cache": {},
                "timings": {
                    "blocked": 0.1,
                    "dns": -1,
                    "connect": 1.2,
                    "send": 0.1,
                    "wait": 10.0,
                    "receive": 1.1,
                    "ssl": 0.5,
                },
                "serverIPAddress": "93.184.216.34",
                "connection": "4242",
            }
        )

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": creator, "version": "1.0"},
            "pages": [{"id": "page_1", "title": "fixture", "startedDateTime": "2024-01-01T00:00:00.000Z"}],
            "entries": har_entries,
        }
    }
