"""Write the synthetic sample files used by the README quickstart."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests.fixtures.generators import build_elf, build_har, build_pe  # noqa: E402

SAMPLES = ROOT / "examples" / "samples"


def main() -> int:
    SAMPLES.mkdir(parents=True, exist_ok=True)

    pe_path = SAMPLES / "hello-world.exe"
    pe_path.write_bytes(build_pe())
    print(f"wrote {pe_path} ({pe_path.stat().st_size} bytes)")

    elf_path = SAMPLES / "hello-world"
    elf_path.write_bytes(build_elf())
    print(f"wrote {elf_path} ({elf_path.stat().st_size} bytes)")

    har_path = SAMPLES / "demo.har"
    har_path.write_text(json.dumps(build_har(), indent=2), encoding="utf-8")
    print(f"wrote {har_path} ({har_path.stat().st_size} bytes)")

    har2_path = SAMPLES / "demo-v2.har"
    entries = [
        {
            "method": "GET",
            "url": "https://api.example.test/v1/users/42",
            "status": 200,
            "content_type": "application/json",
            "response": {"id": 42, "name": "Ada Lovelace", "email": "ada@example.test", "roles": ["admin", "editor"]},
            "headers": {"Content-Type": "application/json"},
        },
        {
            "method": "GET",
            "url": "https://api.example.test/v1/users/43",
            "status": 404,
            "content_type": "application/json",
            "response": {"error": "not found"},
            "headers": {"Content-Type": "application/json"},
        },
        {
            "method": "POST",
            "url": "https://api.example.test/v1/sessions",
            "status": 201,
            "content_type": "application/json",
            "request": {"username": "ada", "password": "hunter2"},
            "response": {"session": "s-2", "expires_in": 7200},
            "headers": {"Content-Type": "application/json"},
        },
        {
            "method": "GET",
            "url": "https://api.example.test/v1/health",
            "status": 200,
            "content_type": "application/json",
            "response": {"status": "ok", "version": "2.0.0"},
            "headers": {"Content-Type": "application/json"},
        },
        {
            "method": "GET",
            "url": "https://api.example.test/v1/metrics",
            "status": 200,
            "content_type": "application/json",
            "response": {"cpu": 0.42},
            "headers": {"Content-Type": "application/json"},
        },
    ]
    har2_path.write_text(json.dumps(build_har(entries=entries), indent=2), encoding="utf-8")
    print(f"wrote {har2_path} ({har2_path.stat().st_size} bytes)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
