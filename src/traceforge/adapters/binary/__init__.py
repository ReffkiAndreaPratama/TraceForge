"""Binary format adapters."""

from traceforge.adapters.binary.base import AdapterResult, BinaryAdapter
from traceforge.adapters.binary.fingerprint import (
    FingerprintResult,
    available_adapters,
    fingerprint,
    select_adapter,
)
from traceforge.adapters.binary.indicators import (
    extract_domains,
    extract_ip_addresses,
    extract_paths,
    extract_urls,
)
from traceforge.adapters.binary.strings import (
    ExtractedString,
    extract_strings,
    shannon_entropy,
)

__all__ = [
    "AdapterResult",
    "BinaryAdapter",
    "ExtractedString",
    "FingerprintResult",
    "available_adapters",
    "extract_domains",
    "extract_ip_addresses",
    "extract_paths",
    "extract_strings",
    "extract_urls",
    "fingerprint",
    "select_adapter",
    "shannon_entropy",
]
