"""TraceForge — local-first reverse engineering workbench.

TraceForge correlates API traffic, binary metadata, extracted strings and static
analysis findings into a single, queryable *evidence graph* while preserving the
provenance of every finding.

The core is intentionally free of any network access, cloud dependency or LLM
requirement: it must be fully usable offline.
"""

from traceforge.version import __version__

__all__ = ["__version__"]
