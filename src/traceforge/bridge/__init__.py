"""Local HTTP bridge used by the desktop UI.

The bridge is optional: installing the core package does not pull in FastAPI or
uvicorn.  ``pip install traceforge[desktop]`` adds them.
"""

from __future__ import annotations

from traceforge.bridge.server import TOKEN_HEADER, create_app, write_token_file

__all__ = ["TOKEN_HEADER", "create_app", "write_token_file"]
