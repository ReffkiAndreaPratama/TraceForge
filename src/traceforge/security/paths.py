"""Safe filesystem handling.

Every path derived from user input goes through this module.  The rules are:

* No traversal outside the workspace root, even via ``..`` or absolute paths.
* Symlinks are resolved before the containment check, so a symlink pointing
  outside the workspace is rejected.
* User supplied file names are never used verbatim as storage names; a
  generated identifier is used instead and the original name is kept only as a
  sanitised *display* label.
"""

from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path

from traceforge.errors import ValidationError

#: Characters that are safe to keep in a display name.
_SAFE_DISPLAY_RE = re.compile(r"[^A-Za-z0-9._\- ]+")
#: Windows reserved device names.
_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *{f"COM{i}" for i in range(1, 10)},
    *{f"LPT{i}" for i in range(1, 10)},
}
MAX_DISPLAY_NAME = 120


def sanitize_display_name(name: str | None, *, fallback: str = "unnamed") -> str:
    """Return a display-safe version of ``name``.

    The result contains no path separators, no control characters and no
    reserved Windows device names.  It is used for *display only*; storage
    always uses generated identifiers.
    """
    if not name:
        return fallback
    base = os.path.basename(name.replace("\\", "/")).strip()
    base = unicodedata.normalize("NFC", base)
    base = "".join(ch for ch in base if ch.isprintable())
    base = _SAFE_DISPLAY_RE.sub("_", base).strip(" ._")
    if not base:
        return fallback
    stem = base.split(".")[0].upper()
    if stem in _RESERVED_NAMES:
        base = f"_{base}"
    if len(base) > MAX_DISPLAY_NAME:
        base = base[:MAX_DISPLAY_NAME].rstrip(" ._")
    return base or fallback


def is_within(root: Path, candidate: Path) -> bool:
    """Return ``True`` when ``candidate`` resolves inside ``root``."""
    try:
        root_resolved = root.resolve(strict=False)
        candidate_resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):  # pragma: no cover - platform dependent
        return False
    try:
        candidate_resolved.relative_to(root_resolved)
    except ValueError:
        return False
    return True


def safe_join(root: Path, *parts: str) -> Path:
    """Join ``parts`` under ``root``, refusing to escape ``root``.

    Raises :class:`ValidationError` when the result would leave the root.
    """
    root = Path(root)
    for part in parts:
        if not part:
            raise ValidationError("Empty path component is not allowed")
        if os.path.isabs(part) or (len(part) > 1 and part[1] == ":"):
            raise ValidationError("Absolute paths are not allowed", detail=part)
    candidate = root.joinpath(*parts)
    if not is_within(root, candidate):
        raise ValidationError("Path escapes the workspace root", detail=str(candidate))
    return candidate


def resolve_existing_file(path: str | Path, *, must_exist: bool = True) -> Path:
    """Resolve ``path`` to an existing regular file, rejecting symlinked inputs.

    Symlinked *input* files are rejected by default: a symlink can point at a
    file that the user did not intend to share.  Callers that need to follow
    symlinks can pass ``allow_symlink=True``.
    """
    raw = Path(path).expanduser()
    if not raw.exists():
        if must_exist:
            raise ValidationError("File does not exist", detail=str(raw))
        raise ValidationError("File does not exist", detail=str(raw))
    if raw.is_dir():
        raise ValidationError("Expected a file but found a directory", detail=str(raw))
    if raw.is_symlink():
        raise ValidationError(
            "Refusing to read a symbolic link; copy the file first", detail=str(raw)
        )
    resolved = raw.resolve(strict=True)
    if not resolved.is_file():
        raise ValidationError("Target is not a regular file", detail=str(resolved))
    return resolved


def ensure_directory(path: Path) -> Path:
    """Create ``path`` (and parents) if needed and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path
