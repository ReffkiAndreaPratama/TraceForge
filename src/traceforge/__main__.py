"""Allow ``python -m traceforge``."""

from traceforge.cli.main import run

if __name__ == "__main__":
    raise SystemExit(run())
