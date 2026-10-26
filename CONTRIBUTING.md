# Contributing to TraceForge

TraceForge is a local-first project.  We welcome contributions, but there are
a few rules designed to keep the tool safe and auditable.

## Ground rules

- **Local-first**: do not add outbound network calls, telemetry, crash reporting
  or cloud uploads.  The only exception is fetching content through an explicit
  command the user runs themselves.
- **Never execute imported artifacts**: binaries, HAR files and any imported data
  must only be parsed.  Do not call `subprocess` to run imported binaries.
- **Provenance is mandatory**: every finding must record `method`, `tool_name`,
  `tool_version`, evidence references, `confidence` and `limitations`.
- **Confidence matters**: `observed` is only for things directly read from the
  input.  `inferred` requires a documented rule.  `hypothesis` is for
  candidate links that have not been verified; binary→endpoint links must be
  hypotheses and explicitly marked unverified.
- **Redact before persistence**: secrets in headers, cookies, auth parameters
  and bodies must be redacted before writing to the database or exporting.
- **Bounds are required**: any new parser must enforce size limits, recursion
  depth limits and time/iteration caps.  Use the existing `Limits` and
  validators.
- **Determinism**: exports used in tests must be deterministic.  Sort
  collections and avoid including non-reproducible timestamps unless the caller
  opts in.
- **SQLite safety**: use parameterised queries.  Never concatenate user input
  into SQL.
- **Tests use synthetic fixtures**: add fixtures under `tests/fixtures/`, never
  commit real binaries, real HAR files, secrets or credentials.

## Development setup

```bash
pip install -e ".[dev,desktop]"
npm install --prefix apps/desktop
npm run build --prefix apps/desktop
pytest -q
```

## Code style

- Run `ruff check .` and `mypy src/traceforge` before submitting.
- Keep functions small and prefer explicit dataclasses/Pydantic models.
- Error messages must be actionable and must not leak the contents of secrets.
- Use the documented CLI exit codes (`traceforge.errors.ExitCode`).

## Pull requests

- Include tests for new behaviour and for any bug fix.
- Update `CHANGELOG.md` and relevant docs if you change the schema, formats,
  CLI contract or security behaviour.
- If you change the relationship vocabulary, update `docs/formats.md` and the
  graph schema version with a migration plan.

## Reporting issues

Use `traceforge report` or the GitHub issue tracker.  See `SECURITY.md` for
vulnerability reports.
