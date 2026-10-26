# Security policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, email `security@traceforge.invalid` with:

- A description of the issue and its potential impact,
- Steps to reproduce (use synthetic examples only),
- The affected version/commit if known.

We will acknowledge the report and work with you on a fix and disclosure timeline.

## Supported scope

TraceForge is a local-only analysis tool.  Security issues we care about:

- **Arbitrary code execution**: any path that executes imported binaries,
  scripts or payloads is a critical bug.
- **Path traversal / symlink abuse**: reading or writing outside the workspace
  or outside approved paths.
- **Secret leakage**: failing to redact secrets, or logging raw sensitive values.
- **SQL injection**: string concatenation in queries.
- **SSRF / outbound network**: adding unauthorised network access.
- **Deserialisation abuse**: unsafe `pickle`/`eval`/`exec` on imported data.
- **Workspace escape via uploads**: the bridge must only accept uploads, not
  arbitrary caller-supplied filesystem paths.

## Security measures in place

- **Parse-only**: imported binaries are never executed.
- **Redaction**: `traceforge.security.redaction` redacts common secret patterns
  before persistence and before most exports.
- **Path safety**: `validate_input_file` blocks symlinks and enforces size
  limits; paths are constrained to the workspace.
- **Bounded parsing**: JSON depth/key limits, HAR entry caps, string scan
  limits, recursion caps.
- **Loopback-only bridge**: the desktop bridge binds to `127.0.0.1`, requires
  a per-run token, restricts CORS and never makes outbound requests.
- **Transactional writes**: database operations use the repository with
  parameterised SQL via SQLAlchemy.
- **Evidence discipline**: uncertain links are hypotheses with explicit
  limitations.

## Hardening checklist for contributors

- [ ] New parsers enforce `Limits`.
- [ ] New file reads use `validate_input_file` or an equivalent guard.
- [ ] Secrets added to fixtures must be clearly fake and redaction-tested.
- [ ] No `subprocess`, `os.system`, `eval`, `exec` or `pickle` on untrusted
  data.
- [ ] Database access uses SQLAlchemy ORM/parameterised statements.
- [ ] Confidence and limitations are populated for every new finding type.
