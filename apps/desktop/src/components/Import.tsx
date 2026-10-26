import { useState } from "react";
import { api } from "../api";
import type { ImportOutcome } from "../types";
import { ErrorBox } from "./ui";

export default function ImportAnalyze({ workspace }: { workspace: string }) {
  const [har, setHar] = useState<File | null>(null);
  const [binary, setBinary] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ImportOutcome | null>(null);

  async function upload(kind: "har" | "binary") {
    const file = kind === "har" ? har : binary;
    if (!file) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const outcome = await api.upload(workspace, kind, file);
      setResult(outcome);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="toolbar">
        <strong>Import and analyze</strong>
        <span className="muted">
          Uploads go to the local bridge only; no files are sent over the
          network.
        </span>
      </div>

      {error && <ErrorBox>{error}</ErrorBox>}

      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))" }}>
        <div className="card">
          <div className="label">HTTP Archive (HAR)</div>
          <p className="muted">
            Import captured traffic. Secrets are redacted before persistence.
            Endpoints and schemas are inferred from observed entries.
          </p>
          <input
            type="file"
            accept=".har,application/json"
            onChange={(event) => setHar(event.target.files?.[0] ?? null)}
          />
          <div style={{ marginTop: 12 }}>
            <button
              className="primary"
              disabled={busy || !har}
              onClick={() => upload("har")}
            >
              {busy ? "Working…" : "Import HAR"}
            </button>
          </div>
        </div>

        <div className="card">
          <div className="label">Binary (PE / ELF / Mach-O)</div>
          <p className="muted">
            Fingerprint the binary and extract strings. No decompiler is used.
            Links to API endpoints are only hypotheses, never inferred as proof.
          </p>
          <input
            type="file"
            onChange={(event) => setBinary(event.target.files?.[0] ?? null)}
          />
          <div style={{ marginTop: 12 }}>
            <button
              className="primary"
              disabled={busy || !binary}
              onClick={() => upload("binary")}
            >
              {busy ? "Working…" : "Analyze binary"}
            </button>
          </div>
        </div>
      </div>

      {result && (
        <div className="section">
          <h2>Last result</h2>
          <div className="grid">
            <div className="card">
              <div className="label">Artifact</div>
              <div className="mono" style={{ marginTop: 4 }}>
                {result.artifact_id}
              </div>
            </div>
            <div className="card">
              <div className="label">Findings</div>
              <div className="value">{result.findings}</div>
            </div>
            <div className="card">
              <div className="label">Endpoints</div>
              <div className="value">{result.endpoints}</div>
            </div>
            <div className="card">
              <div className="label">Relationships</div>
              <div className="value">{result.relationships}</div>
            </div>
          </div>
          <div className="card" style={{ marginTop: 12 }}>
            <div className="label">Details</div>
            <pre className="json">
              {JSON.stringify(result.detail, null, 2)}
            </pre>
          </div>
        </div>
      )}

      <div className="footer-note">
        The bridge enforces size and parsing limits. If an upload is rejected by
        a safety policy, the reason is reported explicitly — nothing is executed.
      </div>
    </div>
  );
}
