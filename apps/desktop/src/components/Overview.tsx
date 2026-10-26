import { useEffect, useState } from "react";
import { api, downloadExport } from "../api";
import type { Overview as OverviewData } from "../types";
import { bytes, Empty, ErrorBox, Loading, timestamp } from "./ui";

export default function Overview({ workspace }: { workspace: string }) {
  const [data, setData] = useState<OverviewData | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError("");
    api
      .overview(workspace)
      .then((result) => {
        if (!cancelled) setData(result);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [workspace]);

  async function handleExport(kind: "openapi" | "findings") {
    setMessage("");
    try {
      await downloadExport(workspace, kind);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  if (error) return <ErrorBox>{error}</ErrorBox>;
  if (!data) return <Loading />;

  const counts = data.counts;
  const cards: [string, number | undefined][] = [
    ["Artifacts", counts.artifacts],
    ["Endpoints", counts.endpoints],
    ["Findings", counts.findings],
    ["Observations", counts.observations],
    ["Relationships", counts.relationships],
    ["Runs", counts.runs],
  ];

  return (
    <div>
      <div className="toolbar">
        <strong>{data.workspace.name}</strong>
        <span className="muted mono">{data.workspace.root}</span>
        <span style={{ flex: 1 }} />
        <button onClick={() => handleExport("findings")}>Export findings (JSON)</button>
        <button onClick={() => handleExport("openapi")}>Export OpenAPI (YAML)</button>
      </div>
      {message && <div className="notice">{message}</div>}

      <div className="grid">
        {cards.map(([label, value]) => (
          <div className="card" key={label}>
            <div className="label">{label}</div>
            <div className="value">{value ?? "—"}</div>
          </div>
        ))}
      </div>

      <div className="section">
        <h2>Artifacts</h2>
        {data.artifacts.length === 0 ? (
          <Empty>No artifacts yet. Import a HAR file or analyze a binary.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Size</th>
                <th>SHA-256</th>
                <th>Imported</th>
              </tr>
            </thead>
            <tbody>
              {data.artifacts.map((artifact) => (
                <tr key={artifact.id}>
                  <td>{artifact.display_name}</td>
                  <td>{artifact.kind}</td>
                  <td>{bytes(artifact.size_bytes)}</td>
                  <td className="mono">{artifact.sha256.slice(0, 16)}…</td>
                  <td>{timestamp(artifact.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="section">
        <h2>Analysis runs</h2>
        {data.runs.length === 0 ? (
          <Empty>No runs recorded.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Run</th>
                <th>Kind</th>
                <th>Status</th>
                <th>Artifact</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {data.runs.map((run) => (
                <tr key={run.id}>
                  <td className="mono">{run.id}</td>
                  <td>{run.kind}</td>
                  <td>{run.status}</td>
                  <td className="mono">{run.artifact_id ?? "—"}</td>
                  <td>{timestamp(run.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="footer-note">
        TraceForge stores provenance for every finding: source artifact, method,
        tool version, evidence references and confidence. Imported files are
        parsed only — they are never executed.
      </div>
    </div>
  );
}
