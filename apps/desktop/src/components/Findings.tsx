import { useEffect, useState } from "react";
import { api } from "../api";
import type { Finding, FindingDetail } from "../types";
import { Badge, Empty, ErrorBox, Loading } from "./ui";

export default function Findings({ workspace }: { workspace: string }) {
  const [query, setQuery] = useState("");
  const [type, setType] = useState("");
  const [types, setTypes] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [annotation, setAnnotation] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .findings(workspace, { limit: 2000 })
      .then((result) => {
        if (cancelled) return;
        setTypes(Array.from(new Set(result.findings.map((item) => item.type))).sort());
      })
      .catch(() => {
        /* the main fetch reports errors */
      });
    return () => {
      cancelled = true;
    };
  }, [workspace]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    api
      .findings(workspace, { q: query || undefined, type: type || undefined })
      .then((result) => {
        if (cancelled) return;
        setFindings(result.findings);
        setSelected((current) =>
          current && result.findings.some((item) => item.id === current)
            ? current
            : (result.findings[0]?.id ?? null),
        );
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [workspace, query, type]);

  useEffect(() => {
    if (!selected) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    api
      .finding(workspace, selected)
      .then((result) => {
        if (cancelled) return;
        setDetail(result);
        setAnnotation(result.finding.annotation ?? "");
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [workspace, selected]);

  async function saveAnnotation() {
    if (!selected) return;
    setSaving(true);
    try {
      await api.annotate(workspace, selected, annotation);
      setDetail((current) =>
        current
          ? { ...current, finding: { ...current.finding, annotation } }
          : current,
      );
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <div className="toolbar">
        <input
          placeholder="Search findings…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          style={{ width: 260 }}
        />
        <select value={type} onChange={(event) => setType(event.target.value)}>
          <option value="">All types</option>
          {types.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <span className="muted">{findings.length} shown</span>
      </div>

      {error && <ErrorBox>{error}</ErrorBox>}

      <div className="split">
        <div>
          {loading ? (
            <Loading />
          ) : findings.length === 0 ? (
            <Empty>No findings match this filter.</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Summary</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((finding) => (
                  <tr
                    key={finding.id}
                    className={`selectable${finding.id === selected ? " selected" : ""}`}
                    onClick={() => setSelected(finding.id)}
                  >
                    <td>{finding.type}</td>
                    <td>{finding.summary}</td>
                    <td>
                      <Badge confidence={finding.confidence} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="detail">
          {!detail ? (
            <Empty>Select a finding to inspect its provenance.</Empty>
          ) : (
            <>
              <h3>{detail.finding.summary}</h3>
              <div className="muted mono">{detail.finding.id}</div>

              <h4>Provenance</h4>
              <div className="kv">
                <span className="k">Type</span>
                <span>{detail.finding.type}</span>
                <span className="k">Confidence</span>
                <span>
                  <Badge confidence={detail.finding.confidence} />
                </span>
                <span className="k">Method</span>
                <span>{detail.finding.method}</span>
                <span className="k">Tool</span>
                <span>
                  {detail.finding.tool.name} {detail.finding.tool.version}
                </span>
                <span className="k">Artifact</span>
                <span className="mono">{detail.finding.artifact_id ?? "—"}</span>
                <span className="k">Run</span>
                <span className="mono">{detail.finding.run_id ?? "—"}</span>
              </div>

              <h4>Evidence references</h4>
              {detail.finding.evidence.length === 0 ? (
                <div className="muted">No evidence references recorded.</div>
              ) : (
                <pre className="json">
                  {JSON.stringify(detail.finding.evidence, null, 2)}
                </pre>
              )}

              <h4>Data</h4>
              <pre className="json">
                {JSON.stringify(detail.finding.data, null, 2)}
              </pre>

              <h4>Limitations</h4>
              {detail.finding.limitations.length === 0 ? (
                <div className="muted">None recorded.</div>
              ) : (
                <ul className="plain">
                  {detail.finding.limitations.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              )}

              <h4>Relationships</h4>
              {detail.relationships.length === 0 ? (
                <div className="muted">No relationships recorded.</div>
              ) : (
                <ul className="plain">
                  {detail.relationships.map((relationship, index) => (
                    <li key={`${relationship.kind}-${index}`}>
                      <span className="mono">{relationship.kind}</span> —{" "}
                      {relationship.summary}{" "}
                      <span className="muted">
                        ({relationship.confidence}
                        {relationship.verified ? ", verified" : ", unverified"})
                      </span>
                    </li>
                  ))}
                </ul>
              )}

              <h4>Annotation</h4>
              <textarea
                rows={3}
                style={{ width: "100%" }}
                value={annotation}
                onChange={(event) => setAnnotation(event.target.value)}
                placeholder="Analyst note (stored locally, never exported automatically)…"
              />
              <div style={{ marginTop: 8 }}>
                <button onClick={saveAnnotation} disabled={saving}>
                  {saving ? "Saving…" : "Save annotation"}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
