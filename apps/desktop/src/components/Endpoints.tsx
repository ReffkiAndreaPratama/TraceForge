import { useEffect, useState } from "react";
import { api } from "../api";
import type { ApiEndpoint, EndpointsDocument } from "../types";
import { Empty, ErrorBox, Loading } from "./ui";

export default function Endpoints({ workspace }: { workspace: string }) {
  const [document, setDocument] = useState<EndpointsDocument | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setDocument(null);
    setError("");
    api
      .endpoints(workspace)
      .then((result) => {
        if (cancelled) return;
        setDocument(result);
        setSelected(result.endpoints[0]?.id ?? null);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [workspace]);

  if (error) return <ErrorBox>{error}</ErrorBox>;
  if (!document) return <Loading />;

  const current: ApiEndpoint | undefined = document.endpoints.find(
    (item) => item.id === selected,
  );

  return (
    <div>
      <div className="toolbar">
        <strong>{document.count}</strong>
        <span className="muted">endpoints derived from observed traffic</span>
      </div>

      {document.endpoints.length === 0 ? (
        <Empty>No endpoints yet. Import a HAR capture to build the inventory.</Empty>
      ) : (
        <div className="split">
          <div>
            <table>
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Origin</th>
                  <th>Calls</th>
                </tr>
              </thead>
              <tbody>
                {document.endpoints.map((endpoint) => (
                  <tr
                    key={endpoint.id}
                    className={`selectable${endpoint.id === selected ? " selected" : ""}`}
                    onClick={() => setSelected(endpoint.id)}
                  >
                    <td className="mono">{endpoint.method}</td>
                    <td className="mono">{endpoint.path}</td>
                    <td className="muted">{endpoint.host}</td>
                    <td>{endpoint.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="detail">
            {!current ? (
              <Empty>Select an endpoint.</Empty>
            ) : (
              <>
                <h3>
                  <span className="mono">{current.method}</span> {current.path}
                </h3>
                <div className="muted mono">{current.origin}</div>

                <h4>Observed</h4>
                <div className="kv">
                  <span className="k">Calls</span>
                  <span>{current.count}</span>
                  <span className="k">Status codes</span>
                  <span>{current.status_codes.join(", ") || "—"}</span>
                  <span className="k">Content types</span>
                  <span>{current.content_types.join(", ") || "—"}</span>
                  <span className="k">Confidence</span>
                  <span>{current.confidence}</span>
                  <span className="k">Artifacts</span>
                  <span className="mono">{current.artifact_ids.join(", ") || "—"}</span>
                </div>

                <h4>Query parameters</h4>
                {current.query_params.length === 0 ? (
                  <div className="muted">None observed.</div>
                ) : (
                  <div className="node-list">
                    {current.query_params.map((param) => (
                      <span className="node-chip" key={param}>
                        {param}
                      </span>
                    ))}
                  </div>
                )}

                <h4>Request schema</h4>
                <pre className="json">
                  {current.request_schema
                    ? JSON.stringify(current.request_schema, null, 2)
                    : "No request body observed."}
                </pre>

                <h4>Response schema</h4>
                <pre className="json">
                  {current.response_schema
                    ? JSON.stringify(current.response_schema, null, 2)
                    : "No response schema inferred."}
                </pre>

                <h4>Limitations</h4>
                {current.limitations.length === 0 ? (
                  <div className="muted">None recorded.</div>
                ) : (
                  <ul className="plain">
                    {current.limitations.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
