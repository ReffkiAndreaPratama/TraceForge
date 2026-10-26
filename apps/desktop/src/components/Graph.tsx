import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { GraphDocument, Neighbour, NeighbourResponse } from "../types";
import { Badge, Empty, ErrorBox, Loading } from "./ui";

export default function GraphView({ workspace }: { workspace: string }) {
  const [document, setDocument] = useState<GraphDocument | null>(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [neighbours, setNeighbours] = useState<NeighbourResponse | null>(null);
  const [loadingNeighbours, setLoadingNeighbours] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setDocument(null);
    setError("");
    api
      .graph(workspace)
      .then((result) => {
        if (!cancelled) setDocument(result);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      });
    return () => {
      cancelled = true;
    };
  }, [workspace]);

  useEffect(() => {
    if (!selected) {
      setNeighbours(null);
      return;
    }
    let cancelled = false;
    setLoadingNeighbours(true);
    api
      .neighbours(workspace, selected)
      .then((result) => {
        if (!cancelled) setNeighbours(result);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoadingNeighbours(false);
      });
    return () => {
      cancelled = true;
    };
  }, [workspace, selected]);

  const nodes = useMemo(() => {
    if (!document) return [];
    const needle = query.trim().toLowerCase();
    if (!needle) return document.nodes.slice(0, 200);
    return document.nodes
      .filter(
        (node) =>
          node.label.toLowerCase().includes(needle) ||
          node.id.toLowerCase().includes(needle) ||
          JSON.stringify(node.attributes).toLowerCase().includes(needle),
      )
      .slice(0, 200);
  }, [document, query]);

  const typeCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const node of document?.nodes ?? []) {
      counts.set(node.type, (counts.get(node.type) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort();
  }, [document]);

  if (error) return <ErrorBox>{error}</ErrorBox>;
  if (!document) return <Loading />;

  const selectedNode = document.nodes.find((node) => node.id === selected);

  return (
    <div>
      <div className="toolbar">
        <input
          placeholder="Filter nodes by label, id or attribute…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          style={{ width: 320 }}
        />
        <span className="muted">
          {document.nodes.length} nodes · {document.edges.length} edges
        </span>
      </div>

      <div className="node-list" style={{ marginBottom: 12 }}>
        {typeCounts.map(([type, count]) => (
          <span className="node-chip" key={type}>
            {type}: {count}
          </span>
        ))}
      </div>

      <div className="split">
        <div>
          {nodes.length === 0 ? (
            <Empty>No nodes match this filter.</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Label</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {nodes.map((node) => (
                  <tr
                    key={node.id}
                    className={`selectable${node.id === selected ? " selected" : ""}`}
                    onClick={() => setSelected(node.id)}
                  >
                    <td>{node.type}</td>
                    <td title={node.id}>{node.label}</td>
                    <td>
                      <Badge confidence={node.confidence} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="detail">
          {!selectedNode ? (
            <Empty>Select a node to inspect its relationships.</Empty>
          ) : (
            <>
              <h3>{selectedNode.label}</h3>
              <div className="muted mono">{selectedNode.id}</div>

              <h4>Node</h4>
              <div className="kv">
                <span className="k">Type</span>
                <span>{selectedNode.type}</span>
                <span className="k">Confidence</span>
                <span>
                  <Badge confidence={selectedNode.confidence} />
                </span>
                <span className="k">Artifact</span>
                <span className="mono">{selectedNode.artifact_id ?? "—"}</span>
              </div>

              <h4>Attributes</h4>
              <pre className="json">
                {JSON.stringify(selectedNode.attributes, null, 2)}
              </pre>

              <h4>Neighbours</h4>
              {loadingNeighbours ? (
                <Loading />
              ) : !neighbours || neighbours.neighbours.length === 0 ? (
                <div className="muted">No relationships recorded for this node.</div>
              ) : (
                <ul className="plain">
                  {neighbours.neighbours.map((neighbour: Neighbour) => (
                    <li key={`${neighbour.direction}-${neighbour.id}`}>
                      <button
                        className="node-chip"
                        onClick={() => setSelected(neighbour.id)}
                        style={{ marginRight: 6 }}
                      >
                        {neighbour.type}
                      </button>
                      {neighbour.label}{" "}
                      <span className="muted">
                        ({neighbour.direction === "out" ? "outgoing" : "incoming"})
                      </span>
                      <ul className="plain">
                        {neighbour.edges.map((edge, index) => (
                          <li key={`${edge.kind}-${index}`}>
                            <span className="mono">{edge.kind}</span> — {edge.summary}{" "}
                            <span className="muted">
                              ({edge.confidence}
                              {edge.verified ? ", verified" : ", unverified"})
                            </span>
                          </li>
                        ))}
                      </ul>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>
      </div>

      <div className="footer-note">
        Candidate links between binaries and endpoints are always marked
        <code> hypothesis</code> and unverified; they are never presented as
        ground truth.
      </div>
    </div>
  );
}
