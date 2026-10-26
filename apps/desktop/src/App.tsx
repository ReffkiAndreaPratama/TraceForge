import { useEffect, useState } from "react";
import { api } from "./api";
import type { WorkspaceSummary } from "./types";
import { Empty, ErrorBox, Loading } from "./components/ui";
import Overview from "./components/Overview";
import Findings from "./components/Findings";
import Endpoints from "./components/Endpoints";
import GraphView from "./components/Graph";
import ImportAnalyze from "./components/Import";

type Tab = "overview" | "findings" | "endpoints" | "graph" | "import";

export default function App() {
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [newName, setNewName] = useState("");
  const [creating, setCreating] = useState(false);
  const [version, setVersion] = useState("");

  useEffect(() => {
    api
      .session()
      .then((session: { version: string }) => setVersion(session.version))
      .catch(() => {
        /* version is best-effort */
      });

    api
      .workspaces()
      .then((result: { workspaces: WorkspaceSummary[] }) => {
        setWorkspaces(result.workspaces);
        if (result.workspaces.length > 0) {
          setActive((current) => current ?? result.workspaces[0].name);
        }
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  async function createWorkspace() {
    if (!newName.trim()) return;
    setCreating(true);
    setError("");
    try {
      const result = await api.createWorkspace(newName.trim());
      setWorkspaces((current) => [...current, result.workspace]);
      setActive(result.workspace.name);
      setNewName("");
      setTab("overview");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreating(false);
    }
  }

  const tabs: [Tab, string][] = [
    ["overview", "Overview"],
    ["findings", "Findings"],
    ["endpoints", "Endpoints"],
    ["graph", "Graph"],
    ["import", "Import / Analyze"],
  ];

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          TraceForge
          {version && <small>v{version}</small>}
        </div>
        <span className="pill">Local-first · No outbound requests</span>
        <span className="spacer" />
        <span className="pill">Bridge: {api.base || "same origin"}</span>
      </header>

      <div className="layout">
        <aside className="sidebar">
          <h2>Workspaces</h2>
          {loading ? (
            <Loading />
          ) : workspaces.length === 0 ? (
            <Empty>No workspaces yet.</Empty>
          ) : (
            workspaces.map((workspace) => (
              <button
                key={workspace.id}
                className={`workspace-item${workspace.name === active ? " active" : ""}`}
                onClick={() => {
                  setActive(workspace.name);
                  setTab("overview");
                }}
              >
                <div className="name">{workspace.name}</div>
                <div className="meta">
                  {workspace.counts.findings ?? 0} findings ·{" "}
                  {workspace.counts.endpoints ?? 0} endpoints
                </div>
              </button>
            ))
          )}

          <div className="section">
            <h2>New workspace</h2>
            <input
              value={newName}
              onChange={(event) => setNewName(event.target.value)}
              placeholder="Name"
              style={{ width: "100%", marginBottom: 8 }}
              onKeyDown={(event) => {
                if (event.key === "Enter") createWorkspace();
              }}
            />
            <button
              className="primary"
              onClick={createWorkspace}
              disabled={creating || !newName.trim()}
              style={{ width: "100%" }}
            >
              {creating ? "Creating…" : "Create"}
            </button>
          </div>

          <div className="footer-note">
            Every finding keeps source, method, tool version, evidence, confidence
            and limitations. Binary→endpoint links are hypotheses only.
          </div>
        </aside>

        <main className="main">
          {!active ? (
            <div className="content">
              <ErrorBox>
                Start the local bridge (`traceforge ui`) and ensure it is
                reachable from this page. The bridge binds to 127.0.0.1 only.
              </ErrorBox>
            </div>
          ) : (
            <>
              <nav className="tabs">
                {tabs.map(([key, label]) => (
                  <button
                    key={key}
                    className={`tab${tab === key ? " active" : ""}`}
                    onClick={() => setTab(key)}
                  >
                    {label}
                  </button>
                ))}
              </nav>
              <div className="content">
                {error && <ErrorBox>{error}</ErrorBox>}
                {tab === "overview" && <Overview workspace={active} />}
                {tab === "findings" && <Findings workspace={active} />}
                {tab === "endpoints" && <Endpoints workspace={active} />}
                {tab === "graph" && <GraphView workspace={active} />}
                {tab === "import" && <ImportAnalyze workspace={active} />}
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
