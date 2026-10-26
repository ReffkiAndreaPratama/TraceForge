import type {
  EndpointsDocument,
  FindingDetail,
  Finding,
  GraphDocument,
  ImportOutcome,
  NeighbourResponse,
  Overview,
  SessionInfo,
  WorkspaceSummary,
} from "./types";

const DEV_BRIDGE = "http://127.0.0.1:8765";

function defaultBase(): string {
  const env = (import.meta as { env?: Record<string, string> }).env ?? {};
  if (env.VITE_BRIDGE_URL) return env.VITE_BRIDGE_URL.replace(/\/$/, "");
  if (window.location.port === "5173") return DEV_BRIDGE;
  return "";
}

export const apiBase = defaultBase();

let sessionPromise: Promise<SessionInfo> | null = null;

async function getSession(): Promise<SessionInfo> {
  if (!sessionPromise) {
    sessionPromise = fetch(`${apiBase}/api/session`).then(async (response) => {
      if (!response.ok) {
        throw new Error(`Bridge session unavailable (HTTP ${response.status})`);
      }
      return (await response.json()) as SessionInfo;
    });
  }
  return sessionPromise;
}

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const session = await getSession();
  const headers = new Headers(init.headers);
  headers.set("X-TraceForge-Token", session.token);
  if (init.body && !(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`${apiBase}${path}`, { ...init, headers });
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      message = body.detail ?? body.error?.message ?? message;
    } catch {
      /* the body was not JSON */
    }
    throw new ApiError(String(message), response.status);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  base: apiBase,
  session: getSession,

  workspaces: () =>
    request<{ workspaces: WorkspaceSummary[] }>("/api/workspaces"),

  createWorkspace: (name: string, description?: string) =>
    request<{ workspace: WorkspaceSummary }>("/api/workspaces", {
      method: "POST",
      body: JSON.stringify({ name, description }),
    }),

  overview: (workspace: string) =>
    request<Overview>(`/api/workspaces/${encodeURIComponent(workspace)}/overview`),

  findings: (workspace: string, params: { q?: string; type?: string; limit?: number } = {}) => {
    const query = new URLSearchParams();
    if (params.q) query.set("q", params.q);
    if (params.type) query.set("type", params.type);
    if (params.limit) query.set("limit", String(params.limit));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<{ count: number; findings: Finding[] }>(
      `/api/workspaces/${encodeURIComponent(workspace)}/findings${suffix}`,
    );
  },

  finding: (workspace: string, id: string) =>
    request<FindingDetail>(
      `/api/workspaces/${encodeURIComponent(workspace)}/findings/${encodeURIComponent(id)}`,
    ),

  annotate: (workspace: string, id: string, text: string) =>
    request<{ finding: string; annotation: string | null }>(
      `/api/workspaces/${encodeURIComponent(workspace)}/findings/${encodeURIComponent(id)}/annotation`,
      { method: "POST", body: JSON.stringify({ text }) },
    ),

  endpoints: (workspace: string) =>
    request<EndpointsDocument>(
      `/api/workspaces/${encodeURIComponent(workspace)}/endpoints`,
    ),

  graph: (workspace: string) =>
    request<GraphDocument>(`/api/workspaces/${encodeURIComponent(workspace)}/graph`),

  neighbours: (workspace: string, nodeId: string) =>
    request<NeighbourResponse>(
      `/api/workspaces/${encodeURIComponent(workspace)}/graph/neighbors/${encodeURIComponent(nodeId)}`,
    ),

  upload: (workspace: string, kind: "har" | "binary", file: File) => {
    const form = new FormData();
    form.append("file", file, file.name);
    const route = kind === "har" ? "imports/har" : "analyses/binary";
    return request<ImportOutcome>(
      `/api/workspaces/${encodeURIComponent(workspace)}/${route}`,
      { method: "POST", body: form },
    );
  },
};

export async function downloadExport(
  workspace: string,
  kind: "openapi" | "findings",
): Promise<void> {
  const session = await getSession();
  const route =
    kind === "openapi" ? "exports/openapi" : "exports/findings";
  const response = await fetch(
    `${apiBase}/api/workspaces/${encodeURIComponent(workspace)}/${route}`,
    { headers: { "X-TraceForge-Token": session.token } },
  );
  if (!response.ok) {
    throw new ApiError(`Export failed (HTTP ${response.status})`, response.status);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download =
    kind === "openapi"
      ? `${workspace}-openapi.yaml`
      : `${workspace}-findings.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
