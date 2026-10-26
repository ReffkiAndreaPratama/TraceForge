export type Confidence = "observed" | "inferred" | "hypothesis";

export interface WorkspaceCounts {
  artifacts?: number;
  endpoints?: number;
  findings?: number;
  observations?: number;
  relationships?: number;
  runs?: number;
  [key: string]: number | undefined;
}

export interface WorkspaceSummary {
  id: string;
  name: string;
  root: string;
  counts: WorkspaceCounts;
}

export interface ArtifactSummary {
  id: string;
  kind: string;
  display_name: string;
  sha256: string;
  size_bytes: number;
  created_at: string | null;
}

export interface RunSummary {
  id: string;
  kind: string;
  status: string;
  artifact_id: string | null;
  started_at: string | null;
}

export interface Overview {
  workspace: { id: string; name: string; root: string };
  counts: WorkspaceCounts;
  artifacts: ArtifactSummary[];
  runs: RunSummary[];
}

export interface EvidenceRef {
  kind?: string;
  ref?: string;
  locator?: string;
  description?: string;
  [key: string]: unknown;
}

export interface Finding {
  id: string;
  type: string;
  summary: string;
  confidence: Confidence;
  method: string;
  tool: { name: string; version: string };
  artifact_id: string | null;
  run_id: string | null;
  key: string;
  data: Record<string, unknown>;
  evidence: EvidenceRef[];
  limitations: string[];
  annotation: string | null;
  created_at: string | null;
}

export interface Relationship {
  kind: string;
  from: string;
  to: string;
  confidence: string;
  verified: boolean;
  summary: string;
}

export interface FindingDetail {
  finding: Finding;
  relationships: Relationship[];
}

export interface ApiEndpoint {
  id: string;
  method: string;
  origin: string;
  path: string;
  path_key: string;
  host: string;
  scheme: string;
  query_params: string[];
  status_codes: number[];
  content_types: string[];
  request_schema: unknown;
  response_schema: unknown;
  timings: unknown;
  count: number;
  confidence: string;
  limitations: string[];
  artifact_ids: string[];
}

export interface EndpointsDocument {
  kind: string;
  schema_version: number;
  count: number;
  endpoints: ApiEndpoint[];
  notes: string[];
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  confidence: Confidence;
  artifact_id: string | null;
  finding_type: string | null;
  attributes: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
  summary: string;
  confidence: Confidence;
  verified: boolean;
  evidence: unknown[];
  limitations: string[];
}

export interface GraphDocument {
  kind: string;
  schema_version: number;
  workspace: { id: string; name: string };
  nodes: GraphNode[];
  edges: GraphEdge[];
  statistics: Record<string, unknown>;
  notes: string[];
}

export interface NeighbourEdge {
  kind: string;
  confidence: Confidence;
  summary: string;
  verified: boolean;
  limitations: string[];
}

export interface Neighbour {
  id: string;
  type: string;
  label: string;
  direction: "in" | "out";
  edges: NeighbourEdge[];
}

export interface NeighbourResponse {
  node: string;
  neighbours: Neighbour[];
}

export interface ImportOutcome {
  artifact_id: string;
  run_id: string;
  status: string;
  findings: number;
  observations: number;
  endpoints: number;
  relationships: number;
  diagnostics: { level: string; code: string; message: string }[];
  detail: Record<string, unknown>;
  workspace: string;
}

export interface SessionInfo {
  token: string;
  version: string;
  workspace_root: string;
  network_policy: string;
}
