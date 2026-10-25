import type {
  SnapshotContextResponse, SnapshotUploadResponse, AssessmentReport,
  PrepareRequest, HandoffStatus, KnowledgeIngestRequest,
  KnowledgeIngestResponse, KnowledgeSearchResponse, TemplateIngestRequest,
  TemplateIngestResponse, RemediationProposalRequest, RemediationProposal,
  ServiceHealth
} from '@/types/api';
import {
  mockSnapshotContext, mockAssessment, mockHandoffVerified,
  mockKnowledgeSearch, MOCK_SNAPSHOT_ID, MOCK_HANDOFF_ID
} from './mockData';

const delay = (ms: number) => new Promise(r => setTimeout(r, ms));
const rand = (min: number, max: number) => Math.random() * (max - min) + min;

class ApiError extends Error {
  constructor(public status: number, message: string, public detail?: unknown) {
    super(message);
    this.name = 'ApiError';
  }
}

async function checkedFetch(url: string, options?: RequestInit): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', ...(options?.headers ?? {}) } });
  } catch (e) {
    throw new ApiError(0, `Network error — cannot reach ${url}. Check that the service is running and the URL is correct.`);
  }
  if (!res.ok) {
    let detail: unknown;
    try { detail = await res.json(); } catch { /* ignore */ }
    const msg = (detail as { detail?: string })?.detail ?? res.statusText;
    throw new ApiError(res.status, `HTTP ${res.status}: ${msg}`, detail);
  }
  return res.json();
}

// ──────────────────────────────────────────────
// Prototype adapter — returns mock data with delays
// ──────────────────────────────────────────────

export class PrototypeAdapter {
  async health(baseUrl: string): Promise<ServiceHealth> {
    await delay(rand(80, 200));
    return { service: 'Main API', url: baseUrl, status: 'unknown', checked_at: new Date().toISOString() };
  }

  async uploadSnapshot(_body: unknown): Promise<SnapshotUploadResponse> {
    await delay(rand(200, 400));
    return {
      snapshot_id: MOCK_SNAPSHOT_ID,
      snapshot_hash: 'sha256-proto-abc123def456',
      target_id: 'pg17-dev.internal:5432/appdb',
      database: 'appdb',
      schema_version: 'v0.3',
      collected_at: new Date().toISOString(),
      gap_count: 1,
      status: 'stored',
    };
  }

  async getSnapshot(_id: string): Promise<SnapshotContextResponse> {
    await delay(rand(150, 300));
    return mockSnapshotContext;
  }

  async getSpecAssessment(_snapshotId: string, _benchmarkId?: string): Promise<AssessmentReport> {
    await delay(rand(200, 500));
    return mockAssessment;
  }

  async prepareHandoff(_req: PrepareRequest): Promise<{ handoff_id: string }> {
    await delay(rand(300, 600));
    return { handoff_id: MOCK_HANDOFF_ID };
  }

  async runHandoff(_handoffId: string): Promise<HandoffStatus> {
    await delay(rand(1500, 3000));
    return mockHandoffVerified;
  }

  async getHandoffStatus(_handoffId: string): Promise<HandoffStatus> {
    await delay(rand(100, 200));
    return mockHandoffVerified;
  }

  async getBundle(runId: string): Promise<{ url: string; status: string; contents: string[] }> {
    await delay(rand(100, 200));
    return {
      url: `/api/v1/sandbox/runs/${runId}/bundle`,
      status: 'READY',
      contents: ['harden.sh', 'runner.py', 'fix.json', 'report.html', 'evidence.json', 'manifest.json', 'README.txt'],
    };
  }

  async searchKnowledge(_query: string): Promise<KnowledgeSearchResponse> {
    await delay(rand(150, 300));
    return mockKnowledgeSearch;
  }

  async searchTemplates(_query: string): Promise<KnowledgeSearchResponse> {
    await delay(rand(150, 300));
    return {
      status: 'ok',
      results: [{
        chunk_id: 'tmpl-pg-set-log-connections-v1-chunk-1',
        document_id: 'tmpl-pg-set-log-connections',
        section: 'v1 · dev',
        content: "[Prototype] ALTER SYSTEM SET log_connections = 'on'; SELECT pg_reload_conf();",
        source_document_title: '[Prototype] pg_set_log_connections',
        source_document_version: '1',
        similarity_score: 0.99,
      }],
    };
  }

  async uploadKnowledge(_file: File): Promise<{ document_id: string; status: string }> {
    await delay(rand(300, 600));
    return { document_id: `doc-proto-${Date.now()}`, status: 'ingested' };
  }

  async ingestKnowledgeDocument(req: KnowledgeIngestRequest): Promise<KnowledgeIngestResponse> {
    await delay(rand(200, 400));
    return {
      document_id: `doc-proto-${Date.now()}`,
      title: req.title,
      status: 'draft',
      ingested_at: new Date().toISOString(),
    };
  }

  async approveKnowledge(_docId: string, _req: unknown): Promise<{ status: string }> {
    await delay(rand(200, 400));
    return { status: 'approved' };
  }

  async getKnowledgeDocument(docId: string): Promise<{ document_id: string; title: string; status: string }> {
    await delay(rand(100, 200));
    return { document_id: docId, title: '[Prototype] Knowledge document', status: 'approved' };
  }

  async approveTemplate(_name: string, _req: unknown): Promise<{ status: string }> {
    await delay(rand(200, 400));
    return { status: 'approved' };
  }

  async ingestTemplate(_req: TemplateIngestRequest): Promise<TemplateIngestResponse> {
    await delay(rand(200, 400));
    return { template_name: _req.template_name, version: 1, status: 'draft' };
  }

  async validateProposal(_req: RemediationProposalRequest): Promise<RemediationProposal> {
    await delay(rand(300, 600));
    return {
      control_id: _req.control_id,
      template_name: 'pg_set_log_connections',
      template_version: 1,
      rendered_sql: "[Prototype] ALTER SYSTEM SET log_connections = 'on'; SELECT pg_reload_conf();",
      evidence_ids: ['doc-ev-002', 'doc-ev-003'],
      warnings: [],
      approved: true,
    };
  }
}

// ──────────────────────────────────────────────
// Connected adapter — real HTTP, no mock fallbacks
// ──────────────────────────────────────────────

export class ConnectedAdapter {
  constructor(private baseUrl: string) {}

  async health(): Promise<ServiceHealth> {
    const start = Date.now();
    try {
      await checkedFetch(`${this.baseUrl}/api/v1/health`);
      return { service: 'Main API', url: this.baseUrl, status: 'healthy', checked_at: new Date().toISOString() };
    } catch (e) {
      return {
        service: 'Main API', url: this.baseUrl, status: 'unavailable',
        checked_at: new Date().toISOString(),
        error: e instanceof Error ? e.message : String(e),
      };
    }
  }

  async uploadSnapshot(body: unknown): Promise<SnapshotUploadResponse> {
    return checkedFetch(`${this.baseUrl}/api/v1/snapshots`, {
      method: 'POST', body: JSON.stringify(body),
    }) as Promise<SnapshotUploadResponse>;
  }

  async getSnapshot(id: string): Promise<SnapshotContextResponse> {
    return checkedFetch(`${this.baseUrl}/api/v1/snapshots/${id}`) as Promise<SnapshotContextResponse>;
  }

  async getSpecAssessment(snapshotId: string, benchmarkId = 'cis-pg17-v1.1.0'): Promise<AssessmentReport> {
    const raw = await checkedFetch(
      `${this.baseUrl}/api/v1/snapshots/${snapshotId}/spec-assessment?benchmark_id=${encodeURIComponent(benchmarkId)}`
    ) as { assessment?: AssessmentReport } & AssessmentReport;
    return raw.assessment ?? raw;
  }

  async prepareHandoff(req: PrepareRequest): Promise<{ handoff_id: string }> {
    return checkedFetch(`${this.baseUrl}/api/v1/sandbox/handoffs`, {
      method: 'POST', body: JSON.stringify(req),
    }) as Promise<{ handoff_id: string }>;
  }

  async runHandoff(handoffId: string): Promise<HandoffStatus> {
    return checkedFetch(`${this.baseUrl}/api/v1/sandbox/handoffs/${handoffId}/run`, {
      method: 'POST',
    }) as Promise<HandoffStatus>;
  }

  async getHandoffStatus(handoffId: string): Promise<HandoffStatus> {
    return checkedFetch(`${this.baseUrl}/api/v1/sandbox/handoffs/${handoffId}`) as Promise<HandoffStatus>;
  }

  async getBundle(runId: string): Promise<{ url: string; status: string }> {
    const url = `${this.baseUrl}/api/v1/sandbox/runs/${runId}/bundle`;
    const res = await fetch(url);
    if (!res.ok) throw new ApiError(res.status, `Bundle unavailable: HTTP ${res.status}`);
    // Endpoint returns a ZIP binary — return the resolved URL for download link
    return { url, status: 'READY' };
  }

  async searchKnowledge(query: string): Promise<KnowledgeSearchResponse> {
    return checkedFetch(`${this.baseUrl}/api/v1/knowledge/search?search_query=${encodeURIComponent(query)}`) as Promise<KnowledgeSearchResponse>;
  }

  async searchTemplates(query: string): Promise<KnowledgeSearchResponse> {
    return checkedFetch(`${this.baseUrl}/api/v1/templates/search?search_query=${encodeURIComponent(query)}`) as Promise<KnowledgeSearchResponse>;
  }

  async uploadKnowledge(file: File): Promise<{ document_id: string; status: string }> {
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch(`${this.baseUrl}/api/v1/knowledge/upload`, { method: 'POST', body: fd });
    if (!res.ok) throw new ApiError(res.status, `Upload failed: ${res.statusText}`);
    return res.json();
  }

  async ingestKnowledgeDocument(req: KnowledgeIngestRequest): Promise<KnowledgeIngestResponse> {
    return checkedFetch(`${this.baseUrl}/api/v1/knowledge/documents`, {
      method: 'POST', body: JSON.stringify(req),
    }) as Promise<KnowledgeIngestResponse>;
  }

  async approveKnowledge(docId: string, req: unknown): Promise<{ status: string }> {
    return checkedFetch(`${this.baseUrl}/api/v1/knowledge/documents/${docId}/approve`, {
      method: 'POST', body: JSON.stringify(req),
    }) as Promise<{ status: string }>;
  }

  async getKnowledgeDocument(docId: string): Promise<unknown> {
    return checkedFetch(`${this.baseUrl}/api/v1/knowledge/documents/${docId}`);
  }

  async approveTemplate(name: string, req: { version?: number } & Record<string, unknown>): Promise<{ status: string }> {
    const versionParam = req.version != null ? `?version=${req.version}` : '';
    return checkedFetch(`${this.baseUrl}/api/v1/templates/${encodeURIComponent(name)}/approve${versionParam}`, {
      method: 'POST', body: JSON.stringify(req),
    }) as Promise<{ status: string }>;
  }

  async ingestTemplate(req: TemplateIngestRequest): Promise<TemplateIngestResponse> {
    return checkedFetch(`${this.baseUrl}/api/v1/templates/ingest`, {
      method: 'POST', body: JSON.stringify(req),
    }) as Promise<TemplateIngestResponse>;
  }

  async validateProposal(req: RemediationProposalRequest): Promise<RemediationProposal> {
    return checkedFetch(`${this.baseUrl}/api/v1/proposals/validate-and-render`, {
      method: 'POST', body: JSON.stringify(req),
    }) as Promise<RemediationProposal>;
  }
}

export { ApiError };

export const protoAdapter = new PrototypeAdapter();
