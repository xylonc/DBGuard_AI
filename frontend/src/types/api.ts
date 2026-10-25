// TypeScript interfaces matching DBGuardAI OpenAPI schemas

export type FindingStatus =
  | 'PASS'
  | 'FAIL'
  | 'MANUAL'
  | 'NEEDS_CAPABILITY'
  | 'NOT_COLLECTED'
  | 'STALE'
  | 'ERROR'
  | 'MANUAL_REVIEW'
  | 'GAPPED';

export type HandoffLifecycle = 'PREPARED' | 'RUNNING' | 'FINISHED' | 'REJECTED';
export type SandboxResult = 'VERIFIED' | 'FAILED' | 'NEEDS_REVIEW' | 'CLEANUP_FAILED';
export type BundleStatus = 'READY' | 'PENDING' | 'UNAVAILABLE' | 'EXPIRED';
export type RetryMode = 'repeat' | 'adaptive';

export interface EvidenceReference {
  document_id: string;
  title: string;
  type: string;
  approved: boolean;
  approval_note?: string;
}

export interface TemplateReference {
  template_name: string;
  version: number;
  environment: string;
  approved: boolean;
  approved_by?: string;
  approval_note?: string;
}

export interface Finding {
  control_id: string;
  title: string;
  observed_value?: string;
  expected_value?: string;
  operator?: string;
  status: FindingStatus;
  upstream_status?: FindingStatus;
  evidence?: EvidenceReference[];
  template?: TemplateReference;
  description?: string;
  rationale?: string;
  supported_fix?: boolean;
}

export interface CollectionGap {
  section: string;
  reason: string;
  remediation?: string;
}

export interface ControlMetadata {
  id: string;
  title: string;
  type: 'automated' | 'needs_capability' | 'manual';
  description?: string;
}

export interface AssessmentSummary {
  pass: number;
  fail: number;
  manual: number;
  needs_capability: number;
  not_collected: number;
  stale: number;
  error: number;
}

export interface AssessmentReport {
  snapshot_id: string;
  benchmark_id: string;
  assessed_at: string;
  summary: AssessmentSummary;
  findings: Finding[];
  upstream_report?: {
    findings: Finding[];
    summary: AssessmentSummary;
  };
  gaps?: CollectionGap[];
}

export interface SnapshotUploadResponse {
  snapshot_id: string;
  snapshot_hash: string;
  target_id: string;
  database: string;
  schema_version?: string;
  collected_at: string;
  gap_count: number;
  status: 'stored';
}

export interface SnapshotContextResponse {
  snapshot_id: string;
  target_id: string;
  database: string;
  postgresql_version: string;
  deployment_type: string;
  snapshot_hash?: string;
  collected_at: string;
  gaps: CollectionGap[];
  available_sections: string[];
  unavailable_sections: string[];
}

export interface PrepareRequest {
  snapshot_id: string;
  benchmark_id: string;
  template_version: number;
  evidence_ids: string[];
  environment: string;
  retry_mode: RetryMode;
  retry_template_versions: number[];
  assessment?: AssessmentReport;
}

export interface SandboxHandoff {
  handoff_id: string;
  snapshot_id: string;
  benchmark_id: string;
  control_id: string;
  template_name: string;
  template_version: number;
  evidence_ids: string[];
  environment: string;
  retry_mode: RetryMode;
  max_attempts: number;
}

export interface AttemptEvidence {
  attempt_number: number;
  before_value?: string;
  after_value?: string;
  rollback_value?: string;
  applied_candidate?: string;
  llm_review?: string;
  health_status?: string;
  cleanup_status?: string;
  stage_timestamps?: Record<string, string>;
}

export interface HandoffStatus {
  handoff_id: string;
  lifecycle: HandoffLifecycle;
  result?: SandboxResult;
  attempt_count: number;
  max_attempts: number;
  attempts: AttemptEvidence[];
  review_bundle?: {
    url?: string;
    status: BundleStatus;
    contents?: string[];
  };
  error?: string;
  reviewer_invoked?: boolean;
}

export interface KnowledgeIngestRequest {
  title: string;
  content: string;
  document_type: string;
  environment?: string;
  tags?: string[];
}

export interface KnowledgeIngestResponse {
  document_id: string;
  title: string;
  status: 'draft' | 'approved';
  ingested_at: string;
}

export interface KnowledgeSearchResult {
  chunk_id: string;
  document_id: string;
  section: string;
  content: string;
  source_document_title: string;
  source_document_version?: string;
  source_url?: string;
  similarity_score: number;
}

export interface KnowledgeSearchResponse {
  status: string;
  results: KnowledgeSearchResult[];
}

export interface TemplateIngestRequest {
  template_name: string;
  sql: string;
  environment: string;
  description?: string;
}

export interface TemplateIngestResponse {
  template_name: string;
  version: number;
  status: 'draft' | 'approved';
}

export interface RemediationProposalRequest {
  control_id: string;
  snapshot_id: string;
  benchmark_id: string;
  template_name?: string;
}

export interface RemediationProposal {
  control_id: string;
  template_name: string;
  template_version: number;
  rendered_sql: string;
  evidence_ids: string[];
  warnings: string[];
  approved: boolean;
}

export interface ServiceHealth {
  service: string;
  url: string;
  status: 'healthy' | 'degraded' | 'unavailable' | 'unknown';
  checked_at?: string;
  error?: string;
}

// UI-specific types

export type StepStatus = 'not-started' | 'running' | 'needs-attention' | 'complete';

export type NavView = 'home' | 'workflows' | 'library' | 'settings';

export type AppMode = 'prototype' | 'connected';

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  toolActivity?: ToolActivity[];
  citations?: Citation[];
  isError?: boolean;
}

export interface ToolActivity {
  tool_name: string;
  status: 'running' | 'done' | 'error';
  input?: Record<string, unknown>;
  output?: Record<string, unknown>;
  error?: string;
}

export interface Citation {
  document_id: string;
  title: string;
  snippet?: string;
}

export interface ChatContext {
  benchmark_id?: string;
  snapshot_id?: string;
  control_id?: string;
  handoff_id?: string;
  run_id?: string;
  environment?: string;
  stage?: number;
}

export interface ServiceConfig {
  mainApi: string;
  demoApi: string;
  composeApi: string;
  hermesApi: string;
  mcpApi: string;
}
