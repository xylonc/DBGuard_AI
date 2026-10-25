import type {
  AssessmentReport, SnapshotContextResponse, HandoffStatus,
  KnowledgeSearchResponse, ChatMessage, ServiceHealth
} from '@/types/api';

const P = '[Prototype]';

export const MOCK_SNAPSHOT_ID = 'snap-proto-001';
export const MOCK_HANDOFF_ID = 'handoff-proto-001';
export const MOCK_BENCHMARK_ID = 'cis-pg17-v1.1.0';

export const mockSnapshotContext: SnapshotContextResponse = {
  snapshot_id: MOCK_SNAPSHOT_ID,
  target_id: 'pg17-dev.internal:5432/appdb',
  database: 'appdb',
  postgresql_version: '17.2',
  deployment_type: 'standalone',
  snapshot_hash: 'sha256-proto-abc123def456',
  collected_at: '2026-09-24T14:32:11Z',
  gaps: [
    { section: '3.1.14', reason: `${P} pgaudit extension not installed on source` },
  ],
  available_sections: ['3.1.16', '3.1.20', '3.1.21', '3.1.25', '6.9'],
  unavailable_sections: ['3.1.14'],
};

export const mockAssessment: AssessmentReport = {
  snapshot_id: MOCK_SNAPSHOT_ID,
  benchmark_id: MOCK_BENCHMARK_ID,
  assessed_at: '2026-09-24T14:35:02Z',
  summary: { pass: 3, fail: 2, manual: 0, needs_capability: 1, not_collected: 0, stale: 0, error: 0 },
  findings: [
    {
      control_id: '3.1.14',
      title: "Ensure 'log_min_messages' is Set to 'warning' or Stricter",
      observed_value: 'not collected',
      expected_value: 'warning',
      operator: 'eq',
      status: 'NEEDS_CAPABILITY',
      upstream_status: 'NEEDS_CAPABILITY',
      description: `${P} Server log message level cannot be collected without the pgaudit extension on source. Control skipped.`,
      supported_fix: false,
      evidence: [],
    },
    {
      control_id: '3.1.16',
      title: "Ensure 'debug_print_parse' is Disabled",
      observed_value: 'off',
      expected_value: 'off',
      operator: 'eq',
      status: 'PASS',
      upstream_status: 'PASS',
      description: `${P} debug_print_parse is correctly disabled. Parse tree output is suppressed from server logs.`,
      supported_fix: false,
      evidence: [{ document_id: 'doc-ev-001', title: `${P} CIS PG17 Section 3.1.16 Evidence`, type: 'evidence', approved: true }],
    },
    {
      control_id: '3.1.20',
      title: 'Ensure \'log_connections\' is Enabled',
      observed_value: 'off',
      expected_value: 'on',
      operator: 'eq',
      status: 'FAIL',
      upstream_status: 'FAIL',
      description: `${P} log_connections should be enabled to log each attempted connection to the server.`,
      supported_fix: true,
      template: {
        template_name: 'pg_set_log_connections',
        version: 1,
        environment: 'dev',
        approved: true,
        approved_by: 'DEMO_FIXTURE_ONLY — not human approval',
        approval_note: `${P} Fixture approval for prototype demonstration only.`,
      },
      evidence: [
        { document_id: 'doc-ev-002', title: `${P} CIS PG17 Section 3.1.20 Remediation Evidence`, type: 'evidence', approved: true },
        { document_id: 'doc-ev-003', title: `${P} log_connections security rationale`, type: 'knowledge', approved: true },
      ],
    },
    {
      control_id: '3.1.21',
      title: 'Ensure \'log_disconnections\' is Enabled',
      observed_value: 'on',
      expected_value: 'on',
      operator: 'eq',
      status: 'PASS',
      upstream_status: 'PASS',
      description: `${P} log_disconnections is correctly enabled.`,
      supported_fix: false,
      evidence: [{ document_id: 'doc-ev-004', title: `${P} CIS PG17 Section 3.1.21 Evidence`, type: 'evidence', approved: true }],
    },
    {
      control_id: '3.1.25',
      title: "Ensure 'log_statement' is Set Correctly",
      observed_value: 'none',
      expected_value: 'ddl',
      operator: 'eq',
      status: 'FAIL',
      upstream_status: 'FAIL',
      description: `${P} log_statement is set to 'none' — DDL statements are not logged. CIS PG17 requires at minimum 'ddl'.`,
      supported_fix: false,
      evidence: [],
    },
    {
      control_id: '6.9',
      title: 'Ensure the Minimum TLS Protocol Version is Configured Correctly',
      observed_value: 'TLSv1.2',
      expected_value: 'TLSv1.2',
      operator: 'gte',
      status: 'PASS',
      upstream_status: 'PASS',
      description: `${P} ssl_min_protocol_version is set to TLSv1.2, meeting the CIS minimum requirement.`,
      supported_fix: false,
      evidence: [{ document_id: 'doc-ev-005', title: `${P} TLS configuration evidence`, type: 'evidence', approved: true }],
    },
  ],
  upstream_report: {
    findings: [],
    summary: { pass: 3, fail: 2, manual: 0, needs_capability: 1, not_collected: 0, stale: 0, error: 0 },
  },
};

export const mockHandoffVerified: HandoffStatus = {
  handoff_id: MOCK_HANDOFF_ID,
  lifecycle: 'FINISHED',
  result: 'VERIFIED',
  attempt_count: 1,
  max_attempts: 3,
  reviewer_invoked: false,
  attempts: [
    {
      attempt_number: 1,
      before_value: 'off',
      after_value: 'on',
      rollback_value: 'off',
      applied_candidate: `${P} ALTER SYSTEM SET log_connections = 'on'; SELECT pg_reload_conf();`,
      health_status: 'healthy',
      cleanup_status: 'complete',
      stage_timestamps: {
        reconstruct: '2026-09-24T15:01:00Z',
        reproduce: '2026-09-24T15:01:12Z',
        apply: '2026-09-24T15:01:15Z',
        reload: '2026-09-24T15:01:16Z',
        reassess: '2026-09-24T15:01:22Z',
        health: '2026-09-24T15:01:24Z',
        rollback: '2026-09-24T15:01:26Z',
        verify_restored: '2026-09-24T15:01:28Z',
        cleanup: '2026-09-24T15:01:32Z',
      },
    },
  ],
  review_bundle: {
    url: `/api/v1/sandbox/runs/${MOCK_HANDOFF_ID}/bundle`,
    status: 'READY',
    contents: ['harden.sh', 'runner.py', 'fix.json', 'report.html', 'evidence.json', 'manifest.json', 'README.txt'],
  },
};

export const mockHandoffFailed: HandoffStatus = {
  handoff_id: 'handoff-proto-failed',
  lifecycle: 'FINISHED',
  result: 'FAILED',
  attempt_count: 3,
  max_attempts: 3,
  reviewer_invoked: true,
  attempts: [
    {
      attempt_number: 1,
      before_value: 'off',
      after_value: 'off',
      rollback_value: 'off',
      applied_candidate: `${P} ALTER SYSTEM SET log_connections = 'on';`,
      health_status: 'healthy',
      cleanup_status: 'complete',
    },
    {
      attempt_number: 2,
      before_value: 'off',
      after_value: 'off',
      health_status: 'healthy',
      cleanup_status: 'complete',
    },
    {
      attempt_number: 3,
      before_value: 'off',
      after_value: 'off',
      health_status: 'degraded',
      cleanup_status: 'complete',
    },
  ],
  error: `${P} All three attempts failed. No approved alternative template available. Manual review required.`,
  review_bundle: { status: 'UNAVAILABLE' },
};

export const mockKnowledgeSearch: KnowledgeSearchResponse = {
  status: 'ok',
  results: [
    {
      chunk_id: 'doc-ev-002-chunk-1',
      document_id: 'doc-ev-002',
      section: '3.1.20',
      content: `${P} Evidence supporting log_connections = on remediation for CIS PG17 v1.1.0 control 3.1.20. Enabling log_connections records every connection attempt, supporting audit and anomaly detection requirements.`,
      source_document_title: `${P} CIS PG17 Section 3.1.20 Remediation Evidence`,
      source_document_version: 'v1.1.0',
      similarity_score: 0.97,
    },
    {
      chunk_id: 'doc-ev-003-chunk-1',
      document_id: 'doc-ev-003',
      section: '3.1.20',
      content: `${P} log_connections security rationale. Enabling log_connections ensures every connection attempt is recorded, supporting audit and anomaly detection per CIS benchmark requirements.`,
      source_document_title: `${P} log_connections security rationale`,
      source_document_version: 'v1.0',
      similarity_score: 0.91,
    },
    {
      chunk_id: 'doc-ev-001-chunk-1',
      document_id: 'doc-ev-001',
      section: '3.1.16',
      content: `${P} Evidence confirming debug_print_parse = off is the required setting per CIS PG17 v1.1.0 control 3.1.16.`,
      source_document_title: `${P} CIS PG17 Section 3.1.16 Evidence`,
      source_document_version: 'v1.1.0',
      similarity_score: 0.84,
    },
  ],
};

export const mockServiceHealth: ServiceHealth[] = [
  { service: 'Main API', url: 'http://localhost:8011', status: 'unknown' },
  { service: 'Demo App', url: 'http://localhost:8010', status: 'unknown' },
  { service: 'Compose Backend', url: 'http://localhost:8000', status: 'unknown' },
  { service: 'HERMES API', url: 'http://localhost:8642', status: 'unknown' },
  { service: 'MCP Server', url: 'http://localhost:8001', status: 'unknown' },
];

let msgCounter = 0;
function msgId() { return `msg-${++msgCounter}-${Date.now()}`; }

export function makeMockChatResponse(userMessage: string, stage: number, controlId?: string): ChatMessage[] {
  const messages: ChatMessage[] = [];
  const now = new Date().toISOString();

  const lc = userMessage.toLowerCase();

  if (lc.includes('explain') && lc.includes('fail')) {
    const ctrl = controlId || '3.1.20';
    messages.push({
      id: msgId(),
      role: 'assistant',
      content: `${P} **Control ${ctrl} — FAIL explanation**\n\nThe observed value is \`off\` but the CIS PG17 v1.1.0 benchmark requires \`on\`. When \`log_connections\` is disabled, connection attempts are not logged, reducing visibility for audit and anomaly detection.\n\n**To remediate:** Set \`log_connections = 'on'\` via \`ALTER SYSTEM\` and reload the configuration. An approved template is available for control 3.1.20.`,
      timestamp: now,
      toolActivity: [
        { tool_name: 'get_snapshot_spec_assessment', status: 'done', input: { snapshot_id: MOCK_SNAPSHOT_ID, control_id: ctrl }, output: { status: 'FAIL', observed: 'off', expected: 'on' } },
      ],
      citations: [{ document_id: 'doc-ev-002', title: `${P} CIS PG17 3.1.20 Evidence` }],
    });
  } else if (lc.includes('approved evidence') || lc.includes('find evidence')) {
    messages.push({
      id: msgId(),
      role: 'assistant',
      content: `${P} **Approved evidence found**\n\nSearched the approved knowledge registry for control 3.1.20 (log_connections). Found 2 approved documents:\n\n1. **doc-ev-002** — CIS PG17 Section 3.1.20 Remediation Evidence (score: 0.97)\n2. **doc-ev-003** — log_connections security rationale (score: 0.91)\n\nThese document IDs can be included in a sandbox handoff preparation.`,
      timestamp: now,
      toolActivity: [
        { tool_name: 'search_approved_knowledge', status: 'done', input: { query: 'log_connections CIS 3.1.20' }, output: { total: 2 } },
      ],
      citations: [
        { document_id: 'doc-ev-002', title: `${P} CIS PG17 3.1.20 Evidence` },
        { document_id: 'doc-ev-003', title: `${P} log_connections rationale` },
      ],
    });
  } else if (lc.includes('prepare') || lc.includes('sandbox test') || lc.includes('test this fix')) {
    messages.push({
      id: msgId(),
      role: 'assistant',
      content: `${P} **Sandbox handoff prepared**\n\nPrepared a handoff for control 3.1.20 using approved template \`pg_set_log_connections\` v1 with evidence documents doc-ev-002 and doc-ev-003.\n\n**Handoff ID:** \`${MOCK_HANDOFF_ID}\`\n\nHandoff lifecycle: **PREPARED**. Use the "Run sandbox test" button or say "run sandbox test" to execute. The test creates a fresh PostgreSQL 17 container and applies the candidate fix.`,
      timestamp: now,
      toolActivity: [
        { tool_name: 'prepare_sandbox_handoff', status: 'done', input: { snapshot_id: MOCK_SNAPSHOT_ID, control_id: '3.1.20', template_name: 'pg_set_log_connections', version: 1 }, output: { handoff_id: MOCK_HANDOFF_ID, lifecycle: 'PREPARED' } },
      ],
    });
  } else if (lc.includes('run sandbox') || lc.includes('run the test')) {
    messages.push({
      id: msgId(),
      role: 'assistant',
      content: `${P} **Sandbox test started**\n\nRunning handoff \`${MOCK_HANDOFF_ID}\`. The test applies the approved candidate fix in a disposable PostgreSQL 17 container and verifies all scoped controls. This call is synchronous — the result will be returned when complete.\n\n*Note: The reviewer was not invoked because the first attempt succeeded. Reviewer invocation only occurs in adaptive mode after a failure.*`,
      timestamp: now,
      toolActivity: [
        { tool_name: 'run_sandbox_handoff', status: 'done', input: { handoff_id: MOCK_HANDOFF_ID }, output: { result: 'VERIFIED', lifecycle: 'FINISHED' } },
      ],
    });
  } else if (lc.includes('rollback') || lc.includes('explain the rollback')) {
    messages.push({
      id: msgId(),
      role: 'assistant',
      content: `${P} **Rollback result explanation**\n\nThe sandbox test included a rollback phase to verify the original state could be restored. After applying and verifying the fix, the candidate was rolled back:\n\n- Rollback value: \`off\` (original state)\n- Rollback status: ✓ Restored successfully\n- Cleanup: ✓ Container removed\n\nThis confirms the fix is reversible. The source database remains unchanged — only the DBA bundle documents the approved change.`,
      timestamp: now,
      toolActivity: [
        { tool_name: 'get_sandbox_handoff_status', status: 'done', input: { handoff_id: MOCK_HANDOFF_ID }, output: { result: 'VERIFIED', rollback_value: 'off' } },
      ],
    });
  } else if (lc.includes('dba bundle') || lc.includes('open the dba')) {
    messages.push({
      id: msgId(),
      role: 'assistant',
      content: `${P} **DBA Review Bundle**\n\nThe review bundle for handoff \`${MOCK_HANDOFF_ID}\` is **READY**.\n\nBundle contents:\n- \`harden.sh\` — per-fix status/apply/rollback script\n- \`runner.py\` — execution wrapper\n- \`fix.json\` — machine-readable fix definition\n- \`report.html\` — human-readable assessment report\n- \`evidence.json\` — complete test evidence\n- \`manifest.json\` — bundle metadata\n- \`README.txt\` — instructions for the DBA\n\nNavigate to the **DBA Review** tab to download the bundle. The DBA runs \`harden.sh\` separately after review — the browser UI has no production Apply endpoint.`,
      timestamp: now,
    });
  } else if (stage === 1) {
    messages.push({
      id: msgId(),
      role: 'assistant',
      content: `${P} **Benchmark & Requirements — Stage 1**\n\nCurrently installed benchmark: \`cis-pg17-v1.1.0\` with 6 sample specs (5 automated checks, 1 needs-capability control).\n\nYou can upload a CIS XLSX workbook via the drag-drop zone. After upload the workbook content will be ingested into draft knowledge — full spec generation from the workbook is a planned integration and is not yet available.\n\nWould you like me to explain any specific control?`,
      timestamp: now,
    });
  } else {
    messages.push({
      id: msgId(),
      role: 'assistant',
      content: `${P} **HERMES AI — Prototype mode**\n\nI'm the HERMES AI assistant. I can help at every stage of the DBGuard workflow.\n\nAvailable actions:\n- "Explain this failure" — explain a specific control failure\n- "Find approved evidence" — search the knowledge registry\n- "Prepare a sandbox test" — set up a handoff for control 3.1.20\n- "Test this fix" — run a prepared sandbox handoff\n- "Explain the rollback result" — interpret rollback evidence\n- "Open the DBA bundle" — describe bundle contents\n\n*Note: In Prototype mode, responses are mock data. In Connected mode, HERMES would route through a verified server-side adapter to the real HERMES API on port 8642.*`,
      timestamp: now,
    });
  }

  return messages;
}
