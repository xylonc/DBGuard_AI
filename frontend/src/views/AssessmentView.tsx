import { useState, useEffect } from 'react';
import { useWorkflow } from '@/store/workflowStore';
import { protoAdapter, ConnectedAdapter, ApiError } from '@/adapters/apiAdapter';
import type { AssessmentReport, Finding } from '@/types/api';
import { ControlTable } from '@/components/shared/ControlTable';
import { StatusBadge } from '@/components/shared/StatusBadge';
import { LoadingState, ErrorState } from '@/components/shared/EmptyState';
import { IconArrowRight, IconShield, IconPlay } from '@/components/shared/icons';
import { MOCK_SNAPSHOT_ID } from '@/adapters/mockData';

function SummaryCard({ label, count, status }: { label: string; count: number; status?: string }) {
  const colors: Record<string, string> = {
    pass: 'text-green-600', fail: 'text-red-600', needs_capability: 'text-purple-600',
    not_collected: 'text-slate-400', manual: 'text-amber-600', default: 'text-slate-500',
  };
  const c = colors[status ?? 'default'];
  return (
    <div className="bg-white rounded-lg border border-slate-200 p-3 text-center">
      <p className={`text-xl font-bold ${c} font-mono`}>{count}</p>
      <p className="text-[10px] text-slate-400 mt-0.5">{label}</p>
    </div>
  );
}

export function AssessmentView() {
  const { state, dispatch, setWorkflowStep } = useWorkflow();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [assessment, setAssessment] = useState<AssessmentReport | null>(state.assessment);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const snapshotId = state.mode === 'prototype'
    ? (state.snapshotId ?? MOCK_SNAPSHOT_ID)
    : state.snapshotId;

  async function runAssessment() {
    if (!snapshotId) return;
    setLoading(true);
    setError(null);
    try {
      const result = state.mode === 'prototype'
        ? await protoAdapter.getSpecAssessment(snapshotId, state.benchmarkId)
        : await new ConnectedAdapter(state.serviceConfig.mainApi).getSpecAssessment(snapshotId, state.benchmarkId);
      setAssessment(result);
      dispatch({ type: 'SET_ASSESSMENT', assessment: result });
      dispatch({ type: 'COMPLETE_STEP', step: 4 });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Assessment failed');
    } finally { setLoading(false); }
  }

  useEffect(() => {
    if (!assessment) { void runAssessment(); }
  }, []);

  function handleSelectControl(controlId: string) {
    const f = assessment?.findings.find(f => f.control_id === controlId) ?? null;
    setSelectedFinding(f);
    dispatch({ type: 'SET_SELECTED_CONTROL', id: controlId });
    dispatch({ type: 'SET_CHAT_CONTEXT', context: { control_id: controlId } });
  }

  async function prepareSandbox(finding: Finding) {
    if (!finding.supported_fix) return;
    setWorkflowStep(5);
    dispatch({ type: 'SET_VIEW', view: 'workflows' });
    dispatch({ type: 'SET_CHAT_CONTEXT', context: { control_id: finding.control_id } });
  }

  if (!snapshotId) {
    return (
      <div className="p-6 max-w-5xl mx-auto">
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-xs text-amber-700">
          <p className="font-medium">No snapshot imported</p>
          <p className="mt-1">Import a snapshot in step 3 before running an assessment. No mock ID is sent to the real API.</p>
          <button
            onClick={() => { setWorkflowStep(3); dispatch({ type: 'SET_VIEW', view: 'workflows' }); }}
            className="mt-2 px-3 py-1.5 rounded-lg bg-amber-600 text-white text-xs font-medium hover:bg-amber-700 transition-colors"
          >
            Go to Import snapshot
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-6 h-6 rounded-full bg-teal-600 text-white text-xs font-bold flex items-center justify-center">4</span>
            <h1 className="text-lg font-semibold text-slate-800">Assess & review proposed fixes</h1>
          </div>
          <p className="text-sm text-slate-500">
            <span className="font-mono text-xs text-slate-600">{snapshotId}</span>
            {' '}·{' '}
            <span className="font-mono text-xs text-slate-600">{state.benchmarkId}</span>
          </p>
        </div>
        <button
          onClick={runAssessment}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs border border-slate-200 rounded-lg text-slate-600 hover:bg-slate-50 disabled:opacity-50 transition-colors"
        >
          <IconShield size={12} />
          Re-assess
        </button>
      </div>

      {loading && <LoadingState label="Running spec assessment…" />}
      {error && <ErrorState message="Assessment failed" detail={error} onRetry={runAssessment} />}

      {assessment && !loading && (
        <>
          {/* Summary */}
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
            <SummaryCard label="PASS" count={assessment.summary.pass} status="pass" />
            <SummaryCard label="FAIL" count={assessment.summary.fail} status="fail" />
            <SummaryCard label="MANUAL" count={assessment.summary.manual} status="manual" />
            <SummaryCard label="NEEDS CAP." count={assessment.summary.needs_capability} status="needs_capability" />
            <SummaryCard label="NOT COLLECTED" count={assessment.summary.not_collected} status="not_collected" />
            <SummaryCard label="ERROR" count={assessment.summary.error} />
          </div>

          {/* Note about upstream_report */}
          <div className="rounded-lg border border-blue-100 bg-blue-50 px-3 py-2 text-[11px] text-blue-700">
            <strong>Authoritative results</strong> come from <code className="bg-blue-100 px-1 rounded">assessment.upstream_report</code>.
            The <code className="bg-blue-100 px-1 rounded">findings</code> field maps some states to MANUAL_REVIEW/GAPPED for convenience but does not override the upstream result shown here.
          </div>

          {/* Control table */}
          <div className="bg-white rounded-xl border border-slate-200 p-5">
            <h2 className="text-sm font-semibold text-slate-700 mb-3">Control findings</h2>
            <ControlTable
              findings={assessment.findings}
              onSelectControl={handleSelectControl}
              selectedControlId={state.selectedControlId}
            />
          </div>

          {/* Selected control detail / fix panel */}
          {selectedFinding && (
            <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-semibold text-slate-700">{selectedFinding.control_id}</span>
                  <StatusBadge status={selectedFinding.upstream_status ?? selectedFinding.status} size="md" />
                </div>
              </div>
              <p className="text-sm text-slate-700">{selectedFinding.title}</p>

              {selectedFinding.status === 'FAIL' && (
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="bg-red-50 rounded-lg p-3">
                    <p className="text-red-600 text-[10px] font-mono mb-1">OBSERVED</p>
                    <p className="font-mono text-red-700">{selectedFinding.observed_value ?? '—'}</p>
                  </div>
                  <div className="bg-green-50 rounded-lg p-3">
                    <p className="text-green-600 text-[10px] font-mono mb-1">EXPECTED</p>
                    <p className="font-mono text-green-700">{selectedFinding.expected_value ?? '—'}</p>
                  </div>
                </div>
              )}

              {/* Fix button */}
              <div>
                {selectedFinding.supported_fix ? (
                  <div className="space-y-2">
                    <div className="rounded-lg border border-teal-200 bg-teal-50 p-3 text-xs">
                      <p className="text-teal-700 font-medium">Supported fix available</p>
                      {selectedFinding.template && (
                        <div className="mt-1 space-y-0.5 font-mono text-teal-600">
                          <p>Template: {selectedFinding.template.template_name} v{selectedFinding.template.version}</p>
                          <p>Environment: {selectedFinding.template.environment}</p>
                          <p>Approved by: {selectedFinding.template.approved_by}</p>
                        </div>
                      )}
                      {selectedFinding.template?.approval_note && (
                        <p className="text-[10px] text-orange-600 font-mono mt-1">{selectedFinding.template.approval_note}</p>
                      )}
                    </div>
                    <button
                      onClick={() => prepareSandbox(selectedFinding)}
                      className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-600 text-white text-xs font-medium hover:bg-teal-700 transition-colors"
                    >
                      <IconPlay size={12} />
                      Test fix in sandbox
                      <IconArrowRight size={12} />
                    </button>
                  </div>
                ) : (
                  <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-200 text-xs text-slate-400 cursor-not-allowed">
                    Fix: Not supported yet for {selectedFinding.control_id}
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
