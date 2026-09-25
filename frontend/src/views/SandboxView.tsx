import { useState } from 'react';
import { useWorkflow } from '@/store/workflowStore';
import { protoAdapter, ConnectedAdapter, ApiError } from '@/adapters/apiAdapter';
import type { HandoffStatus, RetryMode } from '@/types/api';
import { StatusBadge } from '@/components/shared/StatusBadge';
import { LoadingState, ErrorState, NotConnectedState } from '@/components/shared/EmptyState';
import { IconPlay, IconArrowRight, IconChevronDown, IconChevronRight, IconAlertTriangle } from '@/components/shared/icons';
import { MOCK_SNAPSHOT_ID, MOCK_HANDOFF_ID } from '@/adapters/mockData';

const TIMELINE_STAGES = [
  { key: 'reconstruct',     label: 'Reconstruct source state',     desc: 'Apply scoped settings to fresh container' },
  { key: 'reproduce',       label: 'Reproduce failures',           desc: 'Confirm expected FAILs are present' },
  { key: 'apply',           label: 'Apply candidate fix',          desc: 'Execute approved template SQL' },
  { key: 'reload',          label: 'Reload configuration',         desc: 'pg_reload_conf()' },
  { key: 'reassess',        label: 'Reassess all scoped controls',  desc: 'Re-run spec assessment' },
  { key: 'health',          label: 'Check health',                 desc: 'Verify container operational' },
  { key: 'rollback',        label: 'Rollback',                     desc: 'Restore original settings' },
  { key: 'verify_restored', label: 'Verify restored state',        desc: 'Confirm rollback successful' },
  { key: 'cleanup',         label: 'Cleanup',                      desc: 'Remove disposable container' },
];

function TimelineStage({
  stage, isComplete, isRunning,
}: { stage: typeof TIMELINE_STAGES[0]; isComplete: boolean; isRunning: boolean }) {
  return (
    <div className={`flex items-start gap-3 py-2 ${isRunning ? 'opacity-100' : isComplete ? 'opacity-100' : 'opacity-40'}`}>
      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center flex-shrink-0 mt-0.5
        ${isComplete ? 'border-green-400 bg-green-400' : isRunning ? 'border-teal-400 bg-teal-50 animate-pulse' : 'border-slate-200 bg-white'}`}
      >
        {isComplete && (
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
        )}
      </div>
      <div>
        <p className={`text-xs font-medium ${isComplete ? 'text-slate-700' : isRunning ? 'text-teal-700' : 'text-slate-400'}`}>
          {stage.label}
        </p>
        <p className="text-[10px] text-slate-400">{stage.desc}</p>
      </div>
    </div>
  );
}

function AttemptCard({ attempt, number, isFinal }: { attempt: HandoffStatus['attempts'][0]; number: number; isFinal: boolean }) {
  const [open, setOpen] = useState(isFinal);

  return (
    <div className="border border-slate-200 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-4 py-2.5 bg-slate-50 text-xs text-slate-700 hover:bg-slate-100 transition-colors"
      >
        <span className="font-medium">Attempt {number}</span>
        {open ? <IconChevronDown size={12} /> : <IconChevronRight size={12} />}
      </button>
      {open && (
        <div className="p-4 grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
          {attempt.before_value !== undefined && (
            <div className="bg-red-50 rounded p-2">
              <p className="text-[10px] text-red-500 font-mono">BEFORE</p>
              <p className="font-mono text-red-700 mt-0.5">{attempt.before_value || '—'}</p>
            </div>
          )}
          {attempt.after_value !== undefined && (
            <div className="bg-green-50 rounded p-2">
              <p className="text-[10px] text-green-500 font-mono">AFTER</p>
              <p className="font-mono text-green-700 mt-0.5">{attempt.after_value || '—'}</p>
            </div>
          )}
          {attempt.rollback_value !== undefined && (
            <div className="bg-slate-50 rounded p-2">
              <p className="text-[10px] text-slate-500 font-mono">ROLLBACK</p>
              <p className="font-mono text-slate-700 mt-0.5">{attempt.rollback_value || '—'}</p>
            </div>
          )}
          {attempt.applied_candidate && (
            <div className="col-span-2 sm:col-span-3">
              <p className="text-[10px] text-slate-500 font-mono mb-1">APPLIED CANDIDATE</p>
              <pre className="text-[11px] font-mono bg-slate-900 text-green-300 rounded px-3 py-2 overflow-x-auto whitespace-pre-wrap">{attempt.applied_candidate}</pre>
            </div>
          )}
          {attempt.health_status && (
            <div>
              <p className="text-[10px] text-slate-500 font-mono">HEALTH</p>
              <p className="font-mono text-slate-700">{attempt.health_status}</p>
            </div>
          )}
          {attempt.cleanup_status && (
            <div>
              <p className="text-[10px] text-slate-500 font-mono">CLEANUP</p>
              <p className="font-mono text-slate-700">{attempt.cleanup_status}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function SandboxView() {
  const { state, dispatch, setWorkflowStep } = useWorkflow();
  const [retryMode, setRetryMode] = useState<RetryMode>('repeat');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [handoffStatus, setHandoffStatus] = useState<HandoffStatus | null>(state.handoffStatus);

  const snapshotId = state.snapshotId ?? MOCK_SNAPSHOT_ID;

  async function runSandboxTest() {
    if (loading) return;
    setLoading(true);
    setError(null);
    setHandoffStatus(null);

    try {
      let handoffId: string;

      if (state.mode === 'prototype') {
        const prep = await protoAdapter.prepareHandoff({
          snapshot_id: snapshotId,
          benchmark_id: state.benchmarkId,
          template_version: 1,
          evidence_ids: ['doc-ev-002', 'doc-ev-003'],
          environment: state.environment,
          retry_mode: retryMode,
          retry_template_versions: [],
        });
        handoffId = prep.handoff_id;
        dispatch({ type: 'SET_HANDOFF_ID', id: handoffId });
        dispatch({ type: 'SET_CHAT_CONTEXT', context: { handoff_id: handoffId } });

        const result = await protoAdapter.runHandoff(handoffId);
        setHandoffStatus(result);
        dispatch({ type: 'SET_HANDOFF_STATUS', status: result });
        if (result.result === 'VERIFIED') dispatch({ type: 'COMPLETE_STEP', step: 5 });
      } else {
        const adapter = new ConnectedAdapter(state.serviceConfig.mainApi);
        const prep = await adapter.prepareHandoff({
          snapshot_id: snapshotId,
          benchmark_id: state.benchmarkId,
          template_version: 1,
          evidence_ids: [],
          environment: state.environment,
          retry_mode: retryMode,
          retry_template_versions: [],
        });
        handoffId = prep.handoff_id;
        dispatch({ type: 'SET_HANDOFF_ID', id: handoffId });

        const result = await adapter.runHandoff(handoffId);
        setHandoffStatus(result);
        dispatch({ type: 'SET_HANDOFF_STATUS', status: result });
        if (result.result === 'VERIFIED') dispatch({ type: 'COMPLETE_STEP', step: 5 });
      }
    } catch (e) {
      if (e instanceof ApiError) {
        setError(`${e.message}${e.detail ? '\n' + JSON.stringify(e.detail, null, 2) : ''}`);
      } else {
        setError(e instanceof Error ? e.message : 'Sandbox test failed');
      }
    } finally {
      setLoading(false);
    }
  }

  const resultStatus = handoffStatus?.result;

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="w-6 h-6 rounded-full bg-teal-600 text-white text-xs font-bold flex items-center justify-center">5</span>
          <h1 className="text-lg font-semibold text-slate-800">Test in a disposable sandbox</h1>
        </div>
        <p className="text-sm text-slate-500">Applies the approved candidate fix in a fresh PostgreSQL 17 container. Maximum 3 attempts.</p>
      </div>

      {/* Configuration */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <h2 className="text-sm font-semibold text-slate-700">Test configuration</h2>

        <div className="grid grid-cols-2 gap-3 text-xs">
          <div>
            <p className="text-slate-400 mb-1">Snapshot</p>
            <p className="font-mono text-slate-700">{snapshotId.slice(0, 20)}…</p>
          </div>
          <div>
            <p className="text-slate-400 mb-1">Control</p>
            <p className="font-mono text-slate-700">{state.selectedControlId ?? '3.1.20'} — log_connections</p>
          </div>
          <div>
            <p className="text-slate-400 mb-1">Template</p>
            <p className="font-mono text-slate-700">pg_set_log_connections v1</p>
            <p className="text-[10px] text-orange-600 font-mono mt-0.5">DEMO_FIXTURE_ONLY — not human approval</p>
          </div>
          <div>
            <p className="text-slate-400 mb-1">Environment</p>
            <p className="font-mono text-slate-700">{state.environment}</p>
          </div>
        </div>

        {/* Retry mode */}
        <div>
          <p className="text-xs text-slate-600 font-medium mb-2">Retry mode</p>
          <div className="flex gap-3">
            {(['repeat', 'adaptive'] as RetryMode[]).map(m => (
              <label key={m} className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="retryMode"
                  value={m}
                  checked={retryMode === m}
                  onChange={() => setRetryMode(m)}
                  className="accent-teal-600"
                />
                <span className="text-xs text-slate-700 capitalize">{m}</span>
              </label>
            ))}
          </div>
          {retryMode === 'adaptive' && (
            <div className="mt-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] text-amber-700 flex items-start gap-1.5">
              <IconAlertTriangle size={12} className="mt-0.5 flex-shrink-0" />
              Adaptive mode requires a configured reviewer. The LLM may select a different eligible approved candidate after failure, or request manual review. Arbitrary LLM-generated SQL is never executed. The registry currently permits one active version per template name.
            </div>
          )}
        </div>

        <button
          onClick={runSandboxTest}
          disabled={loading || (handoffStatus?.lifecycle === 'RUNNING')}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-600 text-white text-sm font-medium hover:bg-teal-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <IconPlay size={14} />
          Run sandbox test
        </button>
      </div>

      {/* Loading / running state */}
      {loading && (
        <div className="bg-white rounded-xl border border-teal-200 p-5">
          <LoadingState label="Sandbox test running… (synchronous call — may take several minutes)" />
          <p className="text-[10px] text-slate-400 mt-3 font-mono">Detailed stage evidence is shown from the actual API response once complete. No live progress stream is available.</p>
        </div>
      )}

      {error && <ErrorState message="Sandbox test failed" detail={error} onRetry={() => setError(null)} />}

      {/* Result */}
      {handoffStatus && !loading && (
        <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <h2 className="text-sm font-semibold text-slate-700">Test result</h2>
            {resultStatus && <StatusBadge status={resultStatus} size="md" />}
            <StatusBadge status={handoffStatus.lifecycle} size="md" />
            <span className="text-xs text-slate-400">Attempt {handoffStatus.attempt_count}/{handoffStatus.max_attempts}</span>
          </div>

          {/* Important: HTTP 200 ≠ VERIFIED */}
          <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-[11px] text-slate-500">
            A completed HTTP request is not automatically VERIFIED. Execution status and acceptance status are separate.
            {handoffStatus.reviewer_invoked === false && resultStatus === 'VERIFIED' && (
              <span className="text-teal-600 font-medium"> Reviewer not invoked — first attempt passed.</span>
            )}
          </div>

          {handoffStatus.error && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">
              {handoffStatus.error}
            </div>
          )}

          {/* Attempt evidence */}
          {handoffStatus.attempts.length > 0 && (() => {
            const finalNum = Math.max(...handoffStatus.attempts.map(a => a.attempt_number));
            return (
              <div className="space-y-2">
                <p className="text-xs font-medium text-slate-600">Evidence by attempt</p>
                {handoffStatus.attempts.map((a) => (
                  <AttemptCard key={a.attempt_number} attempt={a} number={a.attempt_number} isFinal={a.attempt_number === finalNum} />
                ))}
              </div>
            );
          })()}

          {resultStatus === 'VERIFIED' && (
            <button
              onClick={() => { setWorkflowStep(6); dispatch({ type: 'SET_VIEW', view: 'workflows' }); }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-600 text-white text-sm font-medium hover:bg-teal-700 transition-colors"
            >
              Continue to DBA review
              <IconArrowRight size={14} />
            </button>
          )}
        </div>
      )}

      {state.mode === 'connected' && !handoffStatus && (
        <NotConnectedState feature="Live sandbox progress stream" />
      )}
    </div>
  );
}
