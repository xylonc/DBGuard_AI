import { useState } from 'react';
import { useWorkflow } from '@/store/workflowStore';
import { StatusBadge } from '@/components/shared/StatusBadge';
import { EmptyState } from '@/components/shared/EmptyState';
import { IconDownload, IconArrowRight, IconCheck, IconAlertTriangle, IconInfo, IconFlask } from '@/components/shared/icons';

const BUNDLE_CONTENTS = [
  { file: 'harden.sh', desc: 'Per-fix status/apply/rollback shell script. DBA runs this separately after review.' },
  { file: 'runner.py', desc: 'Python execution wrapper for harden.sh' },
  { file: 'fix.json', desc: 'Machine-readable fix definition and metadata' },
  { file: 'report.html', desc: 'Human-readable assessment report' },
  { file: 'evidence.json', desc: 'Complete sandbox test evidence' },
  { file: 'manifest.json', desc: 'Bundle metadata and checksums' },
  { file: 'README.txt', desc: 'Instructions for the DBA' },
];

export function DBAReviewView() {
  const { state, dispatch, setWorkflowStep } = useWorkflow();
  const hs = state.handoffStatus;
  const [jsonExported, setJsonExported] = useState(false);

  if (!hs) {
    return (
      <div className="p-6 max-w-4xl mx-auto">
        <EmptyState
          icon={<IconFlask size={32} />}
          title="No sandbox result available"
          description={state.mode === 'connected'
            ? 'Run a sandbox test in step 5 to generate evidence for DBA review. No data is loaded from mock in Connected mode.'
            : 'Complete the sandbox test in step 5 to view the DBA review bundle.'}
          action={
            <button
              onClick={() => { setWorkflowStep(5); dispatch({ type: 'SET_VIEW', view: 'workflows' }); }}
              className="px-3 py-1.5 rounded-lg bg-teal-600 text-white text-xs font-medium hover:bg-teal-700 transition-colors"
            >
              Go to sandbox test
            </button>
          }
        />
      </div>
    );
  }

  const bundle = hs.review_bundle;
  const isVerified = hs.result === 'VERIFIED';
  const bundleReady = bundle?.status === 'READY';
  // Final attempt = highest attempt_number (not necessarily index 0)
  const attempt = hs.attempts?.length
    ? hs.attempts.reduce((max, a) => a.attempt_number > max.attempt_number ? a : max, hs.attempts[0])
    : undefined;
  const hsRef = hs; // non-null after the early return

  function exportJson() {
    const data = JSON.stringify(hsRef, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dbguard-evidence-${hsRef.handoff_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setJsonExported(true);
  }

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="w-6 h-6 rounded-full bg-teal-600 text-white text-xs font-bold flex items-center justify-center">6</span>
          <h1 className="text-lg font-semibold text-slate-800">DBA review & bundle</h1>
        </div>
        <p className="text-xs text-slate-500 font-mono">Handoff: {hs.handoff_id}</p>
      </div>

      {/* Status badges — only shown when supported by API evidence */}
      <div className="flex flex-wrap gap-2">
        {isVerified && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-green-200 bg-green-50 text-xs text-green-700 font-medium">
            <IconCheck size={12} />
            Sandbox verified
          </div>
        )}
        {!isVerified && hs.result && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-red-200 bg-red-50 text-xs text-red-700 font-medium">
            <IconAlertTriangle size={12} />
            Result: {hs.result}
          </div>
        )}
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-amber-200 bg-amber-50 text-xs text-amber-700 font-medium">
          <IconAlertTriangle size={12} />
          DBA review required — source not changed
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-blue-200 bg-blue-50 text-xs text-blue-700 font-medium">
          <IconInfo size={12} />
          Sandbox only — no production change applied
        </div>
      </div>

      {/* Before / After / Rollback — only when attempt evidence exists */}
      {attempt ? (
        <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
          <h2 className="text-sm font-semibold text-slate-700">Test evidence summary</h2>
          <div className="grid grid-cols-3 gap-3 text-xs">
            <div className="rounded-lg border border-red-200 bg-red-50 p-3">
              <p className="text-[10px] font-mono text-red-500 mb-1">BEFORE (Original target)</p>
              <p className="font-mono text-red-700 text-sm">{attempt.before_value ?? '—'}</p>
              <p className="text-[10px] text-red-400 mt-1">Value read from source — unchanged</p>
            </div>
            <div className="rounded-lg border border-green-200 bg-green-50 p-3">
              <p className="text-[10px] font-mono text-green-500 mb-1">AFTER (Sandbox fix)</p>
              <p className="font-mono text-green-700 text-sm">{attempt.after_value ?? '—'}</p>
              <p className="text-[10px] text-green-400 mt-1">Result in disposable container</p>
            </div>
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p className="text-[10px] font-mono text-slate-500 mb-1">ROLLBACK (Sandbox)</p>
              <p className="font-mono text-slate-700 text-sm">{attempt.rollback_value ?? '—'}</p>
              <p className="text-[10px] text-slate-400 mt-1">
                {attempt.rollback_value != null ? 'Rollback succeeded — reversible' : 'No rollback value recorded'}
              </p>
            </div>
          </div>

          {attempt.applied_candidate && (
            <div>
              <p className="text-xs font-medium text-slate-600 mb-1.5">Approved candidate (sandbox only)</p>
              <pre className="text-[11px] font-mono bg-slate-900 text-green-300 rounded-lg px-3 py-2.5 overflow-x-auto">{attempt.applied_candidate}</pre>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <p className="text-slate-400 mb-0.5">Health check</p>
              <p className="font-mono text-slate-700">{attempt.health_status ?? '—'}</p>
            </div>
            <div>
              <p className="text-slate-400 mb-0.5">Cleanup status</p>
              <p className="font-mono text-slate-700">{attempt.cleanup_status ?? '—'}</p>
            </div>
          </div>
        </div>
      ) : (
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 text-xs text-slate-500">
          No attempt evidence available — attempts array is empty in the API response.
        </div>
      )}

      {/* Bundle download */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700">DBA review bundle</h2>
          {bundle && <StatusBadge status={bundle.status} size="md" />}
        </div>

        {bundleReady ? (
          <div className="space-y-3">
            <div className="rounded-lg border border-slate-200 overflow-hidden">
              {BUNDLE_CONTENTS.map((f, i) => (
                <div key={f.file} className={`flex items-start gap-3 px-3 py-2 text-xs ${i % 2 === 0 ? 'bg-white' : 'bg-slate-50/50'} ${i < BUNDLE_CONTENTS.length - 1 ? 'border-b border-slate-100' : ''}`}>
                  <span className="font-mono text-teal-700 flex-shrink-0 min-w-[100px]">{f.file}</span>
                  <span className="text-slate-500">{f.desc}</span>
                </div>
              ))}
            </div>
            {bundle.url && (
              <a
                href={bundle.url}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-600 text-white text-sm font-medium hover:bg-teal-700 transition-colors"
              >
                <IconDownload size={14} />
                Download bundle ZIP
              </a>
            )}
            <p className="text-[11px] text-slate-400">The DBA runs <code className="font-mono bg-slate-100 px-1 rounded">harden.sh</code> separately after review. No production Apply endpoint exists in this UI.</p>
          </div>
        ) : (
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-xs text-amber-700">
            <p className="font-medium">Bundle not available</p>
            <p className="mt-1">
              {isVerified
                ? 'The sandbox was VERIFIED but the bundle is unavailable. This may occur if the process restarted, the record expired, or bundle generation failed. Re-run the sandbox test to generate a new bundle.'
                : 'Bundle is only generated for VERIFIED results.'}
            </p>
            <p className="font-mono mt-1 text-[10px]">status: {bundle?.status ?? 'none'}</p>
          </div>
        )}
      </div>

      {/* JSON evidence export */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-slate-700">Evidence export (client-side)</h2>
        <p className="text-xs text-slate-500">Serializes the API response received in this browser session. Client-side only — not a server endpoint.</p>
        <button
          onClick={exportJson}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-200 text-xs text-slate-700 hover:bg-slate-50 transition-colors"
        >
          <IconDownload size={12} />
          Export evidence JSON
          {jsonExported && <IconCheck size={12} className="text-green-500" />}
        </button>
        <p className="text-[10px] text-amber-600 font-mono">Client-side export only — not a server download API</p>
      </div>

      <button
        onClick={() => { dispatch({ type: 'COMPLETE_STEP', step: 6 }); setWorkflowStep(7); dispatch({ type: 'SET_VIEW', view: 'workflows' }); }}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-600 text-white text-sm font-medium hover:bg-teal-700 transition-colors"
      >
        Continue to recollect & verify
        <IconArrowRight size={14} />
      </button>
    </div>
  );
}
