import { useState, useRef } from 'react';
import { useWorkflow } from '@/store/workflowStore';
import { protoAdapter, ConnectedAdapter, ApiError } from '@/adapters/apiAdapter';
import type { SnapshotContextResponse, AssessmentReport } from '@/types/api';
import { StatusBadge } from '@/components/shared/StatusBadge';
import { LoadingState, ErrorState, NotConnectedState } from '@/components/shared/EmptyState';
import { IconUpload, IconAlertTriangle, IconPlay } from '@/components/shared/icons';

export function RecollectView() {
  const { state, dispatch } = useWorkflow();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [targetSnapshot, setTargetSnapshot] = useState<SnapshotContextResponse | null>(null);
  const [targetAssessment, setTargetAssessment] = useState<AssessmentReport | null>(null);
  const [assessing, setAssessing] = useState(false);
  const [assessError, setAssessError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleFile(file: File) {
    setError(null);
    setTargetSnapshot(null);
    setTargetAssessment(null);
    setLoading(true);
    try {
      const raw = JSON.parse(await file.text());
      const result = state.mode === 'prototype'
        ? await protoAdapter.uploadSnapshot(raw)
        : await new ConnectedAdapter(state.serviceConfig.mainApi).uploadSnapshot(raw);
      const ctx = state.mode === 'prototype'
        ? await protoAdapter.getSnapshot(result.snapshot_id)
        : await new ConnectedAdapter(state.serviceConfig.mainApi).getSnapshot(result.snapshot_id);
      setTargetSnapshot(ctx);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Upload failed');
    } finally { setLoading(false); }
  }

  async function runTargetAssessment() {
    if (!targetSnapshot) return;
    setAssessError(null);
    setAssessing(true);
    try {
      const result = state.mode === 'prototype'
        ? await protoAdapter.getSpecAssessment(targetSnapshot.snapshot_id, state.benchmarkId)
        : await new ConnectedAdapter(state.serviceConfig.mainApi).getSpecAssessment(targetSnapshot.snapshot_id, state.benchmarkId);
      setTargetAssessment(result);
    } catch (e) {
      setAssessError(e instanceof ApiError ? e.message : 'Assessment failed');
    } finally { setAssessing(false); }
  }

  // Source assessment findings from store
  const sourceFindings = state.assessment?.findings ?? [];
  // Final attempt = highest attempt_number
  const sandboxAttempts = state.handoffStatus?.attempts ?? [];
  const sandboxAttempt = sandboxAttempts.length
    ? sandboxAttempts.reduce((max, a) => a.attempt_number > max.attempt_number ? a : max, sandboxAttempts[0])
    : undefined;
  const sandboxControlId = state.chatContext.control_id;

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="w-6 h-6 rounded-full bg-teal-600 text-white text-xs font-bold flex items-center justify-center">7</span>
          <h1 className="text-lg font-semibold text-slate-800">Recollect & reassess target</h1>
        </div>
        <p className="text-sm text-slate-500">After the DBA applies the reviewed fix outside this application, collect a new snapshot from the target and reassess.</p>
      </div>

      {/* Workflow instructions */}
      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h2 className="text-sm font-semibold text-slate-700 mb-3">How target verification works</h2>
        <ol className="space-y-2 text-xs text-slate-600 list-none">
          {[
            'DBA applies the reviewed fix using harden.sh from the bundle (outside this application)',
            'Engineer runs the collector again against the same target PostgreSQL source',
            'Upload the new snapshot JSON below',
            'Run assessment against the new snapshot using the same benchmark',
            'Compare the four result contexts side by side',
          ].map((step, i) => (
            <li key={i} className="flex items-start gap-2.5">
              <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-500 text-[10px] font-bold flex items-center justify-center flex-shrink-0">{i + 1}</span>
              {step}
            </li>
          ))}
        </ol>
        <div className="mt-3 rounded-lg border border-red-100 bg-red-50 px-3 py-2 text-[11px] text-red-600 flex items-start gap-1.5">
          <IconAlertTriangle size={12} className="mt-0.5 flex-shrink-0" />
          Never label a sandbox PASS as a production PASS. Source changes require independent recollection and fresh assessment.
        </div>
      </div>

      {/* Upload target snapshot */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <h2 className="text-sm font-semibold text-slate-700">Upload target snapshot (post-fix)</h2>
        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={e => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
          onClick={() => fileRef.current?.click()}
          className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors
            ${dragOver ? 'border-teal-400 bg-teal-50' : 'border-slate-200 hover:border-teal-300 hover:bg-slate-50'}`}
        >
          <input ref={fileRef} type="file" accept=".json" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
          <IconUpload size={20} className="text-slate-300 mx-auto mb-2" />
          <p className="text-sm text-slate-500">Drop new snapshot.json (target, after DBA fix)</p>
          <p className="text-[11px] text-slate-400 mt-1">Must match source identity and spec context</p>
        </div>

        {loading && <LoadingState label="Processing target snapshot…" />}
        {error && <ErrorState message="Upload failed" detail={error} />}

        {targetSnapshot && (
          <div className="space-y-3">
            <div className="rounded-lg border border-teal-200 bg-teal-50 p-3 text-xs text-teal-700">
              Target snapshot loaded: <span className="font-mono">{targetSnapshot.snapshot_id}</span>
              <span className="text-[10px] ml-2 text-teal-500">· {targetSnapshot.target_id}</span>
              <span className="text-[10px] ml-2 text-teal-500">· {new Date(targetSnapshot.collected_at).toLocaleString()}</span>
            </div>

            {!targetAssessment && !assessing && (
              <div>
                <p className="text-xs text-slate-500 mb-2">Snapshot imported but not yet assessed. Run the assessment to populate the comparison.</p>
                <button
                  onClick={runTargetAssessment}
                  className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-teal-600 text-white text-xs font-medium hover:bg-teal-700 transition-colors"
                >
                  <IconPlay size={12} />
                  Run target assessment
                  {state.mode === 'prototype' && <span className="text-teal-200 text-[10px]">(simulated)</span>}
                </button>
              </div>
            )}

            {assessing && <LoadingState label="Running assessment on target snapshot…" />}
            {assessError && <ErrorState message="Assessment failed" detail={assessError} />}

            {targetAssessment && (
              <div className="rounded-lg border border-green-200 bg-green-50 px-3 py-2 text-[11px] text-green-700">
                Assessment complete — {targetAssessment.summary.pass} PASS · {targetAssessment.summary.fail} FAIL
              </div>
            )}
          </div>
        )}
      </div>

      {/* Four-context comparison */}
      {(sourceFindings.length > 0 || state.mode === 'prototype') && (
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <h2 className="text-sm font-semibold text-slate-700 mb-1">Control comparison — four contexts</h2>
          <p className="text-[11px] text-slate-400 mb-4">Results are shown only if the corresponding assessment has been run. "—" means no data in this session.</p>

          {sourceFindings.length === 0 ? (
            <p className="text-xs text-slate-400">No source assessment in this session — run assessment in step 4 first.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs min-w-[700px]">
                <thead>
                  <tr className="border-b border-slate-200">
                    <th className="text-left px-3 py-2 font-medium text-slate-500 w-20">Control</th>
                    <th className="text-left px-3 py-2 font-medium text-slate-500">Title</th>
                    <th className="px-3 py-2 font-medium text-center text-blue-600">Original target</th>
                    <th className="px-3 py-2 font-medium text-center text-amber-600">After sandbox fix</th>
                    <th className="px-3 py-2 font-medium text-center text-slate-500">Sandbox rollback</th>
                    <th className="px-3 py-2 font-medium text-center text-teal-600">Target after DBA fix</th>
                  </tr>
                </thead>
                <tbody>
                  {sourceFindings.map((f, i) => {
                    const isSandboxControl = f.control_id === sandboxControlId;
                    const afterSandbox = isSandboxControl && sandboxAttempt
                      ? (sandboxAttempt.after_value != null ? 'PASS' : null)
                      : null;
                    const rollback = isSandboxControl && sandboxAttempt
                      ? (sandboxAttempt.rollback_value != null ? f.upstream_status ?? f.status : null)
                      : null;
                    const targetResult = targetAssessment?.findings.find(tf => tf.control_id === f.control_id);

                    return (
                      <tr key={f.control_id} className={`border-b border-slate-100 ${i % 2 === 0 ? 'bg-white' : 'bg-slate-50/40'}`}>
                        <td className="px-3 py-2 font-mono text-slate-600 whitespace-nowrap">{f.control_id}</td>
                        <td className="px-3 py-2 text-slate-700"><span className="line-clamp-1">{f.title}</span></td>
                        <td className="px-3 py-2 text-center">
                          <StatusBadge status={f.upstream_status ?? f.status} />
                        </td>
                        <td className="px-3 py-2 text-center">
                          {afterSandbox
                            ? <StatusBadge status={afterSandbox} />
                            : <span className="text-[10px] text-slate-300 font-mono">—</span>}
                        </td>
                        <td className="px-3 py-2 text-center">
                          {rollback
                            ? <StatusBadge status={rollback} />
                            : <span className="text-[10px] text-slate-300 font-mono">—</span>}
                        </td>
                        <td className="px-3 py-2 text-center">
                          {targetResult
                            ? <StatusBadge status={targetResult.upstream_status ?? targetResult.status} />
                            : <span className="text-[10px] text-slate-300 font-mono">awaiting</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      <NotConnectedState feature="Automated target collection & verified snapshot comparison workflow" />

      {/* Return to home */}
      <button
        onClick={() => dispatch({ type: 'SET_VIEW', view: 'home' })}
        className="text-xs text-slate-500 hover:text-teal-600 underline transition-colors"
      >
        Return to Home
      </button>
    </div>
  );
}
