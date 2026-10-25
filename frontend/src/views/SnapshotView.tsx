import { useState, useRef } from 'react';
import { useWorkflow } from '@/store/workflowStore';
import { protoAdapter, ConnectedAdapter, ApiError } from '@/adapters/apiAdapter';
import type { SnapshotContextResponse } from '@/types/api';
import { IconUpload, IconArrowRight, IconDatabase } from '@/components/shared/icons';
import { LoadingState, ErrorState } from '@/components/shared/EmptyState';

export function SnapshotView() {
  const { state, dispatch, setWorkflowStep } = useWorkflow();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<SnapshotContextResponse | null>(null);
  const [knownId, setKnownId] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleFile(file: File) {
    setError(null);
    setLoading(true);
    try {
      let raw: unknown;
      try { raw = JSON.parse(await file.text()); } catch { throw new Error('File is not valid JSON'); }

      let result;
      if (state.mode === 'prototype') {
        result = await protoAdapter.uploadSnapshot(raw);
      } else {
        const adapter = new ConnectedAdapter(state.serviceConfig.mainApi);
        result = await adapter.uploadSnapshot(raw);
      }

      dispatch({ type: 'SET_SNAPSHOT_ID', id: result.snapshot_id });
      dispatch({ type: 'SET_CHAT_CONTEXT', context: { snapshot_id: result.snapshot_id } });

      const ctx = state.mode === 'prototype'
        ? await protoAdapter.getSnapshot(result.snapshot_id)
        : await new ConnectedAdapter(state.serviceConfig.mainApi).getSnapshot(result.snapshot_id);
      setSnapshot(ctx);
    } catch (e) {
      setError(e instanceof ApiError ? `${e.message}` : e instanceof Error ? e.message : 'Upload failed');
    } finally { setLoading(false); }
  }

  async function loadById() {
    if (!knownId.trim()) return;
    setError(null);
    setLoading(true);
    try {
      const ctx = state.mode === 'prototype'
        ? await protoAdapter.getSnapshot(knownId.trim())
        : await new ConnectedAdapter(state.serviceConfig.mainApi).getSnapshot(knownId.trim());
      setSnapshot(ctx);
      dispatch({ type: 'SET_SNAPSHOT_ID', id: knownId.trim() });
      dispatch({ type: 'SET_CHAT_CONTEXT', context: { snapshot_id: knownId.trim() } });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Not found');
    } finally { setLoading(false); }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="w-6 h-6 rounded-full bg-teal-600 text-white text-xs font-bold flex items-center justify-center">3</span>
          <h1 className="text-lg font-semibold text-slate-800">Import snapshot</h1>
        </div>
        <p className="text-sm text-slate-500">Upload the collector JSON file or enter a known snapshot ID. Sends as JSON body to POST /api/v1/snapshots.</p>
      </div>

      {/* Upload zone */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <h2 className="text-sm font-semibold text-slate-700">Upload snapshot JSON</h2>
        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={e => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
          onClick={() => fileRef.current?.click()}
          className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors
            ${dragOver ? 'border-teal-400 bg-teal-50' : 'border-slate-200 hover:border-teal-300 hover:bg-slate-50'}`}
        >
          <input ref={fileRef} type="file" accept=".json" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
          <IconUpload size={24} className="text-slate-300 mx-auto mb-2" />
          <p className="text-sm text-slate-500">Drop snapshot.json here, or click to select</p>
          <p className="text-[11px] text-slate-400 mt-1">Accepts v0.3 (required for sandbox) and v0.2 (legacy warning)</p>
        </div>

        <div className="flex items-center gap-2 text-xs text-slate-400">
          <div className="flex-1 h-px bg-slate-200" />
          <span>or use known snapshot ID</span>
          <div className="flex-1 h-px bg-slate-200" />
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            placeholder="snap-abc123…"
            value={knownId}
            onChange={e => setKnownId(e.target.value)}
            className="flex-1 px-3 py-1.5 text-xs border border-slate-200 rounded-lg font-mono focus:outline-none focus:ring-1 focus:ring-teal-400"
          />
          <button onClick={loadById} className="px-3 py-1.5 text-xs bg-slate-100 text-slate-700 rounded-lg hover:bg-slate-200 transition-colors">
            Load
          </button>
        </div>

        {loading && <LoadingState label="Uploading snapshot…" />}
        {error && <ErrorState message="Upload failed" detail={error} onRetry={() => setError(null)} />}
      </div>

      {/* Snapshot context */}
      {snapshot && (
        <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
          <div className="flex items-center gap-2">
            <IconDatabase size={14} className="text-teal-600" />
            <h2 className="text-sm font-semibold text-slate-700">Source identity</h2>
            <span className="ml-auto text-[10px] font-mono text-teal-600 bg-teal-50 border border-teal-200 rounded px-1.5 py-0.5">
              {state.mode === 'prototype' ? '[Prototype]' : 'Connected'}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            {[
              { label: 'Snapshot ID', value: snapshot.snapshot_id, mono: true },
              { label: 'Target ID', value: snapshot.target_id, mono: true },
              { label: 'Database', value: snapshot.database, mono: true },
              { label: 'PostgreSQL version', value: snapshot.postgresql_version, mono: true },
              { label: 'Deployment type', value: snapshot.deployment_type, mono: true },
              { label: 'Collected at', value: new Date(snapshot.collected_at).toLocaleString(), mono: false },
            ].map(f => (
              <div key={f.label} className="bg-slate-50 rounded-lg p-3">
                <p className="text-slate-400 text-[10px]">{f.label}</p>
                <p className={`text-slate-700 mt-0.5 ${f.mono ? 'font-mono text-[11px]' : 'text-xs'}`}>{f.value}</p>
              </div>
            ))}
          </div>

          {snapshot.gaps.length > 0 && (
            <div>
              <p className="text-xs font-medium text-slate-600 mb-1.5">Collection gaps</p>
              {snapshot.gaps.map(g => (
                <div key={g.section} className="flex items-start gap-2 text-xs py-1.5 border-b border-slate-100">
                  <span className="font-mono text-slate-500 flex-shrink-0">{g.section}</span>
                  <span className="text-slate-400">{g.reason}</span>
                </div>
              ))}
            </div>
          )}

          {snapshot.unavailable_sections.length > 0 && (
            <div className="rounded-lg border border-amber-100 bg-amber-50/50 p-3 text-xs">
              <p className="text-amber-700 font-medium mb-1">Unavailable sections</p>
              <div className="flex flex-wrap gap-1">
                {snapshot.unavailable_sections.map(s => (
                  <span key={s} className="font-mono text-amber-600 bg-amber-100 rounded px-1.5 py-0.5">{s}</span>
                ))}
              </div>
            </div>
          )}

          {snapshot.available_sections.length > 0 && (
            <div className="rounded-lg border border-teal-100 bg-teal-50/50 p-3 text-xs">
              <p className="text-teal-700 font-medium mb-1">Available sections ({snapshot.available_sections.length})</p>
              <div className="flex flex-wrap gap-1">
                {snapshot.available_sections.map(s => (
                  <span key={s} className="font-mono text-teal-600 bg-teal-100 rounded px-1.5 py-0.5">{s}</span>
                ))}
              </div>
            </div>
          )}

          <button
            onClick={() => { dispatch({ type: 'COMPLETE_STEP', step: 3 }); setWorkflowStep(4); dispatch({ type: 'SET_VIEW', view: 'workflows' }); }}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-600 text-white text-sm font-medium hover:bg-teal-700 transition-colors"
          >
            Continue to assessment
            <IconArrowRight size={14} />
          </button>
        </div>
      )}
    </div>
  );
}
