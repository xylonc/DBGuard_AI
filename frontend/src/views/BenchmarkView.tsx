import { useState, useRef } from 'react';
import { useWorkflow } from '@/store/workflowStore';
import { IconUpload, IconCheck, IconArrowRight, IconInfo } from '@/components/shared/icons';
import { PlannedFeature } from '@/components/shared/EmptyState';
import { StatusBadge } from '@/components/shared/StatusBadge';

const sampleSpecs = [
  { id: '3.1.14', title: 'Ensure pgAudit Is Enabled', type: 'needs_capability' as const },
  { id: '3.1.16', title: "Ensure 'log_hostname' is Set Correctly", type: 'automated' as const },
  { id: '3.1.20', title: "Ensure 'log_connections' is Enabled", type: 'automated' as const },
  { id: '3.1.21', title: "Ensure 'log_disconnections' is Enabled", type: 'automated' as const },
  { id: '3.1.25', title: "Ensure 'log_line_prefix' is Set Correctly", type: 'automated' as const },
  { id: '6.9',    title: 'Ensure Row Security is Enabled Where Required', type: 'automated' as const },
];

export function BenchmarkView() {
  const { state, dispatch, setWorkflowStep } = useWorkflow();
  const [workbookIngested, setWorkbookIngested] = useState(false);
  const [ingestLoading, setIngestLoading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleFile(file: File) {
    if (!file.name.endsWith('.xlsx')) return;
    setFileName(file.name);
    setIngestLoading(true);
    await new Promise(r => setTimeout(r, 800));
    setWorkbookIngested(true);
    setIngestLoading(false);
  }

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="w-6 h-6 rounded-full bg-teal-600 text-white text-xs font-bold flex items-center justify-center">1</span>
          <h1 className="text-lg font-semibold text-slate-800">Benchmark & requirements</h1>
        </div>
        <p className="text-sm text-slate-500">Upload a CIS workbook and confirm the benchmark. Spec generation from workbooks is a planned connection.</p>
      </div>

      {/* XLSX Upload */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <h2 className="text-sm font-semibold text-slate-700">Workbook upload</h2>

        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={e => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
          onClick={() => fileRef.current?.click()}
          className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors
            ${dragOver ? 'border-teal-400 bg-teal-50' : 'border-slate-200 hover:border-teal-300 hover:bg-slate-50'}`}
        >
          <input ref={fileRef} type="file" accept=".xlsx" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
          <IconUpload size={24} className="text-slate-300 mx-auto mb-2" />
          <p className="text-sm text-slate-500">Drag & drop XLSX workbook, or click to select</p>
          <p className="text-[11px] text-slate-400 mt-1">CIS Benchmark XLSX format</p>
        </div>

        {fileName && (
          <div className="flex items-center gap-2 text-xs text-slate-600 bg-slate-50 rounded-lg px-3 py-2">
            <IconInfo size={12} className="text-slate-400 flex-shrink-0" />
            <span className="font-mono">{fileName}</span>
          </div>
        )}

        {/* Status indicators */}
        <div className="grid grid-cols-2 gap-3">
          <div className={`rounded-lg border p-3 ${workbookIngested ? 'border-green-200 bg-green-50' : 'border-slate-200 bg-slate-50'}`}>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${workbookIngested ? 'bg-green-500' : 'bg-slate-300'}`} />
              <p className="text-xs font-medium text-slate-600">Workbook ingested</p>
            </div>
            <p className="text-[10px] text-slate-400 mt-1">
              {workbookIngested
                ? `POST /api/v1/knowledge/upload → draft knowledge created`
                : 'Upload XLSX to ingest as draft knowledge'}
            </p>
            {ingestLoading && <p className="text-[10px] text-teal-600 mt-1 font-mono">Ingesting…</p>}
            {workbookIngested && <IconCheck size={12} className="text-green-500 mt-1" />}
          </div>
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-slate-300" />
              <p className="text-xs font-medium text-slate-600">Exact specs available</p>
            </div>
            <p className="text-[10px] text-slate-400 mt-1">Workbook upload does not generate specs.</p>
            <div className="mt-1">
              <PlannedFeature label="Spec generation" />
            </div>
          </div>
        </div>
      </div>

      {/* Benchmark selection */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-slate-700">Benchmark selection</h2>
        <div className="flex items-center gap-3">
          <select
            value={state.benchmarkId}
            onChange={e => dispatch({ type: 'SET_BENCHMARK_ID', id: e.target.value })}
            className="text-sm border border-slate-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-1 focus:ring-teal-400"
          >
            <option value="cis-pg17-v1.1.0">cis-pg17-v1.1.0 (installed)</option>
          </select>
          <span className="text-[11px] text-slate-400">Only installed benchmarks can be selected. Full benchmark generation is a planned integration.</span>
        </div>
      </div>

      {/* Spec preview */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700">Installed specs — {state.benchmarkId}</h2>
          <span className="text-[11px] text-slate-400 font-mono">6 specs · 5 automated · 1 needs-capability</span>
        </div>
        <div className="border border-slate-200 rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200">
                <th className="text-left px-3 py-2 font-medium text-slate-500 w-20">ID</th>
                <th className="text-left px-3 py-2 font-medium text-slate-500">Title</th>
                <th className="text-left px-3 py-2 font-medium text-slate-500 w-28">Type</th>
              </tr>
            </thead>
            <tbody>
              {sampleSpecs.map((s, i) => (
                <tr key={s.id} className={`border-b border-slate-100 ${i % 2 === 0 ? 'bg-white' : 'bg-slate-50/50'}`}>
                  <td className="px-3 py-2 font-mono text-slate-600">{s.id}</td>
                  <td className="px-3 py-2 text-slate-700">{s.title}</td>
                  <td className="px-3 py-2">
                    {s.type === 'automated'
                      ? <StatusBadge status="PASS" showIcon={false} size="sm" />
                      : <StatusBadge status="NEEDS_CAPABILITY" size="sm" />
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-[11px] text-slate-400">These are installed sample specs. A full benchmark from the uploaded workbook requires the planned spec-generation integration.</p>
      </div>

      <button
        onClick={() => { dispatch({ type: 'COMPLETE_STEP', step: 1 }); setWorkflowStep(2); dispatch({ type: 'SET_VIEW', view: 'workflows' }); }}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-600 text-white text-sm font-medium hover:bg-teal-700 transition-colors"
      >
        Continue to collection
        <IconArrowRight size={14} />
      </button>
    </div>
  );
}
