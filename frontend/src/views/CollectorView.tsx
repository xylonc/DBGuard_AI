import { useState } from 'react';
import { useWorkflow } from '@/store/workflowStore';

import { IconArrowRight, IconCopy, IconCheck, IconDatabase } from '@/components/shared/icons';
import { NotConnectedState } from '@/components/shared/EmptyState';

const CLI_COMMANDS = [
  {
    label: 'Step 1 — Build check manifest (one-time per benchmark)',
    cmd: 'python scripts/build_check_manifest.py --specs catalog/specs/cis-pg17-v1.1.0 --out checks.json',
  },
  {
    label: 'Step 2 — Run collector against source PostgreSQL',
    cmd: 'bash collector/dbguard-collect.sh -m checks.json -t dev-pg17 -o snapshot.json',
  },
];

function CopyableCommand({ label, cmd }: { label: string; cmd: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return (
    <div className="rounded-lg border border-slate-200 overflow-hidden">
      <div className="px-3 py-1.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
        <span className="text-[11px] text-slate-500">{label}</span>
        <button onClick={copy} className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-slate-600">
          {copied ? <IconCheck size={10} className="text-green-500" /> : <IconCopy size={10} />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="px-3 py-2.5 text-[11px] font-mono text-slate-700 bg-white overflow-x-auto whitespace-pre-wrap break-all">{cmd}</pre>
    </div>
  );
}

export function CollectorView() {
  const { setWorkflowStep, dispatch } = useWorkflow();

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="w-6 h-6 rounded-full bg-teal-600 text-white text-xs font-bold flex items-center justify-center">2</span>
          <h1 className="text-lg font-semibold text-slate-800">Collect source configuration</h1>
        </div>
        <p className="text-sm text-slate-500">Run the read-only collector CLI against your PostgreSQL source to produce a snapshot JSON file.</p>
      </div>

      {/* Diagram */}
      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h2 className="text-sm font-semibold text-slate-700 mb-4">Collection diagram</h2>
        <div className="flex flex-wrap items-center gap-3">
          <div className="rounded-xl border-2 border-blue-200 bg-blue-50 px-4 py-3 text-center min-w-[120px]">
            <IconDatabase size={18} className="text-blue-500 mx-auto mb-1" />
            <p className="text-xs font-medium text-slate-700">Source PostgreSQL</p>
            <p className="text-[10px] text-slate-400 font-mono mt-0.5">pg17-dev.internal</p>
          </div>
          <div className="flex flex-col items-center gap-0.5">
            <span className="text-[9px] text-slate-400 font-mono">read-only</span>
            <div className="flex items-center">
              <div className="w-8 h-px bg-slate-300" />
              <div style={{ width: 0, height: 0, borderTop: '5px solid transparent', borderBottom: '5px solid transparent', borderLeft: '7px solid #cbd5e1' }} />
            </div>
          </div>
          <div className="rounded-xl border-2 border-teal-200 bg-teal-50 px-4 py-3 text-center min-w-[120px]">
            <p className="text-xs font-medium text-slate-700">dbguard.collector</p>
            <p className="text-[10px] text-slate-400 font-mono mt-0.5">CLI · no passwords stored</p>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-8 h-px bg-slate-300" />
            <div style={{ width: 0, height: 0, borderTop: '5px solid transparent', borderBottom: '5px solid transparent', borderLeft: '7px solid #cbd5e1' }} />
          </div>
          <div className="rounded-xl border-2 border-slate-200 bg-slate-50 px-4 py-3 text-center min-w-[120px]">
            <p className="text-xs font-medium text-slate-700">snapshot.json</p>
            <p className="text-[10px] text-slate-400 font-mono mt-0.5">v0.3 schema</p>
          </div>
        </div>
        <div className="mt-3 pt-3 border-t border-slate-100">
          <p className="text-[11px] text-slate-400 leading-relaxed">
            The collector is read-only — it reads PostgreSQL configuration settings and produces a snapshot file.
            No passwords are transmitted or stored by DBGuardAI. The snapshot contains no sensitive data beyond
            configuration parameter values.
          </p>
        </div>
      </div>

      {/* Benchmark manifest */}
      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h2 className="text-sm font-semibold text-slate-700 mb-3">Benchmark manifest</h2>
        <div className="grid grid-cols-3 gap-3 text-xs">
          <div className="bg-slate-50 rounded-lg p-3">
            <p className="text-slate-400">Benchmark</p>
            <p className="font-mono font-medium text-slate-700 mt-0.5">cis-pg17-v1.1.0</p>
          </div>
          <div className="bg-slate-50 rounded-lg p-3">
            <p className="text-slate-400">Spec count</p>
            <p className="font-mono font-medium text-slate-700 mt-0.5">6</p>
          </div>
          <div className="bg-slate-50 rounded-lg p-3">
            <p className="text-slate-400">Schema</p>
            <p className="font-mono font-medium text-slate-700 mt-0.5">v0.3</p>
          </div>
        </div>
      </div>

      {/* CLI instructions */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-slate-700">CLI instructions</h2>
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] text-amber-700">
          Collector generation and execution use repository CLI scripts. No HTTP endpoint exists for collection.
          Run these commands in your development environment against the source database.
        </div>
        <div className="space-y-3">
          {CLI_COMMANDS.map(c => <CopyableCommand key={c.label} {...c} />)}
        </div>
      </div>

      {/* Not-connected note */}
      <NotConnectedState feature="Browser-based collector download / execution" />

      <button
        onClick={() => { dispatch({ type: 'COMPLETE_STEP', step: 2 }); setWorkflowStep(3); dispatch({ type: 'SET_VIEW', view: 'workflows' }); }}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-600 text-white text-sm font-medium hover:bg-teal-700 transition-colors"
      >
        I have a snapshot — import it
        <IconArrowRight size={14} />
      </button>
    </div>
  );
}
