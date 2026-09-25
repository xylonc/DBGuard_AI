import { useWorkflow } from '@/store/workflowStore';
import { IconArrowRight, IconDatabase, IconShield, IconFlask, IconFileText, IconPackage } from '@/components/shared/icons';
import { StatusBadge } from '@/components/shared/StatusBadge';

const protoRuns = [
  { id: 'run-proto-001', date: '2026-09-24', source: 'pg17-dev.internal', benchmark: 'cis-pg17-v1.1.0', controls: 6, pass: 3, fail: 2, sandbox: 'VERIFIED', bundle: 'READY' },
  { id: 'run-proto-002', date: '2026-09-22', source: 'pg17-dev.internal', benchmark: 'cis-pg17-v1.1.0', controls: 6, pass: 3, fail: 2, sandbox: 'FAILED', bundle: null },
  { id: 'run-proto-003', date: '2026-09-20', source: 'pg17-staging.internal', benchmark: 'cis-pg17-v1.1.0', controls: 6, pass: 4, fail: 2, sandbox: null, bundle: null },
];

function DiagramNode({ label, sub, color }: { label: string; sub?: string; color: string }) {
  return (
    <div className={`rounded-lg border-2 ${color} px-3 py-2 text-center min-w-[100px]`}>
      <p className="text-xs font-medium text-slate-700">{label}</p>
      {sub && <p className="text-[10px] text-slate-400 font-mono mt-0.5">{sub}</p>}
    </div>
  );
}

function DiagramArrow({ label }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-0.5 px-1">
      {label && <span className="text-[9px] text-slate-400 whitespace-nowrap">{label}</span>}
      <div className="flex items-center">
        <div className="w-6 h-px bg-slate-300" />
        <div className="border-t-4 border-b-4 border-l-4 border-t-transparent border-b-transparent border-l-slate-300 -ml-px" style={{ borderLeftWidth: 6, borderTopWidth: 4, borderBottomWidth: 4 }} />
      </div>
    </div>
  );
}

export function OverviewView() {
  const { dispatch, setWorkflowStep } = useWorkflow();

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold text-slate-800">DBGuardAI — PostgreSQL Hardening Workflow</h1>
        <p className="text-sm text-slate-500 mt-1">Assess CIS benchmark compliance, test approved fixes in disposable sandboxes, and produce DBA review bundles.</p>
      </div>

      {/* Start button */}
      <button
        onClick={() => dispatch({ type: 'START_NEW_WORKFLOW' })}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-600 text-white text-sm font-medium hover:bg-teal-700 transition-colors"
      >
        Start new workflow
        <IconArrowRight size={14} />
      </button>

      {/* Data flow diagram */}
      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h2 className="text-sm font-semibold text-slate-700 mb-4 flex items-center gap-2">
          <IconDatabase size={14} className="text-teal-600" />
          How this workflow uses data
        </h2>
        <div className="flex flex-wrap items-center gap-1 overflow-x-auto pb-2">
          <DiagramNode label="Source PostgreSQL" sub="config read-only" color="border-blue-200 bg-blue-50" />
          <DiagramArrow label="collector" />
          <DiagramNode label="Snapshot store" sub="JSON files" color="border-slate-200 bg-slate-50" />
          <DiagramArrow label="assess" />
          <DiagramNode label="DBGuard pgvector" sub="knowledge & templates" color="border-teal-200 bg-teal-50" />
          <DiagramArrow label="handoff" />
          <DiagramNode label="Sandbox PostgreSQL" sub="disposable · isolated" color="border-amber-200 bg-amber-50" />
          <DiagramArrow label="bundle" />
          <DiagramNode label="DBA review bundle" sub="harden.sh + evidence" color="border-purple-200 bg-purple-50" />
        </div>
        <div className="mt-3 pt-3 border-t border-slate-100">
          <p className="text-[11px] text-slate-400 leading-relaxed">
            <span className="font-medium text-red-600">Never:</span> Remediation is never run against DBGuard's own pgvector database.
            The sandbox is a fresh isolated container. Source changes occur only after a DBA applies the reviewed bundle independently.
          </p>
        </div>
      </div>

      {/* Recent runs */}
      <div className="bg-white rounded-xl border border-slate-200">
        <div className="px-5 py-3 border-b border-slate-100 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700">Recent workflow runs</h2>
          <span className="text-[10px] text-amber-600 font-mono bg-amber-50 border border-amber-200 rounded px-1.5 py-0.5">
            Prototype data — not an audit log
          </span>
        </div>
        <div className="divide-y divide-slate-100">
          {protoRuns.map(run => (
            <div key={run.id} className="px-5 py-3 hover:bg-slate-50 transition-colors">
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-slate-600">{run.source}</span>
                    <span className="text-slate-300">·</span>
                    <span className="text-xs text-slate-500">{run.date}</span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5 font-mono">{run.benchmark} · {run.controls} controls</div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] text-green-600 font-mono">{run.pass}P</span>
                  <span className="text-[11px] text-red-600 font-mono">{run.fail}F</span>
                  {run.sandbox && <StatusBadge status={run.sandbox} />}
                  {run.bundle === 'READY' && (
                    <span className="text-[10px] px-1.5 py-0.5 bg-purple-50 text-purple-600 border border-purple-200 rounded font-mono">BUNDLE READY</span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
        <div className="px-5 py-2 border-t border-slate-100">
          <p className="text-[10px] text-slate-400">No workflow-list endpoint — overview uses prototype local data only.</p>
        </div>
      </div>

      {/* Stage cards */}
      <div>
        <h2 className="text-sm font-semibold text-slate-700 mb-3">Seven-stage workflow</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { num: 1, title: 'Benchmark', desc: 'Upload XLSX, select benchmark, preview specs', icon: <IconShield size={16} /> },
            { num: 2, title: 'Collect', desc: 'Run collector CLI against source PostgreSQL', icon: <IconDatabase size={16} /> },
            { num: 3, title: 'Import snapshot', desc: 'Upload snapshot JSON, review source identity', icon: <IconDatabase size={16} /> },
            { num: 4, title: 'Assess & review', desc: 'Run spec assessment, review proposed fixes', icon: <IconShield size={16} /> },
            { num: 5, title: 'Sandbox test', desc: 'Test fix in disposable PostgreSQL container', icon: <IconFlask size={16} /> },
            { num: 6, title: 'DBA review', desc: 'Download evidence bundle, prepare for DBA', icon: <IconFileText size={16} /> },
            { num: 7, title: 'Recollect', desc: 'After DBA applies fix, recollect and compare', icon: <IconPackage size={16} /> },
          ].map(s => (
            <button
              key={s.num}
              onClick={() => { setWorkflowStep(s.num); dispatch({ type: 'SET_VIEW', view: 'workflows' }); }}
              className="text-left p-3 rounded-lg border border-slate-200 bg-white hover:border-teal-300 hover:bg-teal-50/30 transition-colors group"
            >
              <div className="flex items-center gap-2 mb-1.5">
                <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-500 text-[10px] font-bold flex items-center justify-center group-hover:bg-teal-100 group-hover:text-teal-700 transition-colors flex-shrink-0">{s.num}</span>
                <span className="text-xs font-medium text-slate-700">{s.title}</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-snug">{s.desc}</p>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
