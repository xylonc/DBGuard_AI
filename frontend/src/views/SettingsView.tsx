import { useState } from 'react';
import { useWorkflow } from '@/store/workflowStore';
import { ConnectedAdapter } from '@/adapters/apiAdapter';
import type { ServiceHealth } from '@/types/api';
import { IconRefreshCw, IconCheck, IconX, IconAlertTriangle } from '@/components/shared/icons';

const SERVICE_KEYS = [
  { key: 'mainApi' as const,    label: 'Main API',          hint: 'localhost:8011 — primary DBGuardAI backend' },
  { key: 'demoApi' as const,    label: 'Demo App',          hint: 'localhost:8010 — demo/review app' },
  { key: 'composeApi' as const, label: 'Compose Backend',   hint: 'localhost:8000 — docker-compose backend' },
  { key: 'hermesApi' as const,  label: 'HERMES API',        hint: 'localhost:8642 — OpenAI-compatible chat API' },
  { key: 'mcpApi' as const,     label: 'MCP Server',        hint: 'localhost:8001 — DBGuard MCP /mcp endpoint' },
];

function StatusDot({ status }: { status: ServiceHealth['status'] }) {
  const colors = { healthy: 'bg-green-500', degraded: 'bg-amber-400', unavailable: 'bg-red-500', unknown: 'bg-slate-300' };
  return <span className={`w-2 h-2 rounded-full inline-block ${colors[status]}`} />;
}

export function SettingsView() {
  const { state, dispatch } = useWorkflow();
  const [urls, setUrls] = useState({ ...state.serviceConfig });
  const [health, setHealth] = useState<Record<string, ServiceHealth>>({});
  const [checking, setChecking] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  function save() {
    dispatch({ type: 'SET_SERVICE_CONFIG', config: urls });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  async function checkHealth(key: keyof typeof urls) {
    setChecking(key);
    const url = urls[key];
    try {
      const adapter = new ConnectedAdapter(url);
      const result = await adapter.health();
      setHealth(h => ({ ...h, [key]: result }));
    } catch {
      setHealth(h => ({ ...h, [key]: { service: key, url, status: 'unavailable', checked_at: new Date().toISOString() } }));
    }
    setChecking(null);
  }

  async function checkAll() {
    for (const s of SERVICE_KEYS) {
      await checkHealth(s.key);
    }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-slate-800">Settings</h1>
        <p className="text-sm text-slate-500">Configure service connections, mode, and integration requirements.</p>
      </div>

      {/* Mode */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-slate-700">Application mode</h2>
        <div className="grid grid-cols-2 gap-3">
          {(['prototype', 'connected'] as const).map(m => (
            <button
              key={m}
              onClick={() => dispatch({ type: 'SET_MODE', mode: m })}
              className={`px-4 py-3 rounded-lg border-2 text-xs text-left transition-colors ${
                state.mode === m ? (m === 'prototype' ? 'border-amber-400 bg-amber-50' : 'border-teal-500 bg-teal-50') : 'border-slate-200 hover:border-slate-300'
              }`}
            >
              <p className={`font-semibold capitalize ${state.mode === m ? (m === 'prototype' ? 'text-amber-700' : 'text-teal-700') : 'text-slate-600'}`}>{m}</p>
              <p className="text-slate-400 mt-1">
                {m === 'prototype'
                  ? 'Coherent mock data for all operations. No backend required.'
                  : 'Real HTTP calls. Unavailable services show connection errors, never silent mock results.'}
              </p>
            </button>
          ))}
        </div>
        {state.mode === 'connected' && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] text-amber-700 flex items-start gap-1.5">
            <IconAlertTriangle size={12} className="mt-0.5 flex-shrink-0" />
            Connected mode requires an authenticated, reachable gateway or local deployment. Do not expose local POC services publicly without proper authentication.
          </div>
        )}
      </div>

      {/* Service URLs */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700">Service URLs</h2>
          <button
            onClick={checkAll}
            className="inline-flex items-center gap-1.5 text-xs text-slate-500 border border-slate-200 rounded-lg px-2.5 py-1 hover:bg-slate-50 transition-colors"
          >
            <IconRefreshCw size={11} />
            Check all
          </button>
        </div>
        <p className="text-[11px] text-slate-400">Paths being identical does not make their data stores identical. Chat's MCP backend and the UI's selected workflow backend must point to the same instance.</p>
        <div className="space-y-3">
          {SERVICE_KEYS.map(s => (
            <div key={s.key} className="space-y-1">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-slate-600 flex items-center gap-1.5">
                  {health[s.key] && <StatusDot status={health[s.key].status} />}
                  {s.label}
                </label>
                <button
                  onClick={() => checkHealth(s.key)}
                  disabled={checking === s.key}
                  className="text-[10px] text-teal-600 hover:underline disabled:opacity-50"
                >
                  {checking === s.key ? 'Checking…' : 'Check'}
                </button>
              </div>
              <input
                type="text"
                value={urls[s.key]}
                onChange={e => setUrls(u => ({ ...u, [s.key]: e.target.value }))}
                className="w-full px-3 py-1.5 text-xs border border-slate-200 rounded-lg font-mono focus:outline-none focus:ring-1 focus:ring-teal-400"
              />
              <p className="text-[10px] text-slate-400">{s.hint}</p>
              {health[s.key] && (
                <div className={`flex items-center gap-1.5 text-[10px] font-mono ${health[s.key].status === 'healthy' ? 'text-green-600' : 'text-red-600'}`}>
                  {health[s.key].status === 'healthy' ? <IconCheck size={10} /> : <IconX size={10} />}
                  {health[s.key].status}
                  {health[s.key].error && <span className="text-slate-400 ml-1">{health[s.key].error}</span>}
                </div>
              )}
            </div>
          ))}
        </div>
        <button
          onClick={save}
          className="inline-flex items-center gap-2 px-3 py-1.5 text-xs bg-teal-600 text-white rounded-lg hover:bg-teal-700 transition-colors"
        >
          {saved ? <><IconCheck size={12} />Saved</> : 'Save URLs'}
        </button>
      </div>

      {/* Benchmark scope */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-slate-700">Benchmark scope</h2>
        <div className="flex items-center gap-3">
          <select
            value={state.benchmarkId}
            onChange={e => dispatch({ type: 'SET_BENCHMARK_ID', id: e.target.value })}
            className="text-sm border border-slate-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-1 focus:ring-teal-400"
          >
            <option value="cis-pg17-v1.1.0">cis-pg17-v1.1.0 (installed)</option>
          </select>
          <span className="text-xs text-slate-400">Environment:</span>
          <select
            value={state.environment}
            onChange={e => dispatch({ type: 'SET_ENVIRONMENT', env: e.target.value })}
            className="text-sm border border-slate-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-1 focus:ring-teal-400"
          >
            <option value="dev">dev</option>
            <option value="staging">staging</option>
            <option value="prod">prod</option>
          </select>
        </div>
      </div>

      {/* Integration backlog */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-slate-700">Integration backlog</h2>
        <p className="text-[11px] text-slate-400">Features not yet connected. No HTTP endpoint exists for these operations.</p>
        <ul className="space-y-1.5 text-xs text-slate-500">
          {[
            'Workbook-to-spec generation (no HTTP route)',
            'Collector download / execution from browser (CLI only)',
            'Live sandbox progress events (synchronous call, no SSE)',
            'Generic GET /sandbox/runs/{id} (no such route)',
            'Persistent run history / workflow list endpoint',
            'Unified login / role enforcement',
            'HERMES chat proxy (OpenAI-compatible adapter — contract verification required)',
            'Before/after target snapshot comparison workflow',
            'Cancel API (no cancel endpoint exists)',
          ].map(item => (
            <li key={item} className="flex items-start gap-2">
              <span className="w-1 h-1 rounded-full bg-slate-300 mt-1.5 flex-shrink-0" />
              {item}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
