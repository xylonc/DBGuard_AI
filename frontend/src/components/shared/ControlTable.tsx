import { useState } from 'react';
import type { Finding } from '@/types/api';
import { StatusBadge } from './StatusBadge';
import { IconSearch, IconChevronDown, IconChevronRight } from './icons';

interface ControlTableProps {
  findings: Finding[];
  onSelectControl?: (controlId: string) => void;
  selectedControlId?: string | null;
}

export function ControlTable({ findings, onSelectControl, selectedControlId }: ControlTableProps) {
  const [query, setQuery] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const filtered = findings.filter(f =>
    !query ||
    f.control_id.toLowerCase().includes(query.toLowerCase()) ||
    f.title.toLowerCase().includes(query.toLowerCase()) ||
    f.status.toLowerCase().includes(query.toLowerCase())
  );

  const toggleExpand = (id: string) => setExpanded(expanded === id ? null : id);

  return (
    <div>
      <div className="relative mb-3">
        <IconSearch size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
        <input
          type="text"
          placeholder="Filter controls..."
          value={query}
          onChange={e => setQuery(e.target.value)}
          className="w-full pl-8 pr-3 py-1.5 text-xs border border-slate-200 rounded-md bg-white focus:outline-none focus:ring-1 focus:ring-teal-400 focus:border-teal-400"
        />
      </div>

      <div className="border border-slate-200 rounded-lg overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200">
              <th className="text-left px-3 py-2 font-medium text-slate-500 w-6" />
              <th className="text-left px-3 py-2 font-medium text-slate-500 w-20">Control</th>
              <th className="text-left px-3 py-2 font-medium text-slate-500">Title</th>
              <th className="text-left px-3 py-2 font-medium text-slate-500 hidden md:table-cell">Observed</th>
              <th className="text-left px-3 py-2 font-medium text-slate-500 hidden md:table-cell">Expected</th>
              <th className="text-left px-3 py-2 font-medium text-slate-500">Result</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f, i) => (
              <>
                <tr
                  key={f.control_id}
                  onClick={() => { onSelectControl?.(f.control_id); toggleExpand(f.control_id); }}
                  className={`border-b border-slate-100 cursor-pointer transition-colors
                    ${i % 2 === 0 ? 'bg-white' : 'bg-slate-50/50'}
                    ${selectedControlId === f.control_id ? 'ring-1 ring-inset ring-teal-300 bg-teal-50/40' : 'hover:bg-teal-50/20'}
                  `}
                >
                  <td className="px-3 py-2 text-slate-400">
                    {expanded === f.control_id ? <IconChevronDown size={12} /> : <IconChevronRight size={12} />}
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-600 whitespace-nowrap">{f.control_id}</td>
                  <td className="px-3 py-2 text-slate-700 max-w-xs">
                    <span className="line-clamp-1">{f.title}</span>
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-500 hidden md:table-cell">
                    {f.observed_value ?? '—'}
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-500 hidden md:table-cell">
                    {f.expected_value ?? '—'}
                  </td>
                  <td className="px-3 py-2">
                    <StatusBadge status={f.upstream_status ?? f.status} />
                  </td>
                </tr>
                {expanded === f.control_id && (
                  <tr key={`${f.control_id}-detail`} className="bg-slate-50/80 border-b border-slate-200">
                    <td colSpan={6} className="px-4 py-3">
                      <ControlDetail finding={f} />
                    </td>
                  </tr>
                )}
              </>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="text-center py-8 text-slate-400 text-xs">No controls match filter</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ControlDetail({ finding: f }: { finding: Finding }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
      <div>
        <p className="font-medium text-slate-600 mb-1">Description</p>
        <p className="text-slate-500">{f.description || 'No description available.'}</p>
      </div>
      <div className="space-y-2">
        {f.upstream_status && f.upstream_status !== f.status && (
          <div>
            <span className="text-slate-400 mr-2">Authoritative (upstream_report):</span>
            <StatusBadge status={f.upstream_status} />
            <span className="text-slate-300 mx-1">→</span>
            <span className="text-slate-400">convenience mapping:</span>
            <span className="font-mono text-slate-500 ml-1">{f.status}</span>
          </div>
        )}
        {f.template && (
          <div className="p-2 rounded border border-teal-100 bg-teal-50/50">
            <p className="font-medium text-teal-700 mb-1">Approved template</p>
            <p className="font-mono text-teal-600">{f.template.template_name} v{f.template.version}</p>
            {f.template.approval_note && (
              <p className="text-[10px] text-orange-600 mt-1 font-mono">{f.template.approval_note}</p>
            )}
          </div>
        )}
        {f.evidence && f.evidence.length > 0 && (
          <div>
            <p className="font-medium text-slate-600 mb-1">Evidence documents</p>
            {f.evidence.map(e => (
              <div key={e.document_id} className="flex items-center gap-1.5">
                <span className="font-mono text-slate-500">{e.document_id}</span>
                <span className="text-slate-400">—</span>
                <span className="text-slate-500 truncate">{e.title}</span>
                {e.approved && <span className="text-[10px] text-green-600 font-mono">approved</span>}
              </div>
            ))}
          </div>
        )}
        {!f.supported_fix && (
          <div className="text-[11px] text-slate-400 font-mono">Fix: Not supported yet</div>
        )}
      </div>
    </div>
  );
}
