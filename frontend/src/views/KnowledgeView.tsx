import { useState } from 'react';
import { useWorkflow } from '@/store/workflowStore';
import { protoAdapter } from '@/adapters/apiAdapter';
import type { KnowledgeSearchResult } from '@/types/api';
import { LoadingState, ErrorState } from '@/components/shared/EmptyState';
import { IconSearch, IconCheck, IconAlertTriangle } from '@/components/shared/icons';

type Tab = 'knowledge' | 'templates' | 'advanced';

function TabButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 text-xs font-medium border-b-2 transition-colors ${
        active ? 'border-teal-600 text-teal-700' : 'border-transparent text-slate-500 hover:text-slate-700'
      }`}
    >
      {label}
    </button>
  );
}

function SearchResults({ results }: { results: KnowledgeSearchResult[] }) {
  if (results.length === 0) return <p className="text-xs text-slate-400 py-4 text-center">No results</p>;
  return (
    <div className="space-y-2">
      {results.map(r => (
        <div key={r.chunk_id} className="rounded-lg border border-slate-200 p-3 text-xs">
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-teal-600">{r.document_id}</span>
                {r.section && <span className="font-mono text-slate-400 text-[10px]">§{r.section}</span>}
              </div>
              <p className="font-medium text-slate-700 mt-0.5">{r.source_document_title}
                {r.source_document_version && <span className="text-slate-400 font-normal ml-1">({r.source_document_version})</span>}
              </p>
              <p className="text-slate-500 mt-1 line-clamp-3">{r.content}</p>
            </div>
            <div className="flex flex-col items-end gap-1 flex-shrink-0">
              <span className="text-[10px] text-slate-400 font-mono">score: {r.similarity_score.toFixed(2)}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export function KnowledgeView() {
  const { state } = useWorkflow();
  const [tab, setTab] = useState<Tab>('knowledge');
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<KnowledgeSearchResult[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [docId, setDocId] = useState('');
  const [docResult, setDocResult] = useState<unknown>(null);
  const [ingestTitle, setIngestTitle] = useState('');
  const [ingestContent, setIngestContent] = useState('');
  const [ingestResult, setIngestResult] = useState<{ document_id: string } | null>(null);
  const [approveDocId, setApproveDocId] = useState('');
  const [approveResult, setApproveResult] = useState<string | null>(null);
  const [bulkConfirmed, setBulkConfirmed] = useState(false);
  const [bulkRunning, setBulkRunning] = useState(false);

  async function search() {
    setLoading(true);
    setError(null);
    try {
      const res = tab === 'knowledge'
        ? await protoAdapter.searchKnowledge(searchQuery)
        : await protoAdapter.searchTemplates(searchQuery);
      setSearchResults(res.results);
    } catch (e) { setError(e instanceof Error ? e.message : 'Search failed'); }
    finally { setLoading(false); }
  }

  async function lookupDoc() {
    if (!docId.trim()) return;
    setLoading(true);
    try {
      const res = await protoAdapter.getKnowledgeDocument(docId.trim());
      setDocResult(res);
    } catch (e) { setError(e instanceof Error ? e.message : 'Not found'); }
    finally { setLoading(false); }
  }

  async function ingestDoc() {
    if (!ingestTitle.trim() || !ingestContent.trim()) return;
    setLoading(true);
    try {
      const res = await protoAdapter.ingestKnowledgeDocument({ title: ingestTitle, content: ingestContent, document_type: 'knowledge' });
      setIngestResult(res);
    } catch (e) { setError(e instanceof Error ? e.message : 'Ingest failed'); }
    finally { setLoading(false); }
  }

  async function approveDoc() {
    if (!approveDocId.trim()) return;
    if (!confirm(`Approve document ${approveDocId}? This requires an intentional reviewer action.`)) return;
    setLoading(true);
    try {
      await protoAdapter.approveKnowledge(approveDocId.trim(), {});
      setApproveResult(`Document ${approveDocId} approved.`);
    } catch (e) { setError(e instanceof Error ? e.message : 'Approval failed'); }
    finally { setLoading(false); }
  }

  async function runBulkIngest() {
    if (!bulkConfirmed) return;
    setBulkRunning(true);
    await new Promise(r => setTimeout(r, 1500));
    setBulkRunning(false);
    setBulkConfirmed(false);
    alert('[Prototype] Bulk ingestion simulated. In Connected mode, this calls POST /api/v1/templates/ingest-all.');
  }

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-4">
      <div>
        <h1 className="text-lg font-semibold text-slate-800">Knowledge & templates</h1>
        <p className="text-sm text-slate-500">Upload knowledge, search approved evidence, manage SQL templates.</p>
      </div>

      <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] text-amber-700">
        <strong>Limitation:</strong> No general list or version-browser endpoint exists. Search returns eligible content, not a complete catalog.
        Approval buttons require intentional reviewer action and cannot auto-approve.
      </div>

      {/* Tabs */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="flex border-b border-slate-200 px-4">
          <TabButton label="Knowledge documents" active={tab === 'knowledge'} onClick={() => { setTab('knowledge'); setSearchResults(null); }} />
          <TabButton label="Templates" active={tab === 'templates'} onClick={() => { setTab('templates'); setSearchResults(null); }} />
          <TabButton label="Advanced setup" active={tab === 'advanced'} onClick={() => setTab('advanced')} />
        </div>

        <div className="p-5 space-y-5">
          {tab !== 'advanced' && (
            <>
              {/* Search */}
              <div>
                <h3 className="text-xs font-semibold text-slate-600 mb-2">Search approved {tab === 'knowledge' ? 'knowledge' : 'templates'}</h3>
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <IconSearch size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
                    <input
                      type="text"
                      placeholder={`Search ${tab}…`}
                      value={searchQuery}
                      onChange={e => setSearchQuery(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && search()}
                      className="w-full pl-8 pr-3 py-1.5 text-xs border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-teal-400"
                    />
                  </div>
                  <button onClick={search} className="px-3 py-1.5 text-xs bg-teal-600 text-white rounded-lg hover:bg-teal-700 transition-colors">
                    Search
                  </button>
                </div>
                {loading && <LoadingState label="Searching…" />}
                {error && <ErrorState message={error} />}
                {searchResults && <div className="mt-2"><SearchResults results={searchResults} /></div>}
              </div>

              {/* Document lookup */}
              {tab === 'knowledge' && (
                <div className="pt-4 border-t border-slate-100">
                  <h3 className="text-xs font-semibold text-slate-600 mb-2">Look up document by ID</h3>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="doc-ev-001…"
                      value={docId}
                      onChange={e => setDocId(e.target.value)}
                      className="flex-1 px-3 py-1.5 text-xs border border-slate-200 rounded-lg font-mono focus:outline-none focus:ring-1 focus:ring-teal-400"
                    />
                    <button onClick={lookupDoc} className="px-3 py-1.5 text-xs bg-slate-100 text-slate-700 rounded-lg hover:bg-slate-200 transition-colors">
                      Lookup
                    </button>
                  </div>
                  {!!docResult && (
                    <pre className="mt-2 text-[10px] font-mono bg-slate-50 rounded-lg px-3 py-2 overflow-x-auto border border-slate-200">
                      {JSON.stringify(docResult, null, 2)}
                    </pre>
                  )}
                </div>
              )}

              {/* Ingest */}
              <div className="pt-4 border-t border-slate-100">
                <h3 className="text-xs font-semibold text-slate-600 mb-2">Ingest new {tab === 'knowledge' ? 'document' : 'template'} (draft)</h3>
                <div className="space-y-2">
                  <input type="text" placeholder="Title" value={ingestTitle} onChange={e => setIngestTitle(e.target.value)} className="w-full px-3 py-1.5 text-xs border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-teal-400" />
                  <textarea rows={3} placeholder="Content or SQL" value={ingestContent} onChange={e => setIngestContent(e.target.value)} className="w-full px-3 py-1.5 text-xs border border-slate-200 rounded-lg font-mono resize-none focus:outline-none focus:ring-1 focus:ring-teal-400" />
                  <button onClick={ingestDoc} className="px-3 py-1.5 text-xs bg-slate-100 text-slate-700 rounded-lg hover:bg-slate-200 transition-colors">
                    Ingest as draft
                  </button>
                  {ingestResult && <p className="text-xs text-green-600 font-mono"><IconCheck size={10} className="inline mr-1" />Ingested: {ingestResult.document_id} (draft — requires separate approval)</p>}
                </div>
              </div>

              {/* Approve */}
              <div className="pt-4 border-t border-slate-100">
                <h3 className="text-xs font-semibold text-slate-600 mb-2">Approve document / template</h3>
                <p className="text-[11px] text-slate-400 mb-2">Requires intentional reviewer action. Cannot auto-approve during upload or demo setup.</p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder={tab === 'knowledge' ? 'Document ID' : 'Template name'}
                    value={approveDocId}
                    onChange={e => setApproveDocId(e.target.value)}
                    className="flex-1 px-3 py-1.5 text-xs border border-slate-200 rounded-lg font-mono focus:outline-none focus:ring-1 focus:ring-teal-400"
                  />
                  <button onClick={approveDoc} className="px-3 py-1.5 text-xs bg-amber-50 text-amber-700 border border-amber-200 rounded-lg hover:bg-amber-100 transition-colors">
                    Approve (reviewer action)
                  </button>
                </div>
                {approveResult && <p className="text-xs text-green-600 font-mono mt-1">{approveResult}</p>}
              </div>
            </>
          )}

          {/* Advanced tab */}
          {tab === 'advanced' && (
            <div className="space-y-4">
              <div className="rounded-lg border-2 border-red-200 bg-red-50 p-4">
                <div className="flex items-start gap-2 mb-3">
                  <IconAlertTriangle size={14} className="text-red-500 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-semibold text-red-700">Admin only — Bulk template ingestion</p>
                    <p className="text-xs text-red-600 mt-1">Initializes registry structures and ingests all configured templates. Never run automatically when a page loads. Use only for initial setup or re-initialization. In {state.mode === 'prototype' ? 'Prototype' : 'Connected'} mode calls POST /api/v1/templates/ingest-all.</p>
                  </div>
                </div>
                <label className="flex items-center gap-2 text-xs text-red-700 cursor-pointer">
                  <input type="checkbox" checked={bulkConfirmed} onChange={e => setBulkConfirmed(e.target.checked)} className="accent-red-600" />
                  I understand this is an admin-only operation and should not run automatically
                </label>
                <button
                  onClick={runBulkIngest}
                  disabled={!bulkConfirmed || bulkRunning}
                  className="mt-3 px-3 py-1.5 text-xs bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  {bulkRunning ? 'Running…' : 'Run bulk ingestion'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
