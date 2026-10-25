import { useState, useRef, useEffect } from 'react';
import type { ReactNode } from 'react';
import { useWorkflow } from '@/store/workflowStore';
import { makeMockChatResponse } from '@/adapters/mockData';
import type { ChatMessage } from '@/types/api';
import { IconSend, IconLoader, IconX, IconChevronDown, IconChevronRight, IconZap } from '@/components/shared/icons';

const stageActions: Record<number, string[]> = {
  1: ['Explain the benchmark requirements', 'What specs are installed?'],
  2: ['How do I run the collector?', 'What does the collector collect?'],
  3: ['Explain the snapshot format', 'What are collection gaps?'],
  4: ['Explain this failure', 'Find approved evidence', 'Prepare a sandbox test'],
  5: ['Test this fix', 'Explain the rollback result', 'What is adaptive retry?'],
  6: ['Open the DBA bundle', 'What does the DBA run?', 'Explain rollback evidence'],
  7: ['How do I recollect?', 'Explain the comparison', 'What counts as remediated?'],
};

// Safe markdown-to-React renderer — no innerHTML
function SafeMarkdown({ text }: { text: string }) {
  const lines = text.split('\n');
  return (
    <>
      {lines.map((line, li) => (
        <span key={li}>
          {parseInline(line)}
          {li < lines.length - 1 && <br />}
        </span>
      ))}
    </>
  );
}

function parseInline(line: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let remaining = line;
  let key = 0;

  while (remaining.length > 0) {
    const boldMatch = remaining.match(/\*\*(.+?)\*\*/);
    const codeMatch = remaining.match(/`([^`]+)`/);

    if (!boldMatch && !codeMatch) {
      nodes.push(<span key={key++}>{remaining}</span>);
      break;
    }

    const boldIdx = boldMatch ? boldMatch.index! : Infinity;
    const codeIdx = codeMatch ? codeMatch.index! : Infinity;

    if (boldIdx <= codeIdx) {
      if (boldIdx > 0) nodes.push(<span key={key++}>{remaining.slice(0, boldIdx)}</span>);
      nodes.push(<strong key={key++}>{boldMatch![1]}</strong>);
      remaining = remaining.slice(boldIdx + boldMatch![0].length);
    } else {
      if (codeIdx > 0) nodes.push(<span key={key++}>{remaining.slice(0, codeIdx)}</span>);
      nodes.push(
        <code key={key++} className="px-1 rounded bg-slate-100 text-slate-700 font-mono text-[10px]">
          {codeMatch![1]}
        </code>
      );
      remaining = remaining.slice(codeIdx + codeMatch![0].length);
    }
  }

  return nodes;
}

function ChatBubble({ msg, isPrototype }: { msg: ChatMessage; isPrototype: boolean }) {
  const isUser = msg.role === 'user';
  const [toolsOpen, setToolsOpen] = useState(false);

  return (
    <div className={`flex flex-col gap-1 ${isUser ? 'items-end' : 'items-start'}`}>
      {!isUser && isPrototype && (
        <span className="text-[9px] font-mono text-amber-600 px-1">Simulated — prototype data</span>
      )}
      <div className={`max-w-[90%] rounded-xl px-3 py-2 text-xs leading-relaxed
        ${isUser
          ? 'bg-teal-600 text-white rounded-br-sm'
          : msg.isError
            ? 'bg-red-50 text-red-700 border border-red-200 rounded-bl-sm'
            : 'bg-white text-slate-700 border border-slate-200 rounded-bl-sm'
        }`}
      >
        <div className="whitespace-pre-wrap">
          <SafeMarkdown text={msg.content} />
        </div>
      </div>

      {msg.toolActivity && msg.toolActivity.length > 0 && (
        <div className="w-full max-w-[90%]">
          <button
            onClick={() => setToolsOpen(v => !v)}
            className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-slate-600 py-0.5"
          >
            {toolsOpen ? <IconChevronDown size={10} /> : <IconChevronRight size={10} />}
            {msg.toolActivity.length} tool {msg.toolActivity.length === 1 ? 'call' : 'calls'}
          </button>
          {toolsOpen && (
            <div className="space-y-1 mt-1">
              {msg.toolActivity.map((t, i) => (
                <div key={i} className="rounded border border-slate-200 bg-slate-50 px-2 py-1.5">
                  <div className="flex items-center gap-1.5 text-[10px] font-mono">
                    <span className={`w-1.5 h-1.5 rounded-full ${t.status === 'done' ? 'bg-green-500' : t.status === 'error' ? 'bg-red-500' : 'bg-amber-400'}`} />
                    <span className="font-medium text-slate-600">{t.tool_name}</span>
                    <span className="text-slate-400">{t.status}</span>
                  </div>
                  {t.input && (
                    <details className="mt-1">
                      <summary className="text-[9px] text-slate-400 cursor-pointer">input</summary>
                      <pre className="text-[9px] text-slate-500 mt-0.5 overflow-x-auto">{JSON.stringify(t.input, null, 2)}</pre>
                    </details>
                  )}
                  {t.output && (
                    <details className="mt-0.5">
                      <summary className="text-[9px] text-slate-400 cursor-pointer">output</summary>
                      <pre className="text-[9px] text-slate-500 mt-0.5 overflow-x-auto">{JSON.stringify(t.output, null, 2)}</pre>
                    </details>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {msg.citations && msg.citations.length > 0 && (
        <div className="flex flex-wrap gap-1 max-w-[90%]">
          {msg.citations.map(c => (
            <span key={c.document_id} className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded border border-teal-200 bg-teal-50 text-teal-700 font-mono">
              {c.document_id}
            </span>
          ))}
        </div>
      )}

      <span className="text-[9px] text-slate-300">
        {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
      </span>
    </div>
  );
}

export function ChatPanel({ onClose }: { onClose?: () => void }) {
  const { state, dispatch } = useWorkflow();
  const [input, setInput] = useState('');
  const bottomRef = useRef<HTMLDivElement>(null);
  const actions = stageActions[state.activeWorkflowStep] ?? stageActions[4];
  const isPrototype = state.mode === 'prototype';

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [state.chatMessages]);

  async function sendMessage(text?: string) {
    const msg = (text ?? input).trim();
    if (!msg || state.isChatRunning) return;
    setInput('');

    const userMsg: ChatMessage = {
      id: `u-${Date.now()}`,
      role: 'user',
      content: msg,
      timestamp: new Date().toISOString(),
    };
    dispatch({ type: 'ADD_CHAT_MESSAGE', message: userMsg });
    dispatch({ type: 'SET_CHAT_RUNNING', running: true });

    if (isPrototype) {
      await new Promise(r => setTimeout(r, 600 + Math.random() * 800));
      const responses = makeMockChatResponse(msg, state.activeWorkflowStep, state.selectedControlId ?? undefined);
      for (const r of responses) {
        dispatch({ type: 'ADD_CHAT_MESSAGE', message: r });
      }
    } else {
      dispatch({
        type: 'ADD_CHAT_MESSAGE',
        message: {
          id: `e-${Date.now()}`,
          role: 'assistant',
          content: 'HERMES chat is not connected. No server-side adapter exists yet — the HERMES API contract (port 8642) must be verified before implementing a proxy. See integration backlog.',
          timestamp: new Date().toISOString(),
          isError: true,
        },
      });
    }

    dispatch({ type: 'SET_CHAT_RUNNING', running: false });
  }

  return (
    <div className="flex flex-col h-full bg-white border-l border-slate-200">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2.5 border-b border-slate-100 flex-shrink-0">
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 rounded-md bg-teal-600 flex items-center justify-center">
            <IconZap size={11} className="text-white" />
          </div>
          <div>
            <p className="text-xs font-semibold text-slate-800">HERMES AI</p>
            <p className="text-[9px] text-slate-400 font-mono">
              {isPrototype ? 'Prototype — simulated responses' : 'Not connected · port 8642'}
            </p>
          </div>
        </div>
        {onClose && (
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 p-1" title="Close HERMES panel">
            <IconX size={14} />
          </button>
        )}
      </div>

      {/* Context indicator */}
      {(state.chatContext.snapshot_id || state.chatContext.control_id || state.chatContext.handoff_id) && (
        <div className="px-3 py-1.5 bg-slate-50 border-b border-slate-100 text-[10px] font-mono text-slate-500 flex flex-wrap gap-x-3 gap-y-0.5">
          {state.chatContext.snapshot_id && <span>snap: {state.chatContext.snapshot_id.slice(0, 12)}…</span>}
          {state.chatContext.control_id && <span>ctrl: {state.chatContext.control_id}</span>}
          {state.chatContext.handoff_id && <span>handoff: {state.chatContext.handoff_id.slice(0, 12)}…</span>}
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-3 py-3 space-y-3">
        {state.chatMessages.length === 0 && (
          <div className="text-center py-6">
            <p className="text-xs text-slate-400">Start by selecting a control or asking HERMES a question.</p>
            {isPrototype && (
              <p className="text-[10px] text-amber-600 mt-1 font-mono">Prototype — all responses are simulated</p>
            )}
          </div>
        )}
        {state.chatMessages.map(msg => (
          <ChatBubble key={msg.id} msg={msg} isPrototype={isPrototype && msg.role === 'assistant'} />
        ))}
        {state.isChatRunning && (
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <IconLoader size={12} className="animate-spin" />
            HERMES is thinking…
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Suggested actions */}
      <div className="px-3 py-2 border-t border-slate-100 flex flex-wrap gap-1">
        {actions.map(a => (
          <button
            key={a}
            onClick={() => sendMessage(a)}
            disabled={state.isChatRunning}
            className="text-[10px] px-2 py-1 rounded-full border border-teal-200 text-teal-700 bg-teal-50 hover:bg-teal-100 disabled:opacity-40 transition-colors"
          >
            {a}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="px-3 py-2.5 border-t border-slate-100 flex-shrink-0">
        {!isPrototype && (
          <p className="text-[9px] text-slate-400 mb-1.5 font-mono">Chat unavailable in Connected mode — HERMES API not wired</p>
        )}
        <div className="flex items-end gap-2">
          <textarea
            rows={2}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
            placeholder={isPrototype ? 'Ask HERMES (simulated)…' : 'HERMES not connected'}
            disabled={state.isChatRunning || !isPrototype}
            className="flex-1 px-3 py-2 text-xs border border-slate-200 rounded-lg resize-none focus:outline-none focus:ring-1 focus:ring-teal-400 focus:border-teal-400 disabled:opacity-60 min-h-[40px]"
          />
          <button
            onClick={() => sendMessage()}
            disabled={state.isChatRunning || !input.trim() || !isPrototype}
            className="h-9 w-9 flex items-center justify-center rounded-lg bg-teal-600 text-white hover:bg-teal-700 disabled:opacity-40 flex-shrink-0 transition-colors"
          >
            {state.isChatRunning ? <IconLoader size={14} className="animate-spin" /> : <IconSend size={14} />}
          </button>
        </div>
      </div>
    </div>
  );
}
