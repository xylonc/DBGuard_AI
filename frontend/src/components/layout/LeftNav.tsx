import type { ReactNode } from 'react';
import { useWorkflow } from '@/store/workflowStore';
import type { NavView } from '@/types/api';
import {
  IconHome, IconWorkflow, IconBookOpen, IconSettings, IconDatabase
} from '@/components/shared/icons';

const navItems: { view: NavView; label: string; icon: ReactNode }[] = [
  { view: 'home',      label: 'Home',     icon: <IconHome size={15} /> },
  { view: 'workflows', label: 'Workflows', icon: <IconWorkflow size={15} /> },
  { view: 'library',   label: 'Library',   icon: <IconBookOpen size={15} /> },
  { view: 'settings',  label: 'Settings',  icon: <IconSettings size={15} /> },
];

interface LeftNavProps { onClose?: () => void; }

export function LeftNav({ onClose }: LeftNavProps) {
  const { state, dispatch } = useWorkflow();

  function navigate(view: NavView) {
    dispatch({ type: 'SET_VIEW', view });
    onClose?.();
  }

  return (
    <nav className="flex flex-col h-full bg-white border-r border-slate-200 select-none">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-slate-100">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-teal-600 flex items-center justify-center flex-shrink-0">
            <IconDatabase size={14} className="text-white" />
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-800 leading-none">DBGuardAI</p>
            <p className="text-[10px] text-slate-400 mt-0.5 font-mono">CIS PG17 v1.1.0</p>
          </div>
        </div>
      </div>

      {/* Mode toggle */}
      <div className="px-3 py-3 border-b border-slate-100">
        <div className="flex rounded-md border border-slate-200 overflow-hidden text-[11px] font-medium">
          <button
            onClick={() => dispatch({ type: 'SET_MODE', mode: 'prototype' })}
            className={`flex-1 py-1 transition-colors ${state.mode === 'prototype' ? 'bg-amber-50 text-amber-700 border-r border-amber-200' : 'text-slate-500 hover:bg-slate-50 border-r border-slate-200'}`}
          >
            Prototype
          </button>
          <button
            onClick={() => dispatch({ type: 'SET_MODE', mode: 'connected' })}
            className={`flex-1 py-1 transition-colors ${state.mode === 'connected' ? 'bg-teal-50 text-teal-700' : 'text-slate-500 hover:bg-slate-50'}`}
          >
            Connected
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto py-2">
        <div className="px-3">
          {navItems.map(item => (
            <NavItem
              key={item.view}
              label={item.label}
              icon={item.icon}
              active={state.activeView === item.view}
              onClick={() => navigate(item.view)}
            />
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-slate-100">
        <p className="text-[10px] text-slate-400 font-mono leading-snug">
          Connected UI · local build<br />
          Backend contract: Phase 1
        </p>
      </div>
    </nav>
  );
}

function NavItem({ label, icon, active, onClick }: { label: string; icon: ReactNode; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center gap-2.5 px-2 py-1.5 rounded-md text-xs transition-colors text-left
        ${active
          ? 'bg-teal-50 text-teal-700 font-medium border-l-2 border-teal-500 pl-1.5'
          : 'text-slate-600 hover:bg-slate-50 hover:text-slate-800 border-l-2 border-transparent pl-1.5'
        }`}
    >
      <span className={active ? 'text-teal-600' : 'text-slate-400'}>{icon}</span>
      {label}
    </button>
  );
}
