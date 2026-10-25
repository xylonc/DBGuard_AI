import type { ReactNode } from 'react';

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
      {icon && <div className="text-slate-300 mb-4">{icon}</div>}
      <p className="text-sm font-medium text-slate-600">{title}</p>
      {description && <p className="text-xs text-slate-400 mt-1 max-w-xs">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function LoadingState({ label = 'Loading...' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-slate-400 text-sm">
      <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M21 12a9 9 0 11-6.219-8.56" strokeLinecap="round"/>
      </svg>
      {label}
    </div>
  );
}

export function ErrorState({ message, detail, onRetry }: { message: string; detail?: string; onRetry?: () => void }) {
  return (
    <div className="rounded-lg border border-red-200 bg-red-50 p-4">
      <p className="text-sm font-medium text-red-700">{message}</p>
      {detail && <p className="text-xs text-red-600 mt-1 font-mono">{detail}</p>}
      {onRetry && (
        <button onClick={onRetry} className="mt-2 text-xs text-red-600 underline hover:no-underline">Retry</button>
      )}
    </div>
  );
}

export function NotConnectedState({ feature }: { feature: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 flex items-start gap-3">
      <div className="w-1.5 h-1.5 rounded-full bg-slate-400 mt-1.5 flex-shrink-0" />
      <div>
        <p className="text-sm font-medium text-slate-600">{feature}</p>
        <p className="text-xs text-slate-400 mt-0.5">Not connected — no HTTP endpoint exists for this feature yet. See integration backlog.</p>
      </div>
    </div>
  );
}

export function PlannedFeature({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono rounded border border-slate-200 bg-slate-50 text-slate-500">
      <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
      {label} — Planned
    </span>
  );
}
