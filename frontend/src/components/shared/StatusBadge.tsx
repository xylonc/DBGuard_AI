import type { ReactNode } from 'react';
import type { FindingStatus, SandboxResult, HandoffLifecycle, BundleStatus } from '@/types/api';
import { IconCheck, IconX, IconAlertTriangle, IconInfo } from './icons';

type Status = FindingStatus | SandboxResult | HandoffLifecycle | BundleStatus | string;

const configs: Record<string, { bg: string; text: string; border: string; icon?: ReactNode; label?: string }> = {
  PASS:            { bg: 'bg-green-50', text: 'text-green-700', border: 'border-green-200', icon: <IconCheck size={11} /> },
  FAIL:            { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-200', icon: <IconX size={11} /> },
  MANUAL:          { bg: 'bg-amber-50', text: 'text-amber-700', border: 'border-amber-200', icon: <IconInfo size={11} /> },
  MANUAL_REVIEW:   { bg: 'bg-amber-50', text: 'text-amber-700', border: 'border-amber-200', icon: <IconInfo size={11} />, label: 'MANUAL REVIEW' },
  NEEDS_CAPABILITY:{ bg: 'bg-purple-50', text: 'text-purple-700', border: 'border-purple-200', icon: <IconAlertTriangle size={11} />, label: 'NEEDS CAPABILITY' },
  NOT_COLLECTED:   { bg: 'bg-slate-100', text: 'text-slate-600', border: 'border-slate-200', icon: <IconInfo size={11} />, label: 'NOT COLLECTED' },
  STALE:           { bg: 'bg-orange-50', text: 'text-orange-700', border: 'border-orange-200', icon: <IconInfo size={11} /> },
  ERROR:           { bg: 'bg-red-50', text: 'text-red-600', border: 'border-red-200', icon: <IconX size={11} /> },
  GAPPED:          { bg: 'bg-slate-100', text: 'text-slate-600', border: 'border-slate-200', icon: <IconInfo size={11} /> },
  VERIFIED:        { bg: 'bg-green-50', text: 'text-green-700', border: 'border-green-200', icon: <IconCheck size={11} /> },
  FAILED:          { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-200', icon: <IconX size={11} /> },
  NEEDS_REVIEW:    { bg: 'bg-amber-50', text: 'text-amber-700', border: 'border-amber-200', icon: <IconAlertTriangle size={11} />, label: 'NEEDS REVIEW' },
  CLEANUP_FAILED:  { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-200', icon: <IconX size={11} />, label: 'CLEANUP FAILED' },
  PREPARED:        { bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-200', icon: <IconInfo size={11} /> },
  RUNNING:         { bg: 'bg-teal-50', text: 'text-teal-700', border: 'border-teal-200', icon: <IconInfo size={11} /> },
  FINISHED:        { bg: 'bg-slate-100', text: 'text-slate-600', border: 'border-slate-200', icon: <IconInfo size={11} /> },
  REJECTED:        { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-200', icon: <IconX size={11} /> },
  READY:           { bg: 'bg-green-50', text: 'text-green-700', border: 'border-green-200', icon: <IconCheck size={11} /> },
  PENDING:         { bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-200', icon: <IconInfo size={11} /> },
  UNAVAILABLE:     { bg: 'bg-slate-100', text: 'text-slate-500', border: 'border-slate-200', icon: <IconInfo size={11} /> },
  EXPIRED:         { bg: 'bg-orange-50', text: 'text-orange-700', border: 'border-orange-200', icon: <IconAlertTriangle size={11} /> },
};

const fallback = { bg: 'bg-slate-100', text: 'text-slate-600', border: 'border-slate-200' };

interface StatusBadgeProps {
  status: Status;
  size?: 'sm' | 'md';
  showIcon?: boolean;
}

export function StatusBadge({ status, size = 'sm', showIcon = true }: StatusBadgeProps) {
  const cfg = configs[status] ?? fallback;
  const label = cfg.label ?? status;
  const px = size === 'md' ? 'px-2 py-0.5' : 'px-1.5 py-0.5';
  const fs = size === 'md' ? 'text-xs' : 'text-[11px]';

  return (
    <span className={`inline-flex items-center gap-1 ${px} ${fs} font-mono font-medium rounded border ${cfg.bg} ${cfg.text} ${cfg.border} leading-none whitespace-nowrap`}>
      {showIcon && cfg.icon}
      {label}
    </span>
  );
}
