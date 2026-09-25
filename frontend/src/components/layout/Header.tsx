import { useLive } from "@/store/liveStore"
import { useState } from "react"
import { useWorkflow } from "@/store/workflowStore"
import {
  IconChevronDown,
  IconMenu,
  IconMessageSquare,
} from "@/components/shared/icons"

const viewLabels: Record<string, string> = {
  home: "Overview",
  workflows: "Workflows",
  library: "Library",
  settings: "Settings",
}

interface HeaderProps {
  onToggleNav?: () => void
  onToggleChat?: () => void
}

export function Header({ onToggleNav, onToggleChat }: HeaderProps) {
  const { state: ui } = useWorkflow()
  const { state: live } = useLive()
  const state =
    ui.mode === "connected"
      ? {
          ...ui,
          benchmarkId: live.benchmark,
          snapshotId: live.snapshot?.snapshot_id,
          environment: live.environment,
          handoffId: live.handoffId,
        }
      : ui
  const [showDetails, setShowDetails] = useState(false)

  const modeColors =
    state.mode === "prototype"
      ? "bg-amber-50 text-amber-700 border-amber-200"
      : "bg-teal-50 text-teal-700 border-teal-200"

  return (
    <header className="bg-white border-b border-slate-200 flex-shrink-0">
      <div className="flex items-center gap-3 px-4 h-12">
        <button
          onClick={onToggleNav}
          className="lg:hidden text-slate-400 hover:text-slate-600 p-1"
        >
          <IconMenu size={18} />
        </button>

        <span
          className={`flex-shrink-0 inline-flex items-center px-2 py-0.5 text-[10px] font-mono font-medium rounded border ${modeColors}`}
        >
          {state.mode === "prototype" ? "PROTOTYPE" : "CONNECTED"}
        </span>

        <div className="flex items-center gap-3 text-xs text-slate-500 flex-1 min-w-0 overflow-hidden">
          <span className="font-medium text-slate-700 whitespace-nowrap">
            {viewLabels[state.activeView] ?? state.activeView}
          </span>
          {state.activeView === "workflows" && (
            <>
              <span className="text-slate-300">/</span>
              <span className="hidden sm:inline whitespace-nowrap text-slate-500">
                Step {state.activeWorkflowStep} of 7
              </span>
            </>
          )}
          {state.benchmarkId && (
            <>
              <span className="text-slate-300 hidden md:inline">|</span>
              <span className="hidden md:inline whitespace-nowrap">
                Benchmark:{" "}
                <span className="font-mono text-slate-700">
                  {state.benchmarkId}
                </span>
              </span>
            </>
          )}
          {state.snapshotId && (
            <>
              <span className="text-slate-300 hidden lg:inline">|</span>
              <span className="hidden lg:inline whitespace-nowrap">
                Snapshot:{" "}
                <span className="font-mono text-slate-700">
                  {state.snapshotId.slice(0, 16)}…
                </span>
              </span>
            </>
          )}
        </div>

        <button
          onClick={() => setShowDetails((v) => !v)}
          className="hidden sm:flex items-center gap-1 text-[10px] text-slate-400 hover:text-slate-600 border border-slate-200 rounded px-1.5 py-0.5"
        >
          Debug
          <IconChevronDown
            size={10}
            className={`transition-transform ${
              showDetails ? "rotate-180" : ""
            }`}
          />
        </button>

        <button
          onClick={onToggleChat}
          className="lg:hidden text-slate-400 hover:text-slate-600 p-1"
        >
          <IconMessageSquare size={18} />
        </button>
      </div>

      {showDetails && (
        <div className="px-4 py-2 bg-slate-50 border-t border-slate-100 text-[11px] font-mono text-slate-500 flex flex-wrap gap-x-6 gap-y-1">
          <span>mode: {state.mode}</span>
          <span>view: {state.activeView}</span>
          <span>step: {state.activeWorkflowStep}</span>
          <span>completed: [{state.completedSteps.join(",")}]</span>
          <span>benchmark: {state.benchmarkId}</span>
          <span>env: {state.environment}</span>
          <span>snapshot_id: {state.snapshotId ?? "null"}</span>
          <span>handoff_id: {state.handoffId ?? "null"}</span>
          <span>main_api: {state.serviceConfig.mainApi}</span>
          <span>hermes_api: {state.serviceConfig.hermesApi}</span>
        </div>
      )}
    </header>
  )
}
