import { useWorkflow } from '@/store/workflowStore';
import type { StepStatus } from '@/types/api';
import { IconCheck, IconAlertTriangle, IconLoader } from './icons';

const steps = [
  { num: 1, label: 'Benchmark',      short: 'Benchmark' },
  { num: 2, label: 'Collect',        short: 'Collect' },
  { num: 3, label: 'Import snapshot', short: 'Snapshot' },
  { num: 4, label: 'Assess',         short: 'Assess' },
  { num: 5, label: 'Sandbox test',   short: 'Sandbox' },
  { num: 6, label: 'DBA review',     short: 'DBA' },
  { num: 7, label: 'Recollect',      short: 'Recollect' },
];

function deriveStatus(stepNum: number, state: ReturnType<typeof useWorkflow>['state']): StepStatus {
  if (state.completedSteps.includes(stepNum)) return 'complete';
  if (stepNum === 4 && state.assessment === null && state.isChatRunning) return 'running';
  if (stepNum === 5 && state.handoffStatus?.lifecycle === 'RUNNING') return 'running';
  if (stepNum === 5 && state.handoffStatus?.result === 'FAILED') return 'needs-attention';
  if (stepNum === 5 && state.handoffStatus?.result === 'NEEDS_REVIEW') return 'needs-attention';
  if (stepNum === 5 && state.handoffStatus?.result === 'CLEANUP_FAILED') return 'needs-attention';
  return 'not-started';
}

export function WorkflowStepper() {
  const { state, dispatch, setWorkflowStep } = useWorkflow();
  const current = state.activeWorkflowStep;

  return (
    <div className="flex items-center gap-0 overflow-x-auto">
      {steps.map((step, i) => {
        const status = deriveStatus(step.num, state);
        const active = step.num === current;

        return (
          <div key={step.num} className="flex items-center">
            <button
              onClick={() => {
                setWorkflowStep(step.num);
                dispatch({ type: 'SET_VIEW', view: 'workflows' });
              }}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs font-medium transition-colors whitespace-nowrap
                ${active ? 'bg-teal-600 text-white' :
                  status === 'complete' ? 'bg-teal-50 text-teal-700 hover:bg-teal-100 cursor-pointer' :
                  status === 'needs-attention' ? 'bg-amber-50 text-amber-700 hover:bg-amber-100 cursor-pointer' :
                  status === 'running' ? 'bg-blue-50 text-blue-700 cursor-pointer' :
                  'text-slate-400 hover:text-slate-600 cursor-pointer'}
              `}
            >
              <span
                className={`rounded-full border flex items-center justify-center text-[10px] font-bold flex-shrink-0
                  ${active ? 'border-white text-white bg-transparent' :
                    status === 'complete' ? 'border-teal-500 bg-teal-500 text-white' :
                    status === 'needs-attention' ? 'border-amber-500 bg-amber-500 text-white' :
                    status === 'running' ? 'border-blue-400 bg-blue-400 text-white' :
                    'border-slate-300 text-slate-400'}
                `}
                style={{ width: 18, height: 18 }}
              >
                {status === 'complete' ? <IconCheck size={10} /> :
                 status === 'needs-attention' ? <IconAlertTriangle size={10} /> :
                 status === 'running' ? <IconLoader size={10} className="animate-spin" /> :
                 step.num}
              </span>
              <span className="hidden sm:inline">{step.short}</span>
            </button>
            {i < steps.length - 1 && (
              <div className={`w-4 h-px mx-0.5 flex-shrink-0 ${status === 'complete' ? 'bg-teal-300' : 'bg-slate-200'}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}
