import { useWorkflow } from '@/store/workflowStore';
import { WorkflowStepper } from '@/components/shared/WorkflowStepper';
import { BenchmarkView } from './BenchmarkView';
import { CollectorView } from './CollectorView';
import { SnapshotView } from './SnapshotView';
import { AssessmentView } from './AssessmentView';
import { SandboxView } from './SandboxView';
import { DBAReviewView } from './DBAReviewView';
import { RecollectView } from './RecollectView';

export function WorkflowsView() {
  const { state } = useWorkflow();
  const step = state.activeWorkflowStep;

  return (
    <div className="flex flex-col h-full">
      {/* Stepper */}
      <div className="bg-white border-b border-slate-200 px-4 py-2.5 flex-shrink-0 overflow-x-auto">
        <WorkflowStepper />
      </div>

      {/* Step content */}
      <div className="flex-1 overflow-y-auto">
        {step === 1 && <BenchmarkView />}
        {step === 2 && <CollectorView />}
        {step === 3 && <SnapshotView />}
        {step === 4 && <AssessmentView />}
        {step === 5 && <SandboxView />}
        {step === 6 && <DBAReviewView />}
        {step === 7 && <RecollectView />}
      </div>
    </div>
  );
}
