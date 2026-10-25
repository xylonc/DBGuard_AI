import React, { createContext, useContext, useReducer, useCallback } from 'react';
import type {
  AppMode, NavView, AssessmentReport, HandoffStatus,
  ChatMessage, ChatContext, ServiceConfig
} from '@/types/api';

interface WorkflowState {
  mode: AppMode;
  activeView: NavView;
  activeWorkflowStep: number;
  completedSteps: number[];
  snapshotId: string | null;
  handoffId: string | null;
  benchmarkId: string;
  environment: string;
  assessment: AssessmentReport | null;
  handoffStatus: HandoffStatus | null;
  chatMessages: ChatMessage[];
  chatContext: ChatContext;
  isChatRunning: boolean;
  isChatOpen: boolean;
  serviceConfig: ServiceConfig;
  selectedControlId: string | null;
}

type Action =
  | { type: 'SET_MODE'; mode: AppMode }
  | { type: 'SET_VIEW'; view: NavView }
  | { type: 'SET_WORKFLOW_STEP'; step: number }
  | { type: 'COMPLETE_STEP'; step: number }
  | { type: 'START_NEW_WORKFLOW' }
  | { type: 'SET_SNAPSHOT_ID'; id: string | null }
  | { type: 'SET_HANDOFF_ID'; id: string | null }
  | { type: 'SET_BENCHMARK_ID'; id: string }
  | { type: 'SET_ENVIRONMENT'; env: string }
  | { type: 'SET_ASSESSMENT'; assessment: AssessmentReport | null }
  | { type: 'SET_HANDOFF_STATUS'; status: HandoffStatus | null }
  | { type: 'ADD_CHAT_MESSAGE'; message: ChatMessage }
  | { type: 'CLEAR_CHAT' }
  | { type: 'SET_CHAT_CONTEXT'; context: Partial<ChatContext> }
  | { type: 'SET_CHAT_RUNNING'; running: boolean }
  | { type: 'TOGGLE_CHAT' }
  | { type: 'SET_CHAT_OPEN'; open: boolean }
  | { type: 'SET_SERVICE_CONFIG'; config: Partial<ServiceConfig> }
  | { type: 'SET_SELECTED_CONTROL'; id: string | null };

const defaultServiceConfig: ServiceConfig = {
  mainApi: 'http://localhost:8011',
  demoApi: 'http://localhost:8010',
  composeApi: 'http://localhost:8000',
  hermesApi: 'http://localhost:8642',
  mcpApi: 'http://localhost:8001',
};

const initialState: WorkflowState = {
  mode: 'connected',
  activeView: 'home',
  activeWorkflowStep: 1,
  completedSteps: [],
  snapshotId: null,
  handoffId: null,
  benchmarkId: 'cis-pg17-v1.1.0',
  environment: 'dev',
  assessment: null,
  handoffStatus: null,
  chatMessages: [],
  chatContext: { benchmark_id: 'cis-pg17-v1.1.0', environment: 'dev', stage: 0 },
  isChatRunning: false,
  isChatOpen: typeof window !== 'undefined' && window.innerWidth >= 1024,
  serviceConfig: defaultServiceConfig,
  selectedControlId: null,
};

// Invalidate assessment + sandbox results but keep snapshot/benchmark selections
const downstreamReset = {
  assessment: null,
  handoffStatus: null,
  handoffId: null,
};

function reducer(state: WorkflowState, action: Action): WorkflowState {
  switch (action.type) {
    case 'SET_MODE': {
      const changed = action.mode !== state.mode;
      return {
        ...state,
        mode: action.mode,
        ...(changed ? { ...downstreamReset, completedSteps: state.completedSteps.filter(s => s < 3) } : {}),
      };
    }
    case 'SET_VIEW': return { ...state, activeView: action.view };
    case 'SET_WORKFLOW_STEP': return { ...state, activeWorkflowStep: action.step };
    case 'COMPLETE_STEP':
      return state.completedSteps.includes(action.step)
        ? state
        : { ...state, completedSteps: [...state.completedSteps, action.step] };
    case 'START_NEW_WORKFLOW':
      return {
        ...state,
        activeView: 'workflows',
        activeWorkflowStep: 1,
        completedSteps: [],
        snapshotId: null,
        handoffId: null,
        assessment: null,
        handoffStatus: null,
        selectedControlId: null,
        chatContext: { benchmark_id: state.benchmarkId, environment: state.environment, stage: 1 },
      };
    case 'SET_SNAPSHOT_ID': {
      const changed = action.id !== state.snapshotId;
      return {
        ...state,
        snapshotId: action.id,
        ...(changed ? { ...downstreamReset, completedSteps: state.completedSteps.filter(s => s < 4) } : {}),
      };
    }
    case 'SET_HANDOFF_ID': return { ...state, handoffId: action.id };
    case 'SET_BENCHMARK_ID': {
      const changed = action.id !== state.benchmarkId;
      return {
        ...state,
        benchmarkId: action.id,
        ...(changed ? { ...downstreamReset, completedSteps: state.completedSteps.filter(s => s < 4) } : {}),
      };
    }
    case 'SET_ENVIRONMENT': return { ...state, environment: action.env };
    case 'SET_ASSESSMENT': return { ...state, assessment: action.assessment };
    case 'SET_HANDOFF_STATUS': return { ...state, handoffStatus: action.status };
    case 'ADD_CHAT_MESSAGE': return { ...state, chatMessages: [...state.chatMessages, action.message] };
    case 'CLEAR_CHAT': return { ...state, chatMessages: [] };
    case 'SET_CHAT_CONTEXT': return { ...state, chatContext: { ...state.chatContext, ...action.context } };
    case 'SET_CHAT_RUNNING': return { ...state, isChatRunning: action.running };
    case 'TOGGLE_CHAT': return { ...state, isChatOpen: !state.isChatOpen };
    case 'SET_CHAT_OPEN': return { ...state, isChatOpen: action.open };
    case 'SET_SERVICE_CONFIG': return { ...state, serviceConfig: { ...state.serviceConfig, ...action.config } };
    case 'SET_SELECTED_CONTROL': return { ...state, selectedControlId: action.id };
    default: return state;
  }
}

interface WorkflowContextValue {
  state: WorkflowState;
  dispatch: React.Dispatch<Action>;
  setMode: (mode: AppMode) => void;
  setView: (view: NavView) => void;
  setWorkflowStep: (step: number) => void;
  advanceStep: () => void;
}

const WorkflowContext = createContext<WorkflowContextValue | null>(null);

export function WorkflowProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);

  const setMode = useCallback((mode: AppMode) => dispatch({ type: 'SET_MODE', mode }), []);
  const setView = useCallback((view: NavView) => dispatch({ type: 'SET_VIEW', view }), []);
  const setWorkflowStep = useCallback((step: number) => dispatch({ type: 'SET_WORKFLOW_STEP', step }), []);
  const advanceStep = useCallback(() => {
    dispatch({ type: 'SET_WORKFLOW_STEP', step: Math.min(state.activeWorkflowStep + 1, 7) });
  }, [state.activeWorkflowStep]);

  return (
    <WorkflowContext.Provider value={{ state, dispatch, setMode, setView, setWorkflowStep, advanceStep }}>
      {children}
    </WorkflowContext.Provider>
  );
}

export function useWorkflow() {
  const ctx = useContext(WorkflowContext);
  if (!ctx) throw new Error('useWorkflow must be used within WorkflowProvider');
  return ctx;
}
