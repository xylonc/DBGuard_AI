import { LiveProvider } from "@/store/liveStore"
import { WorkflowProvider } from "@/store/workflowStore"
import { AppShell } from "@/components/layout/AppShell"

export default function App() {
  return (
    <WorkflowProvider>
      <LiveProvider>
        <AppShell />
      </LiveProvider>
    </WorkflowProvider>
  )
}
