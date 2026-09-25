import { LiveHome, LiveWorkflow, LiveChat, LiveSettings } from "@/live/LiveUI"
import { EndpointPanel } from "@/live/EndpointPanel"
import { useState } from "react"
import { useWorkflow } from "@/store/workflowStore"
import { LeftNav } from "./LeftNav"
import { Header } from "./Header"
import { ChatPanel } from "./ChatPanel"
import { OverviewView } from "@/views/OverviewView"
import { WorkflowsView } from "@/views/WorkflowsView"
import { KnowledgeView } from "@/views/KnowledgeView"
import { SettingsView } from "@/views/SettingsView"
import { IconMessageSquare } from "@/components/shared/icons"

function ActiveView() {
  const { state } = useWorkflow()
  switch (state.activeView) {
    case "home":
      return state.mode === "connected" ? <LiveHome /> : <OverviewView />
    case "workflows":
      return state.mode === "connected" ? <LiveWorkflow /> : <WorkflowsView />
    case "library":
      return state.mode === "connected" ? <EndpointPanel /> : <KnowledgeView />
    case "settings":
      return state.mode === "connected" ? <LiveSettings /> : <SettingsView />
    default:
      return <OverviewView />
  }
}

export function AppShell() {
  const { state, dispatch } = useWorkflow()
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  return (
    <div className="h-full flex flex-col">
      {/* Mobile nav overlay */}
      {mobileNavOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div
            className="absolute inset-0 bg-black/30"
            onClick={() => setMobileNavOpen(false)}
          />
          <div className="absolute left-0 top-0 bottom-0 w-64 z-50">
            <LeftNav onClose={() => setMobileNavOpen(false)} />
          </div>
        </div>
      )}

      {/* Main layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left nav — desktop */}
        <div className="hidden lg:flex flex-col w-[240px] flex-shrink-0">
          <LeftNav />
        </div>

        {/* Main workspace */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <Header
            onToggleNav={() => setMobileNavOpen((v) => !v)}
            onToggleChat={() => dispatch({ type: "TOGGLE_CHAT" })}
          />
          <main className="flex-1 overflow-y-auto relative">
            <ActiveView />

            {/* HERMES reopen button — visible when chat is closed */}
            {!state.isChatOpen && (
              <button
                onClick={() => dispatch({ type: "SET_CHAT_OPEN", open: true })}
                className="fixed bottom-5 right-5 z-30 hidden lg:flex items-center gap-2 px-3 py-2 bg-teal-600 text-white text-xs font-medium rounded-full shadow-lg hover:bg-teal-700 transition-colors"
              >
                <IconMessageSquare size={14} />
                HERMES
              </button>
            )}
          </main>
        </div>

        {/* Right chat panel — desktop */}
        {state.isChatOpen && (
          <div className="hidden lg:flex flex-col w-[340px] flex-shrink-0">
            {state.mode === "connected" ? (
              <LiveChat
                onClose={() => dispatch({ type: "SET_CHAT_OPEN", open: false })}
              />
            ) : (
              <ChatPanel
                onClose={() => dispatch({ type: "SET_CHAT_OPEN", open: false })}
              />
            )}
          </div>
        )}
      </div>

      {/* Mobile chat drawer */}
      {state.isChatOpen && (
        <div className="lg:hidden fixed inset-0 z-40">
          <div
            className="absolute inset-0 bg-black/30"
            onClick={() => dispatch({ type: "SET_CHAT_OPEN", open: false })}
          />
          <div className="absolute bottom-0 left-0 right-0 h-[65vh] z-50 rounded-t-xl overflow-hidden shadow-xl">
            {state.mode === "connected" ? (
              <LiveChat
                onClose={() => dispatch({ type: "SET_CHAT_OPEN", open: false })}
              />
            ) : (
              <ChatPanel
                onClose={() => dispatch({ type: "SET_CHAT_OPEN", open: false })}
              />
            )}
          </div>
        </div>
      )}

      {/* Mobile chat reopen */}
      {!state.isChatOpen && (
        <button
          onClick={() => dispatch({ type: "SET_CHAT_OPEN", open: true })}
          className="lg:hidden fixed bottom-5 right-5 z-30 flex items-center gap-2 px-3 py-2 bg-teal-600 text-white text-xs font-medium rounded-full shadow-lg hover:bg-teal-700 transition-colors"
        >
          <IconMessageSquare size={14} />
          HERMES
        </button>
      )}
    </div>
  )
}
