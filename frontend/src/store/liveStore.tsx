import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react"
import { api, request, type Service } from "@/adapters/live"
type LiveState = {
  service: Service
  snapshot: any
  assessment: any
  demo: any
  handoffId: string
  result: any
  benchmark: string
  environment: string
  templateVersion: number
  evidenceIds: string
  retryMode: string
  messages: { role: string; content: string }[]
  chatJob: string
  busy: string
  error: string
  verification: any
}
const fresh = (): LiveState => ({
  service: "demo",
  snapshot: null,
  assessment: null,
  demo: null,
  handoffId: "",
  result: null,
  benchmark: "cis-pg17-v1.1.0",
  environment: "test",
  templateVersion: 1,
  evidenceIds: "",
  retryMode: "adaptive",
  messages: [],
  chatJob: "",
  busy: "",
  error: "",
  verification: null,
})
function restore() {
  try {
    const value = JSON.parse(
      sessionStorage.getItem("dbguard-live-v1") || "null",
    )
    return value ? { ...fresh(), ...value, busy: "" } : fresh()
  } catch {
    return fresh()
  }
}
const Context = createContext<any>(null)
export function LiveProvider({ children }: { children: ReactNode }) {
  const [state, set] = useState<LiveState>(restore)
  const current = useRef(state)
  current.current = state
  const lock = useRef(false)
  const generation = useRef(0)
  const patch = (value: Partial<LiveState>) => set((s) => ({ ...s, ...value }))
  useEffect(() => {
    try { sessionStorage.setItem("dbguard-live-v1", JSON.stringify(state)) } catch { /* Keep oversized evidence in memory; the backend retains the run. */ }
  }, [state])
  async function action(label: string, fn: () => Promise<void>) {
    if (lock.current) throw new Error("An operation is already running")
    lock.current = true
    patch({ busy: label, error: "" })
    try {
      await fn()
    } catch (e) {
      patch({ error: e instanceof Error ? e.message : String(e) })
    } finally {
      lock.current = false
      patch({ busy: "" })
    }
  }
  async function sync() {
    const s = current.current
    const gen = generation.current
    if (s.service === "demo") {
      const context = await api("demo", "/review/context")
      if (gen !== generation.current) return
      if (context.workflow.snapshot_id !== s.snapshot?.snapshot_id) {
        generation.current++
        patch({snapshot: null, assessment: null, result: null, handoffId: "", verification: null, error: "The demo session changed. Load the current live demo again."})
        return
      }
      patch({
        demo: context.workflow,
        ...(context.last_result ? { result: context.last_result } : {}),
      })
    } else if (s.handoffId) {
      const h = await api(
        "main",
        `/api/v1/sandbox/handoffs/${encodeURIComponent(s.handoffId)}`,
      )
      if (
        gen === generation.current &&
        h.snapshot_id === s.snapshot?.snapshot_id
      )
        patch({ result: h.result ?? null })
    }
  }
  async function loadDemo() {
    await action("Loading live demo", async () => {
      const d = await api("demo", "/api/v1/demo/workflow")
      const snapshot = await api("demo", `/api/v1/snapshots/${d.snapshot_id}`)
      const assessment = await api(
        "demo",
        `/api/v1/snapshots/${d.snapshot_id}/spec-assessment?benchmark_id=${d.benchmark_id}`,
      )
      const context = await api("demo", "/review/context")
      generation.current++
      patch({
        service: "demo",
        demo: d,
        snapshot,
        assessment,
        benchmark: d.benchmark_id,
        environment: d.environment,
        evidenceIds: d.evidence_ids.join(", "),
        templateVersion: d.template_version,
        retryMode: d.retry_mode,
        result: context.last_result,
        handoffId: "",
        verification: null,
        messages: [],
      })
    })
  }
  async function loadSnapshot(id: string) {
    await action("Loading snapshot", async () => {
      const snapshot = await api(
        current.current.service,
        `/api/v1/snapshots/${encodeURIComponent(id)}`,
      )
      generation.current++
      patch({
        snapshot,
        assessment: null,
        result: null,
        handoffId: "",
        verification: null,
        messages: [],
      })
    })
  }
  async function upload(file: File) {
    await action("Importing snapshot", async () => {
      const receipt = await api(
        current.current.service,
        "/api/v1/snapshots",
        JSON.parse(await file.text()),
      )
      const snapshot = await api(
        current.current.service,
        `/api/v1/snapshots/${receipt.snapshot_id}`,
      )
      generation.current++
      patch({
        snapshot,
        assessment: null,
        result: null,
        handoffId: "",
        verification: null,
        messages: [],
      })
    })
  }
  async function assess() {
    await action("Assessing exact specs", async () => {
      const s = current.current
      if (!s.snapshot) throw new Error("Import a snapshot first")
      const assessment = await api(
        s.service,
        `/api/v1/snapshots/${s.snapshot.snapshot_id}/spec-assessment?benchmark_id=${encodeURIComponent(s.benchmark)}`,
      )
      patch({ assessment })
    })
  }
  async function run() {
    await action("Testing in disposable PostgreSQL", async () => {
      const s = current.current
      if (!s.snapshot || !s.assessment)
        throw new Error("Assess the selected snapshot first")
      let id = s.handoffId
      if (!id) {
        const prep = await api(s.service, "/api/v1/sandbox/handoffs", {
          snapshot_id: s.snapshot.snapshot_id,
          benchmark_id: s.benchmark,
          environment: s.environment,
          template_version: s.templateVersion,
          evidence_ids: s.evidenceIds
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean),
          retry_mode: s.retryMode,
          retry_template_versions: [],
        })
        id = prep.handoff_id
        patch({ handoffId: id })
      }
      const result = await api(
        s.service,
        `/api/v1/sandbox/handoffs/${id}/run`,
        {},
      )
      patch({ result })
    })
  }
  async function send(content: string) {
    if (lock.current || current.current.chatJob) return
    const s = current.current
    const messages = [...s.messages, { role: "user", content }]
    patch({ messages, error: "" })
    await action("Sending to live HERMES", async () => {
      const job = await request("/bridge/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          service: s.service,
          messages: messages.slice(-30),
          context: {
            snapshot_id: s.snapshot?.snapshot_id,
            benchmark_id: s.benchmark,
            environment: s.environment,
            handoff_id: s.handoffId,
            run_id: s.result?.run_id,
          },
        }),
      })
      patch({ chatJob: job.id })
    })
  }
  useEffect(() => {
    if (!state.chatJob) return
    let cancelled = false
    const id = state.chatJob
    const timer = setInterval(async () => {
      try {
        const job = await request(`/bridge/chat/${id}`)
        if (cancelled || job.status === "running") return
        clearInterval(timer)
        if (job.status === "failed") {
          patch({ chatJob: "", error: job.error })
          return
        }
        const content = job.response?.choices?.[0]?.message?.content
        if (typeof content !== "string")
          throw new Error("HERMES returned no answer")
        set((s) => ({
          ...s,
          chatJob: "",
          messages: [...s.messages, { role: "assistant", content }],
        }))
        await sync()
        const s = current.current
        if (s.snapshot) {
          const assessment = await api(
            s.service,
            `/api/v1/snapshots/${s.snapshot.snapshot_id}/spec-assessment?benchmark_id=${encodeURIComponent(s.benchmark)}`,
          )
          if (!cancelled) patch({ assessment })
        }
      } catch (e) {
        if (!cancelled) patch({ chatJob: "", error: String(e) })
      }
    }, 2000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [state.chatJob])
  // Backend records remain authoritative, including runs started in the separate HERMES dashboard.
  useEffect(() => {
    if (!state.snapshot) return
    let pending = false
    const timer = setInterval(async () => {
      if (pending) return
      pending = true
      try {
        await sync()
      } catch {
        /* Explicit refresh displays failures; background polls never replace evidence. */
      } finally {
        pending = false
      }
    }, 5000)
    return () => clearInterval(timer)
  }, [state.snapshot?.snapshot_id, state.service, state.handoffId])
  function reset(service: Service = state.service) {
    if (state.busy || state.chatJob) return
    generation.current++
    set({ ...fresh(), service })
  }
  function configure(value: Partial<LiveState>) {
    if (state.busy || state.chatJob) return
    generation.current++
    patch({
      ...value,
      ...(value.benchmark !== undefined ? {assessment: null} : {}),
      result: null,
      handoffId: "",
      verification: null,
      messages: [],
    })
  }
  return (
    <Context.Provider
      value={{
        state,
        patch,
        configure,
        action,
        reset,
        loadDemo,
        loadSnapshot,
        upload,
        assess,
        run,
        sync,
        send,
      }}
    >
      {children}
    </Context.Provider>
  )
}
export function useLive() {
  return useContext(Context) as {
    state: LiveState
    patch: (v: Partial<LiveState>) => void
    configure: (v: Partial<LiveState>) => void
    action: (label: string, fn: () => Promise<void>) => Promise<void>
    reset: (s?: Service) => void
    loadDemo: () => Promise<void>
    loadSnapshot: (id: string) => Promise<void>
    upload: (f: File) => Promise<void>
    assess: () => Promise<void>
    run: () => Promise<void>
    sync: () => Promise<void>
    send: (s: string) => Promise<void>
  }
}
