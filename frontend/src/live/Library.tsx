import { useEffect, useState, useRef } from "react"
import { api, request } from "@/adapters/live"
import { Card, Raw } from "./LiveUI"
const field = "block w-full border rounded p-2 mt-1"
const button = "rounded bg-teal-700 text-white px-4 py-2 disabled:opacity-40"
const initial = {
  name: "",
  description: "",
  content: "",
  version: "1",
  risk: "",
  pg: "17",
  reviewer: "",
}
export function Library() {
  const [kind, setKind] = useState("templates")
  const [status, setStatus] = useState("")
  const [search, setSearch] = useState("")
  const [page, setPage] = useState(0)
  const [catalog, setCatalog] = useState<any>(null)
  const [selected, setSelected] = useState<any>(null)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState(initial)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [notice, setNotice] = useState("")
  const [reviewed, setReviewed] = useState(false)
  const [chunks, setChunks] = useState<any>(null)
  const generation = useRef(0)
  async function load(requestPage = page) {
    const ticket = ++generation.current
    setBusy(true)
    setError("")
    setCatalog(null)
    try {
      const result = await api(
        "main",
        `/api/v1/library/${kind}?${new URLSearchParams({ status, search, offset: String(requestPage * 50) }).toString().replace("status=&", "")}`,
      )
      if (ticket === generation.current) setCatalog(result)
    } catch (e) {
      if (ticket === generation.current) setError(String(e))
    } finally {
      if (ticket === generation.current) setBusy(false)
    }
  }
  useEffect(() => {
    void load()
  }, [kind, status, page])
  const update = (key: string, value: string) =>
    setForm((f) => ({ ...f, [key]: value }))
  async function save(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError("")
    setNotice("")
    try {
      const payload =
        kind === "templates"
          ? {
              template_name: form.name,
              description: form.description,
              sql_template: form.content,
              version: Number(form.version),
              pg_version: form.pg,
              risk_level: form.risk || null,
              status: "draft",
            }
          : {
              document_id: form.name,
              title: form.description,
              version: form.version,
              content: form.content,
              effective_date: new Date().toISOString(),
              postgresql_versions: [form.pg],
              environment_applicability: ["all"],
              status: "draft",
            }
      const result = await api(
        "main",
        kind === "templates"
          ? "/api/v1/templates/ingest"
          : "/api/v1/knowledge/documents",
        payload,
      )
      if (result.errors?.length) throw new Error(JSON.stringify(result.errors))
      setNotice(
        kind === "templates"
          ? `${
              result.created
                ? "Saved new draft"
                : "Existing identical SQL returned"
            }: ${result.template_name}, version ${result.version ?? "not returned"}, status ${result.lifecycle_status}.`
          : `Document ${result.document_id} saved. Review its draft before approval.`,
      )
      setCreating(false)
      setForm(initial)
      await load()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }
  async function inspect(row: any) {
    setSelected(row)
    setReviewed(false)
    setForm(initial)
    setChunks(null)
    setError("")
    if (kind === "knowledge") {
      setBusy(true)
      try {
        setChunks(
          await api(
            "main",
            `/api/v1/library/knowledge/${encodeURIComponent(row.document_id)}/content`,
          ),
        )
      } catch (e) {
        setError(String(e))
      } finally {
        setBusy(false)
      }
    }
  }
  async function approve() {
    setBusy(true)
    setError("")
    try {
      const path =
        kind === "templates"
          ? `/api/v1/templates/${encodeURIComponent(selected.template_name)}/approve?version=${selected.version}`
          : `/api/v1/knowledge/documents/${encodeURIComponent(selected.document_id)}/approve`
      await api("main", path, { approved_by: form.reviewer.trim() })
      setNotice("Approval recorded for the reviewed content.")
      setSelected(null)
      await load()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="p-6 max-w-5xl mx-auto space-y-5">
      <h1 className="text-2xl font-semibold">Library</h1>
      <p className="text-slate-600">
        Maintain the SQL templates and supporting evidence used to propose
        fixes. New content starts as a draft.
      </p>
      <div role="tablist" className="flex gap-2">
        {[
          ["templates", "SQL templates"],
          ["knowledge", "Knowledge & evidence"],
        ].map(([id, label]) => (
          <button
            role="tab"
            aria-selected={kind === id}
            disabled={busy}
            className={kind === id ? button : "rounded border px-4 py-2"}
            key={id}
            onClick={() => {
              setKind(id)
              setPage(0)
              setSelected(null)
              setCreating(false)
              setNotice("")
            }}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="flex gap-2 flex-wrap">
        <input
          aria-label="Search Library by name"
          className="border rounded p-2 grow"
          placeholder="Search by name or document ID"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          aria-label="Content status"
          className="border rounded p-2"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value)
            setPage(0)
          }}
        >
          <option value="">All statuses</option>
          {[
            "draft",
            "active",
            "archived",
            ...(kind === "knowledge" ? ["superseded"] : []),
          ].map((v) => (
            <option key={v}>{v}</option>
          ))}
        </select>
        <button
          className={button}
          disabled={busy}
          onClick={() => {
            setPage(0)
            void load(0)
          }}
        >
          Search
        </button>
        <button
          className={button}
          disabled={busy}
          onClick={() => {
            setCreating(true)
            setSelected(null)
            setForm(initial)
          }}
        >
          + Add {kind === "templates" ? "template" : "document"}
        </button>
      </div>
      {error && (
        <p role="alert" className="bg-red-50 text-red-800 p-3 rounded">
          {error}
        </p>
      )}
      {notice && (
        <p role="status" className="bg-teal-50 text-teal-800 p-3 rounded">
          {notice}
        </p>
      )}
      {creating && (
        <Card
          title={
            kind === "templates" ? "New SQL template" : "New evidence document"
          }
        >
          <form onSubmit={save} className="space-y-3">
            <label className="block">
              {kind === "templates" ? "Template name" : "Unique document ID"}
              <input
                required
                maxLength={255}
                className={field}
                value={form.name}
                onChange={(e) => update("name", e.target.value)}
              />
            </label>
            <label className="block">
              {kind === "templates" ? "Description" : "Document title"}
              <input
                required
                className={field}
                value={form.description}
                onChange={(e) => update("description", e.target.value)}
              />
            </label>
            <div className="flex gap-4">
              <label>
                Version
                <input
                  required
                  className={field}
                  type={kind === "templates" ? "number" : "text"}
                  min="1"
                  value={form.version}
                  onChange={(e) => update("version", e.target.value)}
                />
              </label>
              <label>
                PostgreSQL version
                <input
                  required
                  className={field}
                  value={form.pg}
                  onChange={(e) => update("pg", e.target.value)}
                />
              </label>
              {kind === "templates" && (
                <label>
                  Proposed operational risk
                  <select
                    className={field}
                    value={form.risk}
                    onChange={(e) => update("risk", e.target.value)}
                  >
                    <option value="">Not assessed</option>
                    {["low", "medium", "high"].map((v) => (
                      <option key={v}>{v}</option>
                    ))}
                  </select>
                </label>
              )}
            </div>
            <label className="block">
              {kind === "templates"
                ? "SQL template"
                : "Evidence content (at least 100 characters)"}
              <textarea
                required
                minLength={kind === "templates" ? 1 : 100}
                rows={9}
                className={field + " font-mono text-sm"}
                value={form.content}
                onChange={(e) => update("content", e.target.value)}
              />
            </label>
            {kind === "templates" && (
              <p className="text-sm text-slate-500">
                For setting templates use {"{{ param_name | ident }}"} and{" "}
                {"{{ param_value | literal }}"}. Saving does not execute SQL.
                Changed SQL creates a new draft version; identical SQL returns
                its existing version.
              </p>
            )}
            <button className={button} disabled={busy}>
              Save draft
            </button>
            <button
              type="button"
              className="ml-3"
              onClick={() => setCreating(false)}
            >
              Cancel
            </button>
          </form>
        </Card>
      )}
      {kind === "knowledge" && !creating && (
        <Card title="Import evidence workbook">
          <p className="text-sm">
            Upload an XLSX for knowledge ingestion. This does not generate
            executable benchmark specs.
          </p>
          <input
            type="file"
            accept=".xlsx"
            aria-label="Evidence workbook"
            disabled={busy}
            onChange={async (e) => {
              const f = e.target.files?.[0]
              if (!f) return
              setBusy(true)
              setError("")
              try {
                const body = new FormData()
                body.append("file", f)
                const r = await request(
                  "/bridge/main/api/v1/knowledge/upload",
                  { method: "POST", body },
                )
                setNotice(JSON.stringify(r))
                await load()
              } catch (err) {
                setError(String(err))
              } finally {
                setBusy(false)
              }
            }}
          />
        </Card>
      )}
      {busy && <p role="status">Loading…</p>}
      {catalog && (
        <Card
          title={`${catalog.total} ${
            kind === "templates" ? "template versions" : "documents"
          }`}
        >
          <div className="overflow-auto">
            <table className="w-full text-sm text-left">
              <thead>
                <tr>
                  {["Name", "Version", "Status", "Reviewer", "Action"].map(
                    (h) => (
                      <th className="p-2 border-b" key={h}>
                        {h}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {catalog.items.map((row: any) => (
                  <tr key={row.id ?? row.document_id}>
                    <td className="p-2 border-b">
                      {row.template_name ?? row.title}
                      <small className="block text-slate-500">
                        {row.document_id}
                      </small>
                    </td>
                    <td className="p-2 border-b">{row.version}</td>
                    <td className="p-2 border-b">{row.status}</td>
                    <td className="p-2 border-b">
                      {row.approved_by || "Not approved"}
                    </td>
                    <td className="p-2 border-b">
                      <button
                        className="text-teal-700 underline"
                        disabled={busy}
                        onClick={() => void inspect(row)}
                      >
                        View & review
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {catalog.items.length === 0 && (
            <p>No content matches these filters.</p>
          )}
          <div className="flex gap-4">
            <button
              disabled={busy || page === 0}
              onClick={() => setPage(page - 1)}
            >
              Previous
            </button>
            <span>Page {page + 1}</span>
            <button
              disabled={busy || (page + 1) * 50 >= catalog.total}
              onClick={() => setPage(page + 1)}
            >
              Next
            </button>
          </div>
        </Card>
      )}
      {selected && (
        <Card
          title={`Review ${selected.template_name ?? selected.title} · version ${selected.version}`}
        >
          <p>
            Status: {selected.status}. Approval applies to this exact stored
            content.
          </p>
          <pre className="whitespace-pre-wrap break-words bg-slate-50 p-3 text-sm max-h-96 overflow-auto">
            {selected.sql_template ??
              chunks?.chunks?.map((c: any) => c.content).join("\n\n") ??
              "Content unavailable"}
          </pre>
          <Raw value={selected} label="Version, hash and approval record" />
          {selected.status === "draft" && (
            <>
              <label className="block">
                Reviewer name
                <input
                  className={field}
                  value={form.reviewer}
                  onChange={(e) => update("reviewer", e.target.value)}
                />
              </label>
              <label className="flex gap-2">
                <input
                  type="checkbox"
                  checked={reviewed}
                  onChange={(e) => setReviewed(e.target.checked)}
                />
                I reviewed this exact version and approve its use. This is my
                approval, not an automated decision.
              </label>
              <button
                className={button}
                disabled={
                  busy ||
                  !reviewed ||
                  !form.reviewer.trim() ||
                  (kind === "knowledge" && !chunks)
                }
                onClick={() => void approve()}
              >
                Approve version {selected.version}
              </button>
            </>
          )}
          <button className="text-slate-500" onClick={() => setSelected(null)}>
            Close review
          </button>
        </Card>
      )}
    </div>
  )
}
