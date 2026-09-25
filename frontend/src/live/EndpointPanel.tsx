import { useState } from "react"
import contract from "@/imports/dbguard-openapi.json"
import { request } from "@/adapters/live"
import { Card, Raw } from "./LiveUI"
const spec = contract as any
const operations = Object.entries(spec.paths).flatMap(
  ([path, methods]: [string, any]) =>
    Object.entries(methods)
      .filter(([m]) => ["get", "post", "put", "delete", "patch"].includes(m))
      .map(([method, operation]) => ({
        path,
        method,
        operation: operation as any,
      })),
)
function resolve(schema: any): any {
  return schema?.$ref
    ? spec.components.schemas[schema.$ref.split("/").pop()]
    : schema
}
function example(schema: any, depth = 0): any {
  schema = resolve(schema)
  if (!schema || depth > 5) return null
  if (schema.default !== undefined) return schema.default
  if (schema.example !== undefined) return schema.example
  if (schema.enum) return schema.enum[0]
  if (schema.anyOf)
    return example(
      schema.anyOf.find((s: any) => s.type !== "null"),
      depth + 1,
    )
  if (schema.type === "object" || schema.properties)
    return Object.fromEntries(
      Object.entries(schema.properties ?? {})
        .filter(([k]) => schema.required?.includes(k))
        .map(([k, v]) => [k, example(v, depth + 1)]),
    )
  if (schema.type === "array") return []
  if (schema.type === "integer" || schema.type === "number")
    return schema.minimum ?? 1
  if (schema.type === "boolean") return false
  if (schema.format === "date-time") return new Date().toISOString()
  return ""
}
export function EndpointPanel() {
  const [index, setIndex] = useState(
    operations.findIndex((o) => o.path === "/api/v1/knowledge/search"),
  )
  const selected = operations[index]
  const [params, setParams] = useState<Record<string, string>>({})
  const [body, setBody] = useState("{}")
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const [confirmed, setConfirmed] = useState(false)
  const content = selected.operation.requestBody?.content ?? {}
  const schema = resolve(
    content["application/json"]?.schema ??
      content["multipart/form-data"]?.schema,
  )
  const mutation = selected.method !== "get"
  function choose(i: number) {
    setIndex(i)
    setParams({})
    setResult(null)
    setError("")
    setConfirmed(false)
    setFile(null)
    const c = operations[i].operation.requestBody?.content ?? {}
    setBody(
      JSON.stringify(example(c["application/json"]?.schema) || {}, null, 2),
    )
  }
  async function execute() {
    setBusy(true)
    setError("")
    setResult(null)
    try {
      let path = selected.path
      const query = new URLSearchParams()
      for (const p of selected.operation.parameters ?? []) {
        const value = params[p.name] ?? ""
        if (p.required && !value) throw new Error(`${p.name} is required`)
        if (p.in === "path")
          path = path.replace(`{${p.name}}`, encodeURIComponent(value))
        if (p.in === "query" && value) query.set(p.name, value)
      }
      if (path.includes("{")) throw new Error("Fill in path parameters")
      if (path.startsWith("/api/v1/templates/") && path.endsWith("/approve") && !params.version) throw new Error("Enter the exact template version to approve")
      const url = "/bridge/main" + path + (query.size ? "?" + query : "")
      let options: RequestInit = { method: selected.method.toUpperCase() }
      if (content["multipart/form-data"]) {
        if (!file) throw new Error("Choose a file")
        const data = new FormData()
        data.append("file", file)
        options.body = data
      } else if (content["application/json"]) {
        options.headers = { "Content-Type": "application/json" }
        options.body = JSON.stringify(JSON.parse(body))
      }
      if (path.endsWith("/bundle")) {
        const response = await fetch(url)
        if (!response.ok) throw new Error(await response.text())
        const blob = await response.blob()
        const href = URL.createObjectURL(blob)
        const a = document.createElement("a")
        a.href = href
        a.download = "dbguard-review-bundle.zip"
        a.click()
        setTimeout(() => URL.revokeObjectURL(href), 1000)
        setResult({ downloaded: true, bytes: blob.size })
      } else setResult(await request(url, options))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="p-6 max-w-4xl mx-auto space-y-5">
      <h1 className="text-xl font-semibold">Library & API tools</h1>
      <p className="text-sm text-slate-500">
        Every endpoint in the supplied OpenAPI contract is connected through the
        local Main API gateway. Use the workflow for the guided path; use these
        advanced controls for ingestion, search, approval, proposal validation
        and legacy operations.
      </p>
      <Card title="Choose an operation">
        <div className="flex gap-2 flex-wrap">{[
          ["Search evidence", "/api/v1/knowledge/search"],
          ["Search templates", "/api/v1/templates/search"],
          ["Upload knowledge", "/api/v1/knowledge/upload"],
          ["Look up document", "/api/v1/knowledge/documents/{document_id}"],
        ].map(([label,path]) => <button key={path} className="rounded border px-3 py-2 text-sm text-teal-700" disabled={busy} onClick={() => choose(operations.findIndex(o=>o.path===path))}>{label}</button>)}</div>
        <label className="block text-sm">
          API operation
          <select
            className="w-full border rounded p-2 mt-1"
            value={index}
            disabled={busy}
            onChange={(e) => choose(Number(e.target.value))}
          >
            {operations.map((o, i) => (
              <option key={i} value={i}>
                {o.method.toUpperCase()} {o.path}
              </option>
            ))}
          </select>
        </label>
        <p className="text-sm">{selected.operation.summary}</p>
        {(selected.operation.parameters ?? []).map((p: any) => (
          <label key={p.name} className="block text-sm">
            {p.name}
            {p.required ? " *" : ""}
            <input
              className="w-full border rounded p-2 mt-1"
              value={params[p.name] ?? ""}
              onChange={(e) =>
                setParams({ ...params, [p.name]: e.target.value })
              }
            />
          </label>
        ))}
        {content["multipart/form-data"] && (
          <input
            type="file"
            aria-label="Knowledge upload file"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
        )}{" "}
        {content["application/json"] && (
          <label className="block text-sm">
            Request JSON
            <textarea
              aria-label="API request JSON"
              className="w-full border rounded p-3 font-mono text-xs mt-1"
              rows={12}
              value={body}
              onChange={(e) => setBody(e.target.value)}
            />
          </label>
        )}
        {schema && <Raw value={schema} label="Required request schema" />}
        {mutation && (
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            I reviewed this request and intend to perform this operation on the
            Main API. Approval actions must name the actual reviewer.
          </label>
        )}
        <button
          className="rounded bg-teal-700 text-white px-4 py-2 disabled:opacity-40"
          disabled={busy || (mutation && !confirmed)}
          onClick={execute}
        >
          {busy ? "Request running…" : "Send request"}
        </button>
        {error && (
          <p
            role="alert"
            className="text-red-700 whitespace-pre-wrap break-words"
          >
            {error}
          </p>
        )}
        {result !== null && (
          <div>
            <p className="text-teal-700">API response received</p>
            <pre className="overflow-auto max-h-96 text-xs bg-slate-50 p-3 whitespace-pre-wrap break-all">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        )}
      </Card>
      <p className="text-xs text-slate-500">
        Endpoint availability does not guarantee configured dependencies.
        Search/ingestion require embeddings and a registry; unsupported legacy
        endpoints may return errors. No approvals or bulk writes run
        automatically.
      </p>
    </div>
  )
}
