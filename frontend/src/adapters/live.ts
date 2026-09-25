export type Service = "demo" | "main"
export async function request(path: string, options: RequestInit = {}) {
  const response = await fetch(path, options)
  const text = await response.text()
  let data
  try {
    data = JSON.parse(text)
  } catch {
    data = text
  }
  if (!response.ok)
    throw new Error(
      `HTTP ${response.status}: ${
        typeof data === "object" ? JSON.stringify(data?.detail ?? data) : text
      }`,
    )
  return data
}
export const api = (service: Service, path: string, body?: unknown) =>
  request(
    `/bridge/${service}${path}`,
    body === undefined
      ? {}
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
  )
export const jsonText = (value: unknown) =>
  value == null
    ? "Not returned"
    : typeof value === "string"
      ? value
      : JSON.stringify(value)
export function findings(envelope: any): any[] {
  const assessment = envelope?.assessment ?? envelope
  const rows = assessment?.upstream_report?.results
  if (Array.isArray(rows))
    return rows.map((r: any) => ({ ...r, id: r.spec_id, status: r.result }))
  const f = assessment?.findings
  return Array.isArray(f)
    ? f.map((r: any) => ({ ...r, id: r.control_id, status: r.status }))
    : Object.entries(f ?? {}).map(([id, value]: [string, any]) => ({
        id,
        status: typeof value === "object" ? value.status : value,
      }))
}
export function sameTarget(before: any, after: any) {
  return (
    !!before?.target_id &&
    before.target_id === after?.target_id &&
    before.database === after.database &&
    before.postgresql_version === after.postgresql_version
  )
}
export function bundlePath(service: Service, result: any) {
  if (result?.review_bundle?.status !== "READY" || !result.run_id)
    return undefined
  return `/bridge/${service}/api/v1/sandbox/runs/${encodeURIComponent(result.run_id)}/bundle`
}

export function isFreshSnapshot(before: any, after: any) {
  return !!after?.snapshot_id && before?.snapshot_id !== after.snapshot_id
    && Number.isFinite(Date.parse(before?.collected_at))
    && Date.parse(after.collected_at) > Date.parse(before.collected_at);
}
