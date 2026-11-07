// Before / after fix / after undo pictures recorded during a sandbox test
// (Task 2). Reads only the server's `terminal_evidence` shape; a picture is
// shown only when its PNG data is well-formed base64. Missing or unavailable
// stages stay visible with their reason, never silently dropped.
// This file must stay free of React and "@/" imports so node --test can load it.

export type Stage = "before" | "after" | "rollback"

export const STAGES: [Stage, string][] = [
  ["before", "Before the fix"],
  ["after", "After the fix"],
  ["rollback", "After the undo"],
]

export type ShotView = {
  stage: Stage
  label: string
  captured: boolean
  // "Terminal" (VHS) or "Rendered" (browser page of the query results).
  kind: string | null
  src: string | null
  sha256: string | null
  typedCommand: string | null
  sql: string | null
  reason: string | null
}

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/
const SHA256 = /^[0-9a-f]{64}$/
const MAX_TEXT = 4000

function text(value: unknown, max = MAX_TEXT): string | null {
  if (typeof value !== "string" || !value) return null
  return value.length > max ? value.slice(0, max - 1) + "…" : value
}

export function shotsOf(evidence: any): ShotView[] | null {
  const stages = evidence?.stages
  if (!stages || typeof stages !== "object") return null
  return STAGES.map(([stage, label]) => {
    const shot = stages[stage]
    const b64 = typeof shot?.png_base64 === "string" ? shot.png_base64 : ""
    const captured =
      shot?.status === "CAPTURED" &&
      shot?.format === "png" &&
      b64.length > 0 &&
      b64.length % 4 === 0 &&
      BASE64.test(b64)
    const mode = shot?.mode
    return {
      stage,
      label,
      captured,
      kind:
        mode === "terminal"
          ? "Terminal"
          : mode === "rendered"
            ? "Rendered"
            : null,
      src: captured ? `data:image/png;base64,${b64}` : null,
      sha256:
        typeof shot?.sha256 === "string" && SHA256.test(shot.sha256)
          ? shot.sha256
          : null,
      typedCommand: text(shot?.typed_command, 600),
      sql: text(shot?.sql),
      reason: captured
        ? text(shot?.reason, 300)
        : (text(shot?.reason, 300) ??
          (shot ? "No picture was returned." : "This stage was not recorded.")),
    }
  })
}
