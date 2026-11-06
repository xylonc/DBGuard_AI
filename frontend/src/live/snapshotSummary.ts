// Step 3: a readable summary of the loaded snapshot (GET /api/v1/snapshots/{id}).
// Counts and identity fields only: no setting values, role names or hashes beyond
// the snapshot ID. Collection gaps are listed so "not collected" is never hidden,
// and a missing or malformed gaps field is "Not returned", never "None".
// This file must stay free of React and "@/" imports so node --test can load it.

export type SnapshotLine = {
  label: string
  value: string
}
export type SnapshotGap = {
  section: string
  reason: string
}

export type SnapshotSummary = {
  lines: SnapshotLine[]
  gaps: SnapshotGap[]
  // Sections the server lists as not collected that no gap entry names already.
  unavailable: string[]
  // Gap entries that were not well-formed objects: counted, never dropped silently.
  malformedGaps: number
}

const NOT_RETURNED = "Not returned"
const NOT_COLLECTED = "Not collected"
const MAX_TEXT = 160

function clip(value: string): string {
  return value.length > MAX_TEXT ? value.slice(0, MAX_TEXT - 1) + "…" : value
}

function text(value: unknown): string {
  return typeof value === "string" && value ? clip(value) : NOT_RETURNED
}

function collectedAt(value: unknown): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)))
    return NOT_RETURNED
  return new Date(value).toISOString().replace("T", " ").slice(0, 16) + " UTC"
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? `1 ${one}` : `${n} ${many}`
}

export function snapshotSummary(snapshot: any): SnapshotSummary | null {
  if (!snapshot || typeof snapshot !== "object") return null
  const gapsReturned = Array.isArray(snapshot.gaps)
  const rawGaps: unknown[] = gapsReturned ? snapshot.gaps : []
  const gaps: SnapshotGap[] = rawGaps
    .filter((g: any) => g && typeof g === "object")
    .map((g: any) => ({ section: text(g.section), reason: text(g.reason) }))
  const malformedGaps = rawGaps.length - gaps.length
  const allUnavailable: string[] = Array.isArray(snapshot.unavailable_sections)
    ? snapshot.unavailable_sections
        .filter((s: unknown): s is string => typeof s === "string" && !!s)
        .map(clip)
    : []
  const unavailable = allUnavailable.filter(
    (s) => !gaps.some((g) => g.section === s),
  )
  const sectionMissing = (section: string) =>
    allUnavailable.includes(section) || gaps.some((g) => g.section === section)
  const settings =
    snapshot.settings &&
    typeof snapshot.settings === "object" &&
    !sectionMissing("settings")
      ? Object.keys(snapshot.settings).length
      : null
  const roles =
    Array.isArray(snapshot.roles) && !sectionMissing("roles")
      ? snapshot.roles.length
      : null
  const sections = Array.isArray(snapshot.available_sections)
    ? snapshot.available_sections.length
    : null
  const version = text(snapshot.postgresql_version)
  const gapCount = gaps.length + malformedGaps
  return {
    lines: [
      { label: "Target", value: text(snapshot.target_id) },
      { label: "Database", value: text(snapshot.database) },
      {
        label: "PostgreSQL",
        value: version === NOT_RETURNED ? version : `version ${version}`,
      },
      { label: "Collected", value: collectedAt(snapshot.collected_at) },
      {
        label: "Server settings read",
        value: settings === null ? NOT_COLLECTED : String(settings),
      },
      {
        label: "Accounts (roles) read",
        value: roles === null ? NOT_COLLECTED : String(roles),
      },
      {
        label: "Evidence sections",
        value:
          sections === null
            ? NOT_RETURNED
            : `${sections} collected, ${allUnavailable.length} not collected`,
      },
      {
        label: "Collection gaps",
        value: !gapsReturned
          ? NOT_RETURNED
          : gapCount
            ? plural(gapCount, "gap", "gaps") +
              (malformedGaps ? ` (${malformedGaps} unreadable)` : "")
            : "None",
      },
    ],
    gaps,
    unavailable,
    malformedGaps,
  }
}
