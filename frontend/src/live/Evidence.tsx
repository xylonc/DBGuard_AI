const SHOWN = 50

function value(v: unknown) {
  if (v == null) return "—"
  if (typeof v === "boolean") return v ? "yes" : "no"
  return typeof v === "string" ? v : JSON.stringify(v)
}

// The notices and the evidence list (names and attributes only) that catalog
// checks attach to an assessment row. The reason sentence comes from
// explanations.ts (explainRow), like every other row.
export function CatalogEvidence({ row }: { row: any }) {
  const evidence: any[] = Array.isArray(row?.evidence) ? row.evidence : []
  // Fixed, reviewed notices from the assessor (e.g. 7.4's restore-test
  // reminder), shown whatever the status.
  const notices: string[] = Array.isArray(row?.notices)
    ? row.notices
        .map((n: any) => n?.text)
        .filter((t: unknown): t is string => typeof t === "string" && !!t)
    : []
  if (!evidence.length && !notices.length) return null
  return (
    <div className="mt-1 space-y-1 text-xs text-slate-600">
      {notices.map((text, i) => (
        <p key={i} className="rounded bg-amber-50 px-2 py-1 text-amber-900">
          {text}
        </p>
      ))}
      {evidence.length > 0 && (
        <details>
          <summary className="cursor-pointer text-teal-700">
            Evidence ({evidence.length})
          </summary>
          <ul className="mt-1 space-y-1">
            {evidence.slice(0, SHOWN).map((item, i) => (
              <li key={i} className="bg-slate-50 rounded px-2 py-1 break-words">
                {typeof item === "object" && item !== null
                  ? Object.entries(item)
                      .map(([k, v]) => `${k}: ${value(v)}`)
                      .join(" · ")
                  : value(item)}
              </li>
            ))}
          </ul>
          {evidence.length > SHOWN && (
            <p className="mt-1">
              …and {evidence.length - SHOWN} more in the API evidence.
            </p>
          )}
        </details>
      )}
    </div>
  )
}
