import { useState } from "react"
import { shotsOf, type ShotView } from "./shotViews"

// "Evidence screenshots": one thumbnail per stage; click to open full size.
export function EvidenceShots({ evidence }: { evidence: any }) {
  const shots = shotsOf(evidence)
  const [open, setOpen] = useState<ShotView | null>(null)
  if (!shots) return null
  return (
    <section className="rounded-lg border border-slate-200 p-3 space-y-2">
      <div>
        <p className="font-semibold text-sm">Evidence screenshots</p>
        <p className="text-xs text-slate-500">
          Taken on the throwaway copy before the fix, after it, and after the
          undo. The query results recorded with each picture are the source of
          truth; the picture shows them.
        </p>
      </div>
      <ul className="grid gap-3 sm:grid-cols-3">
        {shots.map((shot) => (
          <li key={shot.stage} className="space-y-1">
            <p className="text-xs font-medium">
              {shot.label}
              {shot.kind && (
                <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-normal text-slate-600">
                  {shot.kind}
                </span>
              )}
            </p>
            {shot.src ? (
              <button
                type="button"
                className="block w-full overflow-hidden rounded border border-slate-200 bg-slate-900 focus:outline-none focus:ring-2 focus:ring-teal-600"
                onClick={() => setOpen(shot)}
                aria-label={`Open the ${shot.label.toLowerCase()} screenshot full size`}
              >
                <img
                  src={shot.src}
                  alt={`${shot.label}: database query results in the sandbox`}
                  className="w-full h-28 object-cover object-top"
                />
              </button>
            ) : (
              <p className="rounded border border-amber-200 bg-amber-50 px-2 py-3 text-xs text-amber-900">
                No picture. {shot.reason}
              </p>
            )}
            {shot.src && shot.reason && (
              <p className="text-[11px] text-slate-500">{shot.reason}</p>
            )}
          </li>
        ))}
      </ul>
      {open && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label={`${open.label} screenshot`}
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/70 p-4"
          onClick={() => setOpen(null)}
          onKeyDown={(e) => e.key === "Escape" && setOpen(null)}
        >
          <div
            className="max-h-full max-w-5xl overflow-auto rounded-lg bg-white p-4 space-y-2"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-3">
              <p className="flex-1 font-semibold">
                {open.label}
                {open.kind && ` · ${open.kind}`}
              </p>
              <button
                type="button"
                autoFocus
                className="rounded border border-slate-300 px-3 py-1 text-sm"
                onClick={() => setOpen(null)}
              >
                Close
              </button>
            </div>
            {open.src && (
              <img
                src={open.src}
                alt={`${open.label}: database query results in the sandbox`}
                className="w-full rounded border"
              />
            )}
            {open.typedCommand && (
              <p className="text-xs break-all">
                <span className="font-semibold">Typed command: </span>
                <code>{open.typedCommand}</code>
              </p>
            )}
            {open.sql && (
              <details className="text-xs">
                <summary className="cursor-pointer text-teal-700">
                  The read-only checks this picture ran
                </summary>
                <pre className="mt-1 whitespace-pre-wrap bg-slate-50 p-2">
                  {open.sql}
                </pre>
              </details>
            )}
            {open.sha256 && (
              <p className="text-[11px] text-slate-500 break-all">
                Fingerprint (sha256): {open.sha256}
              </p>
            )}
          </div>
        </div>
      )}
    </section>
  )
}
