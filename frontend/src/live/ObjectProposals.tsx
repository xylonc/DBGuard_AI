import { activeObjectFix, useLive } from "@/store/liveStore"
import {
  POLICY_MISSING_CODE,
  approvedTemplateVersion,
  changeKey,
  changeSummary,
  limitSourceLabel,
  noteDetail,
  noteSentence,
  riskLabel,
  riskLevel,
  targetLabel,
} from "./objectFixes"

// Step 5: per-object fixes for the account and permission checks (Gate 1 E).
// Everything shown is text from the server-derived proposal or a fixed sentence;
// choosing a fix records only its fix_id.

type ObjectProposalsProps = {
  groups: any[]
  templateVersions?: any
  selected: string[]
  onToggle: (fixId: string, on: boolean) => void
  onOpenPolicy?: () => void
}

const RISK_STYLE: Record<string, string> = {
  high: "bg-red-50 text-red-800 border-red-200",
  medium: "bg-amber-50 text-amber-800 border-amber-200",
  low: "bg-slate-50 text-slate-700 border-slate-200",
  not_assessed: "bg-slate-50 text-slate-700 border-slate-200",
}

export function ObjectProposals({
  groups,
  templateVersions,
  selected,
  onToggle,
  onOpenPolicy,
}: ObjectProposalsProps) {
  const all: any[] = groups.flatMap((g) => g.proposals ?? [])
  // Changes already ticked, so the same change under another CIS rule is blocked.
  const tickedChanges = new Map<string, any>(
    all
      .filter((p) => selected.includes(p.fix_id))
      .map((p) => [changeKey(p), p] as [string, any]),
  )
  return (
    <section
      className="border border-teal-200 rounded p-4 space-y-4"
      aria-label="Proposed fixes for accounts and permissions"
    >
      <div className="space-y-1">
        <h3 className="font-semibold">
          Proposed fixes for accounts and permissions
        </h3>
        <p className="text-sm">
          Each fix changes one account, function or table, and only what the
          collected evidence shows. DBGuard rehearses it on a throwaway stand-in
          copy, proves it worked and that the undo restores the object, then
          adds it to the DBA bundle. Nothing is applied to your database.
        </p>
      </div>
      {groups.map((g) => (
        <ProposalGroup
          key={g.spec_id}
          group={g}
          selected={selected}
          tickedChanges={tickedChanges}
          templateVersions={templateVersions}
          onToggle={onToggle}
          onOpenPolicy={onOpenPolicy}
        />
      ))}
    </section>
  )
}

type ProposalGroupProps = {
  group: any
  selected: string[]
  tickedChanges: Map<string, any>
  templateVersions?: any
  onToggle: (fixId: string, on: boolean) => void
  onOpenPolicy?: () => void
}

function ProposalGroup({
  group,
  selected,
  tickedChanges,
  templateVersions,
  onToggle,
  onOpenPolicy,
}: ProposalGroupProps) {
  const proposals: any[] = Array.isArray(group.proposals) ? group.proposals : []
  const notes: any[] = Array.isArray(group.notes) ? group.notes : []
  return (
    <div className="space-y-2">
      <h4 className="font-medium">
        CIS {group.recommendation}
        {group.title ? `: ${group.title}` : ""}
      </h4>
      {proposals.length === 0 && (
        <p className="text-sm text-slate-600">
          No fix is offered for this rule. See the notes below.
        </p>
      )}
      {proposals.map((p) => (
        <ProposalCard
          key={p.fix_id}
          proposal={p}
          templateVersion={approvedTemplateVersion(
            templateVersions,
            p.fix_type,
          )}
          checked={selected.includes(p.fix_id)}
          blockedBy={
            selected.includes(p.fix_id)
              ? null
              : (tickedChanges.get(changeKey(p)) ?? null)
          }
          onToggle={onToggle}
        />
      ))}
      {notes.length > 0 && (
        <div className="rounded border border-slate-200 bg-slate-50 p-3 space-y-2">
          <p className="text-sm font-medium">Notes</p>
          <ul className="list-disc pl-5 space-y-2 text-sm">
            {notes.map((n, i) => (
              <NoteItem
                key={`${n.code}-${i}`}
                note={n}
                onOpenPolicy={onOpenPolicy}
              />
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

type NoteItemProps = {
  note: any
  onOpenPolicy?: () => void
}

function NoteItem({ note, onOpenPolicy }: NoteItemProps) {
  const where = targetLabel(note?.target)
  const detail = noteDetail(note)
  const policy = note?.code === POLICY_MISSING_CODE
  return (
    <li className={policy ? "text-amber-900" : undefined}>
      {where && <strong>{where}: </strong>}
      {noteSentence(note?.code)}
      {detail && <span className="block text-xs">{detail}</span>}
      {policy && onOpenPolicy && (
        <button
          className="mt-1 block rounded border border-amber-700 text-amber-800 px-3 py-1 text-xs"
          onClick={onOpenPolicy}
        >
          Open the Policy Profile screen
        </button>
      )}
    </li>
  )
}

type ProposalCardProps = {
  proposal: any
  checked: boolean
  blockedBy: any
  templateVersion: number | null
  onToggle: (fixId: string, on: boolean) => void
}

function ProposalCard({
  proposal: p,
  templateVersion,
  checked,
  blockedBy,
  onToggle,
}: ProposalCardProps) {
  const live = useLive(),
    s = live.state
  const chosen = activeObjectFix(s)
  const rehearsable = p.rehearsable === true
  const level = riskLevel(p.risk)
  const source = p.limit_source ? limitSourceLabel(p.limit_source) : null
  return (
    <article
      className={`border rounded p-3 space-y-2 ${
        rehearsable ? "" : "opacity-60 bg-slate-50"
      }`}
      aria-disabled={!rehearsable}
    >
      <div className="flex flex-wrap gap-2 items-center">
        <h5 className="font-semibold">{p.title}</h5>
        <span className={`rounded border px-2 text-xs ${RISK_STYLE[level]}`}>
          {riskLabel(p.risk)}
        </span>
      </div>
      <p className="text-sm">
        <span className="font-medium">What it changes: </span>
        {changeSummary(p)}
      </p>
      {source && (
        <p className="text-sm">
          <span className="font-medium">Where the limit comes from: </span>
          {source}
        </p>
      )}
      <p className="text-sm">{p.explanation}</p>
      {typeof p.note === "string" && p.note && (
        <p className="text-sm text-amber-800">{p.note}</p>
      )}
      {!rehearsable ? (
        <p className="text-sm">
          <span className="font-medium">Can't rehearse: </span>
          {p.not_rehearsable_reason ||
            "Unknown: needs human review. This fix cannot be rehearsed."}{" "}
          It stays in the report for a person to handle.
        </p>
      ) : (
        <div className="flex flex-wrap gap-4 items-center border-t pt-3">
          {chosen?.fix_id === p.fix_id ? (
            <span className="rounded bg-teal-700 text-white px-4 py-2">
              ✓ This fix runs in the single-fix test below
            </span>
          ) : (
            <button
              className="rounded border border-teal-700 text-teal-700 px-4 py-2 disabled:opacity-40"
              disabled={!!s.busy || !!s.handoffId || !s.snapshot}
              onClick={() =>
                live.configure({
                  objectFix: {
                    fix_id: p.fix_id,
                    spec_id: p.spec_id,
                    title: p.title,
                    template_version: templateVersion,
                    snapshot_id: s.snapshot.snapshot_id,
                    profile_ref: s.policyProfile?.profile_ref ?? null,
                  },
                })
              }
            >
              Test this fix on its own
            </button>
          )}
          <label className="flex gap-2 items-center">
            <input
              aria-label={"Include " + p.title + " in combined test"}
              type="checkbox"
              checked={checked}
              disabled={!!blockedBy}
              onChange={(e) => onToggle(p.fix_id, e.target.checked)}
            />
            Add to combined test
          </label>
          {blockedBy && (
            <span className="text-xs text-slate-600">
              Same change as "{blockedBy.title}" already ticked; it runs once.
            </span>
          )}
        </div>
      )}
    </article>
  )
}
