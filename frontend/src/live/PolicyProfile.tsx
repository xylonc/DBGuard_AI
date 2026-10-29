import { useEffect, useState } from "react"
import { api, ApiError } from "@/adapters/live"
import { useLive, type ChosenProfile } from "@/store/liveStore"
import { Card } from "./LiveUI"
import { cisRule, conditionPhrase, POLICY_MISSING_LABEL } from "./explanations"
import {
  DEMO_APPROVAL_LABEL,
  assessmentProfilePin,
  draftBody,
  errorsFromDetail,
  expectedToText,
  formFromProfile,
  groupErrors,
  isApproved,
  settingHelp,
  shapeHint,
  shortSha,
  type ProfileForm,
} from "./profileForm"

const button =
  "rounded-lg bg-teal-700 text-white px-4 py-2 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
const outline =
  "rounded-lg border border-teal-700 text-teal-700 px-3 py-1.5 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
const input =
  "border border-slate-300 rounded-lg px-3 py-2 w-full text-sm bg-white"

const profilesPath = (benchmark: string) =>
  `/api/v1/benchmarks/${encodeURIComponent(benchmark)}/policy-profiles`

function messageOf(e: unknown): string[] {
  if (e instanceof ApiError) {
    const list = errorsFromDetail(e.detail)
    return list.length ? list : [e.message]
  }
  return [e instanceof Error ? e.message : String(e)]
}

function toChosen(summary: any): ChosenProfile {
  return {
    profile_ref: summary.profile_ref,
    profile_id: summary.profile_id,
    approved_by: summary.approved_by ?? null,
    approved_at: summary.approved_at ?? null,
  }
}

// Shown next to every approval: approvals here are a typed name, not a sign-in.
export function DemoApprovalTag() {
  return (
    <span className="inline-block rounded border border-amber-400 bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-900">
      {DEMO_APPROVAL_LABEL}
    </span>
  )
}

function ErrorList({ errors }: { errors: string[] }) {
  if (!errors.length) return null
  return (
    <ul role="alert" className="list-disc pl-5 text-sm text-red-700 space-y-1">
      {errors.map((e, i) => (
        <li key={i} className="break-words">
          {e}
        </li>
      ))}
    </ul>
  )
}

// Which profile the current assessment actually used, from the backend's pin.
export function PolicyProfileInUse() {
  const s = useLive().state
  const pin = assessmentProfilePin(s.assessment)
  if (pin === undefined) {
    return (
      <p className="text-sm">
        Policy profile for the next assessment:{" "}
        <strong>
          {s.policyProfile
            ? `${s.policyProfile.profile_id} · sha ${shortSha(s.policyProfile.profile_ref)}`
            : "none"}
        </strong>
      </p>
    )
  }
  if (pin === null)
    return (
      <p className="text-sm">
        Policy profile in use: <strong>none</strong>. Every control that needs a
        company-chosen value shows {POLICY_MISSING_LABEL}.
      </p>
    )
  return (
    <p className="text-sm flex flex-wrap gap-x-2 gap-y-1 items-center">
      <span>
        Policy profile in use: <strong>{pin.profile_id}</strong>
      </span>
      <span>·</span>
      {pin.approved_by ? (
        <>
          <span>
            approved by <strong>{pin.approved_by}</strong> at{" "}
            {pin.approved_at ?? "unknown time"}
          </span>
          <DemoApprovalTag />
        </>
      ) : (
        <span className="text-red-700">
          not approved, so its values are not used
        </span>
      )}
      <span>·</span>
      <span className="font-mono text-xs">sha {shortSha(pin.sha256)}</span>
    </p>
  )
}

// Step 4 card: choose the approved profile the assessment uses (default none).
export function PolicyProfileSelector({ onOpen }: { onOpen: () => void }) {
  const live = useLive()
  const s = live.state
  const [profiles, setProfiles] = useState<any[]>([])
  const [error, setError] = useState("")
  useEffect(() => {
    let cancelled = false
    setError("")
    api(s.service, profilesPath(s.benchmark))
      .then((d) => {
        if (!cancelled) setProfiles(d.profiles ?? [])
      })
      .catch((e) => {
        if (!cancelled) setError(messageOf(e).join("; "))
      })
    return () => {
      cancelled = true
    }
  }, [s.service, s.benchmark])
  const approved = profiles.filter(isApproved)
  const busy = !!s.busy || !!s.chatJob
  return (
    <Card title="Policy profile for this assessment">
      <PolicyProfileInUse />
      <label className="block text-sm">
        Use approved profile
        <select
          aria-label="Policy profile for this assessment"
          className={input}
          disabled={busy}
          value={s.policyProfile?.profile_ref ?? ""}
          onChange={(e) => {
            const chosen = approved.find(
              (p) => p.profile_ref === e.target.value,
            )
            void live.choosePolicyProfile(chosen ? toChosen(chosen) : null)
          }}
        >
          <option value="">
            None (company-policy controls stay unchecked)
          </option>
          {approved.map((p) => (
            <option key={p.profile_ref} value={p.profile_ref}>
              {p.profile_id} · approved by {p.approved_by} (
              {DEMO_APPROVAL_LABEL}) · sha {shortSha(p.profile_ref)}
            </option>
          ))}
          {s.policyProfile &&
            !approved.some(
              (p) => p.profile_ref === s.policyProfile?.profile_ref,
            ) && (
              <option value={s.policyProfile.profile_ref}>
                {s.policyProfile.profile_id} · sha{" "}
                {shortSha(s.policyProfile.profile_ref)}
              </option>
            )}
        </select>
      </label>
      {error && (
        <p className="text-sm text-red-700 break-words">
          Could not list policy profiles: {error}
        </p>
      )}
      <p className="text-xs text-slate-500">
        Only profiles approved by a named person are listed. Changing the
        profile reassesses the snapshot. DBGuard and HERMES never approve a
        profile.
      </p>
      <button className={outline} onClick={onOpen}>
        Open Policy Profile screen
      </button>
    </Card>
  )
}

export function PolicyMissingBanner({
  rows,
  onOpen,
}: {
  rows: any[]
  onOpen: () => void
}) {
  if (!rows.length) return null
  return (
    <div
      role="alert"
      className="rounded-xl border-2 border-red-300 bg-red-50 p-4 space-y-2"
    >
      <p className="font-bold text-red-800 tracking-wide">
        {POLICY_MISSING_LABEL}: {rows.length} control
        {rows.length === 1 ? "" : "s"}
      </p>
      <ul className="list-disc pl-5 text-sm text-red-900">
        {rows.map((r) => (
          <li key={r.id ?? r.spec_id}>{cisRule(r)}</li>
        ))}
      </ul>
      <p className="text-sm text-red-900">
        These controls check values your company must choose, so they can't pass
        yet. Approving a profile on the Policy Profile screen and selecting it
        for this assessment clears this.
      </p>
      <button className={button} onClick={onOpen}>
        Open Policy Profile screen
      </button>
    </div>
  )
}

function ApproveForm({
  profile,
  onApproved,
}: {
  profile: any
  onApproved: (summary: any) => void
}) {
  const s = useLive().state
  const [name, setName] = useState("")
  const [errors, setErrors] = useState<string[]>([])
  const [pending, setPending] = useState(false)
  return (
    <div className="rounded-lg border border-amber-300 bg-amber-50 p-3 space-y-2">
      <p className="text-sm">
        Approve <strong>{profile.profile_id}</strong> (sha{" "}
        {shortSha(profile.profile_ref)}). Approval is recorded under the name
        you type, as a new hash-pinned profile; the draft is kept unchanged.
      </p>
      <p className="text-sm flex flex-wrap gap-2 items-center">
        <DemoApprovalTag />
        <span>
          DBGuard does not check who you are. Only a person may approve; AI
          agents never approve profiles.
        </span>
      </p>
      <label className="block text-sm">
        Approver's name
        <input
          className={input}
          aria-label="Approver's name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Your full name"
        />
      </label>
      <ErrorList errors={errors} />
      <button
        className={button}
        disabled={pending || !name.trim()}
        onClick={async () => {
          setPending(true)
          setErrors([])
          try {
            const r = await api(
              s.service,
              `${profilesPath(s.benchmark)}/${profile.profile_ref}/approve`,
              { approver_name: name },
            )
            onApproved(r)
          } catch (e) {
            setErrors(messageOf(e))
          } finally {
            setPending(false)
          }
        }}
      >
        Record approval
      </button>
    </div>
  )
}

type Check = {
  status: "idle" | "checking" | "valid" | "invalid" | "unavailable"
  errors: string[]
}

export function PolicyProfileScreen({ onBack }: { onBack: () => void }) {
  const live = useLive()
  const s = live.state
  const base = profilesPath(s.benchmark)
  const [profiles, setProfiles] = useState<any[]>([])
  const [controls, setControls] = useState<any[]>([])
  const [seedDoc, setSeedDoc] = useState<any>(null)
  const [form, setForm] = useState<ProfileForm | null>(null)
  const [loadError, setLoadError] = useState<string[]>([])
  const [check, setCheck] = useState<Check>({ status: "idle", errors: [] })
  const [saveErrors, setSaveErrors] = useState<string[]>([])
  const [pending, setPending] = useState("")
  const [saved, setSaved] = useState<any>(null)
  const [approving, setApproving] = useState<any>(null)

  async function refresh() {
    const d = await api(s.service, base)
    setProfiles(d.profiles ?? [])
    setControls(d.controls ?? [])
    return d
  }
  async function startFrom(ref: string, ctrls: any[]) {
    const d = await api(s.service, `${base}/${ref}`)
    setForm(formFromProfile(ctrls, d.profile, ref, s.snapshot))
    setSaved(null)
    setSaveErrors([])
    return d
  }

  useEffect(() => {
    let cancelled = false
    setLoadError([])
    setForm(null)
    ;(async () => {
      try {
        const d = await refresh()
        const seed =
          (d.profiles ?? []).find((p: any) => p.source === "seed") ??
          (d.profiles ?? [])[0]
        if (cancelled) return
        if (seed) {
          const doc = await startFrom(seed.profile_ref, d.controls ?? [])
          if (!cancelled && seed.source === "seed") setSeedDoc(doc.profile)
        } else {
          setForm(formFromProfile(d.controls ?? [], null, null, s.snapshot))
        }
      } catch (e) {
        if (!cancelled) setLoadError(messageOf(e))
      }
    })()
    return () => {
      cancelled = true
    }
  }, [s.service, s.benchmark])

  // Live validation: the backend checks the draft exactly as Save would, without
  // storing it. Nothing is re-implemented here.
  useEffect(() => {
    if (!form) return
    let cancelled = false
    setCheck((c) => ({ ...c, status: "checking" }))
    const timer = setTimeout(async () => {
      try {
        const r = await api(
          s.service,
          `${base}/validate`,
          draftBody(form, controls),
        )
        if (!cancelled)
          setCheck({
            status: r.valid ? "valid" : "invalid",
            errors: r.errors ?? [],
          })
      } catch (e) {
        if (cancelled) return
        if (e instanceof ApiError && e.status === 422)
          setCheck({ status: "invalid", errors: messageOf(e) })
        else setCheck({ status: "unavailable", errors: messageOf(e) })
      }
    }, 500)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [form, controls, s.service, base])

  const policyControls = controls.filter((c) => c.kind === "policy_value")
  const siteControls = controls.filter((c) => c.kind === "site_fix")
  const shownErrors =
    check.status === "invalid" ? [...check.errors, ...saveErrors] : saveErrors
  const grouped = groupErrors(
    shownErrors,
    controls.map((c) => c.spec_id),
  )

  function update(next: (f: ProfileForm) => ProfileForm) {
    setForm((f) => (f ? next(f) : f))
    setSaveErrors([])
  }
  function setValue(
    specId: string,
    key: "expected" | "fix" | "brk",
    v: string,
  ) {
    update((f) => ({
      ...f,
      values: { ...f.values, [specId]: { ...f.values[specId], [key]: v } },
    }))
  }

  function afterApproval(r: any) {
    setApproving(null)
    setSaved(r)
    void refresh().catch(() => {})
  }

  return (
    <>
      <Card title="Policy Profile">
        <div className="flex justify-between gap-3 flex-wrap">
          <p className="text-sm max-w-2xl">
            Some CIS controls say a setting must match "your organization's
            policy". A policy profile records the values your company chose. A
            profile is only used after a named person approves it, and you
            choose which approved profile an assessment uses. AI never approves
            a profile.
          </p>
          <button className={outline} onClick={onBack}>
            ← Back to assessment
          </button>
        </div>
        <ErrorList errors={loadError} />
        {!form && !loadError.length ? (
          <p className="text-sm text-slate-500">Loading policy profiles…</p>
        ) : (
          <ProfilesTable
            profiles={profiles}
            activeRef={s.policyProfile?.profile_ref}
            disabled={!!pending || !!s.busy || !!s.chatJob}
            onEdit={(p) =>
              void startFrom(p.profile_ref, controls).catch((e) =>
                setLoadError(messageOf(e)),
              )
            }
            onApprove={(p) => setApproving(p)}
            onUse={(p) => {
              void live.choosePolicyProfile(toChosen(p))
              onBack()
            }}
          />
        )}
        {approving && (
          <ApproveForm profile={approving} onApproved={afterApproval} />
        )}
      </Card>
      {form && (
        <>
          <Card title="Profile details">
            <label className="block text-sm">
              Profile name (letters, digits, . _ -)
              <input
                className={input}
                aria-label="Profile name"
                value={form.profileId}
                onChange={(e) =>
                  update((f) => ({ ...f, profileId: e.target.value }))
                }
              />
            </label>
            <ErrorList errors={grouped.profileId} />
            <p className="text-xs text-slate-500">
              Starting from:{" "}
              {form.basedOn
                ? `sha ${shortSha(form.basedOn)}`
                : "an empty profile"}
              . Saving creates a new draft; existing profiles are never changed.
            </p>
            <ValidationStatus check={check} />
          </Card>
          <Card title="Company policy values">
            <p className="text-sm text-slate-600">
              Each value is pre-filled from DBGuard's reference profile
              (catalog/policies/{s.benchmark}/reference.yaml). Leave all three
              fields of a control empty to leave it without a value; it then
              shows {POLICY_MISSING_LABEL}.
            </p>
            {policyControls.map((c) => (
              <PolicyValueControl
                key={c.spec_id}
                control={c}
                value={
                  form.values[c.spec_id] ?? { expected: "", fix: "", brk: "" }
                }
                seed={seedDoc?.values?.[c.spec_id]}
                errors={grouped.bySpec[c.spec_id] ?? []}
                onChange={(key, v) => setValue(c.spec_id, key, v)}
              />
            ))}
            {!policyControls.length && (
              <p className="text-sm">
                This benchmark has no controls that take a company-chosen value.
              </p>
            )}
          </Card>
          <Card title="Site-specific fixes">
            {siteControls.map((c) => (
              <section key={c.spec_id} className="space-y-2">
                <h3 className="font-semibold">{cisRule(c)}</h3>
                <p className="text-sm">{settingHelp(c)}</p>
                <blockquote className="border-l-4 border-slate-300 pl-3 text-sm italic text-slate-700">
                  CIS: “{c.pass_condition_quote}”
                </blockquote>
                {c.setting_name === "listen_addresses" ? (
                  <p className="text-sm">
                    To get an automatic fix for {c.recommendation}, enter the
                    addresses this server should listen on. The value must
                    include <code>localhost</code> plus the server's real IP
                    address, for example <code>localhost, 10.0.0.5</code>, so
                    the sandbox can start PostgreSQL and test the change.
                    Without a value here, no {c.recommendation} fix is offered
                    and the DBA changes <code>listen_addresses</code> by hand.
                  </p>
                ) : (
                  <p className="text-sm">
                    This fix needs a value specific to your server. Without it,
                    no automatic fix is offered for {c.recommendation}.
                  </p>
                )}
                <label className="block text-sm">
                  Fix value for <code>{c.setting_name}</code>
                  <input
                    className={input}
                    aria-label={`Site-specific fix for ${c.recommendation}`}
                    placeholder="localhost, 10.0.0.5"
                    value={form.fixes[c.spec_id] ?? ""}
                    onChange={(e) =>
                      update((f) => ({
                        ...f,
                        fixes: { ...f.fixes, [c.spec_id]: e.target.value },
                      }))
                    }
                  />
                </label>
                <p className="text-xs text-slate-500">{shapeHint(c)}</p>
                <ErrorList errors={grouped.bySpec[c.spec_id] ?? []} />
              </section>
            ))}
            {!siteControls.length && (
              <p className="text-sm">No controls need a site-specific fix.</p>
            )}
          </Card>
          <ConnectionLimits
            form={form}
            hasSnapshot={!!s.snapshot}
            errors={grouped.connection}
            update={update}
          />
          <Card title="Save">
            <ErrorList errors={grouped.general} />
            <div className="flex flex-wrap gap-3 items-center">
              <button
                className={button}
                disabled={
                  !!pending ||
                  check.status === "invalid" ||
                  check.status === "checking"
                }
                onClick={async () => {
                  setPending("Saving draft")
                  setSaveErrors([])
                  try {
                    const r = await api(
                      s.service,
                      base,
                      draftBody(form, controls),
                    )
                    setSaved(r)
                    setApproving(null)
                    await refresh()
                  } catch (e) {
                    setSaveErrors(messageOf(e))
                  } finally {
                    setPending("")
                  }
                }}
              >
                Save as draft
              </button>
              {saved && !isApproved(saved) && (
                <button
                  className={outline}
                  disabled={!!pending}
                  onClick={() => setApproving(saved)}
                >
                  Approve this draft…
                </button>
              )}
              {pending && (
                <span className="text-sm text-teal-800">{pending}…</span>
              )}
            </div>
            {saved && (
              <SavedNotice
                saved={saved}
                onUse={() => {
                  void live.choosePolicyProfile(toChosen(saved))
                  onBack()
                }}
              />
            )}
            <p className="text-xs text-slate-500">
              A draft is never used by an assessment. Approval is a separate,
              explicit step by a named person; nothing is approved
              automatically.
            </p>
          </Card>
        </>
      )}
    </>
  )
}

function ValidationStatus({ check }: { check: Check }) {
  if (check.status === "checking" || check.status === "idle")
    return <p className="text-sm text-slate-500">Checking with the server…</p>
  if (check.status === "valid")
    return (
      <p className="text-sm text-green-700">
        The server accepted every value in this draft.
      </p>
    )
  if (check.status === "unavailable")
    return (
      <p className="text-sm text-amber-800 break-words">
        Live validation is unavailable ({check.errors.join("; ")}). The server
        still checks the draft when you save it.
      </p>
    )
  return (
    <p className="text-sm text-red-700">
      The server found {check.errors.length} problem
      {check.errors.length === 1 ? "" : "s"}; see the messages next to each
      field.
    </p>
  )
}

type SavedNoticeProps = {
  saved: any
  onUse: () => void
}

function SavedNotice({ saved, onUse }: SavedNoticeProps) {
  const approved = isApproved(saved)
  return (
    <div className="rounded-lg border p-3 text-sm space-y-2">
      <p className="flex flex-wrap gap-2 items-center">
        <span>
          {approved ? "Approved" : "Saved draft"}{" "}
          <strong>{saved.profile_id}</strong> · sha{" "}
          <span className="font-mono">{shortSha(saved.profile_ref)}</span>
        </span>
        {approved && (
          <>
            <span>
              by <strong>{saved.approved_by}</strong> at {saved.approved_at}
            </span>
            <DemoApprovalTag />
          </>
        )}
      </p>
      {approved ? (
        <button className={button} onClick={onUse}>
          Use this profile for the assessment
        </button>
      ) : (
        <p>
          It is not used by any assessment until a named person approves it.
        </p>
      )}
    </div>
  )
}

function ProfilesTable({
  profiles,
  activeRef,
  disabled,
  onEdit,
  onApprove,
  onUse,
}: {
  profiles: any[]
  activeRef?: string
  disabled: boolean
  onEdit: (p: any) => void
  onApprove: (p: any) => void
  onUse: (p: any) => void
}) {
  if (!profiles.length)
    return <p className="text-sm">No policy profiles are stored yet.</p>
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr>
            <th className="p-2">Profile</th>
            <th className="p-2">Status</th>
            <th className="p-2">Approval</th>
            <th className="p-2">Actions</th>
          </tr>
        </thead>
        <tbody>
          {profiles.map((p) => (
            <tr
              key={p.profile_ref}
              className="border-t border-slate-100 align-top"
            >
              <td className="p-2">
                {p.profile_id}
                <small className="block text-slate-500 font-mono">
                  sha {shortSha(p.profile_ref)}
                  {p.source === "seed"
                    ? " · DBGuard reference (read-only)"
                    : ""}
                </small>
              </td>
              <td className="p-2">{isApproved(p) ? "approved" : "draft"}</td>
              <td className="p-2">
                {isApproved(p) ? (
                  <span className="space-y-1 block">
                    <span className="block">
                      {p.approved_by} · {p.approved_at}
                    </span>
                    <DemoApprovalTag />
                  </span>
                ) : (
                  "Not approved"
                )}
              </td>
              <td className="p-2 space-x-2 space-y-1">
                <button
                  className={outline}
                  disabled={disabled}
                  onClick={() => onEdit(p)}
                >
                  Edit as new draft
                </button>
                {isApproved(p) ? (
                  activeRef === p.profile_ref ? (
                    <span className="text-teal-800">
                      Selected for assessment
                    </span>
                  ) : (
                    <button
                      className={outline}
                      disabled={disabled}
                      onClick={() => onUse(p)}
                    >
                      Use for assessment
                    </button>
                  )
                ) : (
                  <button
                    className={outline}
                    disabled={disabled}
                    onClick={() => onApprove(p)}
                  >
                    Approve…
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function PolicyValueControl({
  control: c,
  value,
  seed,
  errors,
  onChange,
}: {
  control: any
  value: {
    expected: string
    fix: string
    brk: string
  }
  seed: any
  errors: string[]
  onChange: (key: "expected" | "fix" | "brk", v: string) => void
}) {
  return (
    <section className="border border-slate-200 rounded-lg p-4 space-y-2">
      <h3 className="font-semibold">{cisRule(c)}</h3>
      <p className="text-xs text-slate-500">
        Setting <code>{c.setting_name}</code>
      </p>
      <p className="text-sm">{settingHelp(c)}</p>
      {c.applies_when && (
        <p className="text-sm text-slate-600">
          Only checked when {conditionPhrase(c.applies_when)}.
        </p>
      )}
      <blockquote className="border-l-4 border-slate-300 pl-3 text-sm italic text-slate-700">
        CIS: “{c.pass_condition_quote}”
      </blockquote>
      <p className="text-xs text-slate-500">Allowed shape: {shapeHint(c)}</p>
      {seed && (
        <p className="text-xs text-slate-500">
          Recommended (reference profile): expected{" "}
          <code>{expectedToText(seed.expected)}</code>, fix{" "}
          <code>{String(seed.fix)}</code>
        </p>
      )}
      <div className="grid gap-2 md:grid-cols-3">
        <label className="block text-sm">
          Accepted value{c.operator === "equals" ? "" : "s"}
          <input
            className={input}
            aria-label={`Accepted value for ${c.recommendation}`}
            value={value.expected}
            onChange={(e) => onChange("expected", e.target.value)}
          />
        </label>
        <label className="block text-sm">
          Fix value (the sandbox sets this)
          <input
            className={input}
            aria-label={`Fix value for ${c.recommendation}`}
            value={value.fix}
            onChange={(e) => onChange("fix", e.target.value)}
          />
        </label>
        <label className="block text-sm">
          Test value that must fail
          <input
            className={input}
            aria-label={`Failing test value for ${c.recommendation}`}
            value={value.brk}
            onChange={(e) => onChange("brk", e.target.value)}
          />
        </label>
      </div>
      <p className="text-xs text-slate-500">
        The fix value must pass the check; the test value must fail it, so the
        sandbox can prove the check catches a wrong setting.
      </p>
      <ErrorList errors={errors} />
    </section>
  )
}

function ConnectionLimits({
  form,
  hasSnapshot,
  errors,
  update,
}: {
  form: ProfileForm
  hasSnapshot: boolean
  errors: string[]
  update: (next: (f: ProfileForm) => ProfileForm) => void
}) {
  function setRole(index: number, key: "name" | "limit", v: string) {
    update((f) => ({
      ...f,
      roles: f.roles.map((r, i) => (i === index ? { ...r, [key]: v } : r)),
    }))
  }
  return (
    <Card title="Connection limits (groundwork for CIS 5.5)">
      <p className="text-sm">
        Stored with the profile for later fix proposals. DBGuard does not check
        or change connection limits yet. Superusers ignore connection limits, so
        a limit on a superuser role has no effect.
      </p>
      <label className="block text-sm max-w-xs">
        Default limit for login roles (blank = none)
        <input
          className={input}
          aria-label="Default connection limit for login roles"
          inputMode="numeric"
          value={form.defaultLimit}
          onChange={(e) =>
            update((f) => ({ ...f, defaultLimit: e.target.value }))
          }
        />
      </label>
      {!hasSnapshot && (
        <p className="text-xs text-slate-500">
          Load a snapshot to pre-fill the login roles of your server.
        </p>
      )}
      {form.roles.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr>
                <th className="p-2">Role</th>
                <th className="p-2">Limit on the server now</th>
                <th className="p-2">Limit in this profile (blank = default)</th>
                <th className="p-2" />
              </tr>
            </thead>
            <tbody>
              {form.roles.map((r, i) => (
                <tr key={i} className="border-t border-slate-100">
                  <td className="p-2">
                    <input
                      className={input}
                      aria-label={`Role name ${i + 1}`}
                      value={r.name}
                      onChange={(e) => setRole(i, "name", e.target.value)}
                    />
                    {r.superuser && (
                      <small className="block text-amber-800">
                        Superuser: ignores connection limits
                      </small>
                    )}
                  </td>
                  <td className="p-2">{r.current}</td>
                  <td className="p-2">
                    <input
                      className={input}
                      aria-label={`Connection limit for ${r.name || `role ${i + 1}`}`}
                      inputMode="numeric"
                      value={r.limit}
                      onChange={(e) => setRole(i, "limit", e.target.value)}
                    />
                  </td>
                  <td className="p-2">
                    <button
                      className="text-teal-700 text-sm"
                      onClick={() =>
                        update((f) => ({
                          ...f,
                          roles: f.roles.filter((_, j) => j !== i),
                        }))
                      }
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <button
        className={outline}
        onClick={() =>
          update((f) => ({
            ...f,
            roles: [
              ...f.roles,
              {
                name: "",
                limit: "",
                superuser: false,
                current: "not in this snapshot",
              },
            ],
          }))
        }
      >
        Add role override
      </button>
      <ErrorList errors={errors} />
    </Card>
  )
}
