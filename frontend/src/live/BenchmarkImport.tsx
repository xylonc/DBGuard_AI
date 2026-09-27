import { useState } from "react"
import { api, request } from "@/adapters/live"
import { useLive } from "@/store/liveStore"
import { Card, Raw } from "./LiveUI"
export function BenchmarkImport() {
  const live = useLive(),
    [receipt, setReceipt] = useState<any>(null),
    [reviewer, setReviewer] = useState(""),
    [reviewed, setReviewed] = useState(false)
  const button = "rounded bg-teal-700 text-white px-4 py-2 disabled:opacity-40"
  return (
    <Card title="Import benchmark workbook">
      <p>
        Supported format: CIS PostgreSQL 17 v1.1.0, Combined Profiles sheet.
        Existing exact-match reviewed specs are reused. Other controls are
        listed as manual or needing capability; they are never silently marked
        automated.
      </p>
      <input
        aria-label="Benchmark XLSX"
        type="file"
        accept=".xlsx"
        disabled={!!live.state.busy}
        onChange={(e) => {
          const f = e.target.files?.[0]
          if (f)
            void live.action(
              "Parsing benchmark and preparing specs",
              async () => {
                setReceipt(null)
                setReviewed(false)
                const body = new FormData()
                body.append("file", f)
                setReceipt(
                  await request("/bridge/main/api/v1/benchmarks/import", {
                    method: "POST",
                    body,
                  }),
                )
              },
            )
        }}
      />
      {receipt && (
        <>
          <p>
            {receipt.controls} controls · {receipt.automated} automated ·{" "}
            {receipt.manual_or_capability} manual / needs capability
          </p>
          <a
            className="text-teal-700 underline"
            href={`/bridge/main/api/v1/benchmarks/${receipt.benchmark_id}/package`}
            download
          >
            Download specs and collector for review
          </a>
          <Raw value={receipt} />
          <input
            aria-label="Benchmark reviewer"
            placeholder="Reviewer name"
            className="w-full border rounded p-2"
            value={reviewer}
            onChange={(e) => setReviewer(e.target.value)}
          />
          <label className="flex gap-2">
            <input
              type="checkbox"
              checked={reviewed}
              onChange={(e) => setReviewed(e.target.checked)}
            />
            I reviewed this exact spec set and its manual coverage limits.
          </label>
          <button
            className={button}
            disabled={
              !!live.state.busy ||
              !reviewed ||
              !reviewer.trim() ||
              receipt.status === "APPROVED"
            }
            onClick={() =>
              void live.action(
                "Approving exact benchmark release",
                async () => {
                  const a = await api(
                    "main",
                    `/api/v1/benchmarks/${receipt.benchmark_id}/approve`,
                    { reviewer, spec_set_hash: receipt.spec_set_hash },
                  )
                  setReceipt({ ...receipt, ...a })
                },
              )
            }
          >
            Approve spec release
          </button>
          {receipt.status === "APPROVED" && (
            <button
              className={button}
              disabled={!!live.state.busy}
              onClick={() => {
                live.reset("main")
                live.configure({ benchmark: receipt.benchmark_id })
              }}
            >
              Use this release on Main API
            </button>
          )}
          {receipt.status === "APPROVED" && (
            <p>
              Approved benchmark ID: <strong>{receipt.benchmark_id}</strong>.
              Run the downloaded collector and upload its snapshot.
            </p>
          )}
        </>
      )}
    </Card>
  )
}
