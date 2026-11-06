import { useState, type ChangeEvent, type InputHTMLAttributes } from "react"

// A file picker that looks like a button. The real <input type="file"> stays in
// the page (visually hidden, still focusable and labelled) so keyboard and screen
// reader users get the native picker; the chosen file's name is shown beside it.
type FileButtonProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "className"> & {
  label: string
}

export function FileButton({
  label,
  disabled,
  onChange,
  ...input
}: FileButtonProps) {
  const [chosen, setChosen] = useState("")
  return (
    <span className="inline-flex flex-wrap items-center gap-3">
      <label
        className={`inline-flex items-center gap-2 rounded-lg border border-teal-700 bg-white px-4 py-2 text-sm font-medium text-teal-800 focus-within:ring-2 focus-within:ring-teal-600 focus-within:ring-offset-1 ${
          disabled
            ? "opacity-40 cursor-not-allowed"
            : "cursor-pointer hover:bg-teal-50"
        }`}
      >
        <span aria-hidden="true">⇪</span>
        {label}
        <input
          {...input}
          type="file"
          className="sr-only"
          disabled={disabled}
          onChange={(e: ChangeEvent<HTMLInputElement>) => {
            setChosen(e.target.files?.[0]?.name ?? "")
            onChange?.(e)
          }}
        />
      </label>
      <span className="text-xs text-slate-500 break-all">
        {chosen || "No file chosen"}
      </span>
    </span>
  )
}
