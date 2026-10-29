import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

// Evidence.tsx is JSX, which node cannot import without a build step, so this
// checks the source: the row component reads the assessor's fixed notices
// (row.notices[].text, e.g. 7.4's restore-test reminder) and renders them
// whatever the status, never from model output.
const source = readFileSync(
  new URL("../src/live/Evidence.tsx", import.meta.url),
  "utf8",
)

test("CatalogEvidence reads row.notices and renders each notice's text", () => {
  assert.match(source, /export function CatalogEvidence/)
  assert.match(source, /Array\.isArray\(row\?\.notices\)/)
  assert.match(source, /row\.notices[\s\S]*?\.map\(\(n: any\) => n\?\.text\)/)
  assert.match(source, /notices\.map\(\(text, i\) =>/)
  // A row with only notices still renders (not hidden behind evidence).
  assert.match(source, /!evidence\.length && !notices\.length/)
})

test("every assessment row renders CatalogEvidence under its reason", () => {
  const live = readFileSync(
    new URL("../src/live/LiveUI.tsx", import.meta.url),
    "utf8",
  )
  assert.match(live, /import \{ CatalogEvidence \} from "\.\/Evidence"/)
  assert.match(live, /<CatalogEvidence row=\{r\} \/>/)
})

test("notices are rendered as text, never as HTML", () => {
  assert.doesNotMatch(source, /dangerouslySetInnerHTML/)
})
