import { test } from "node:test"
import assert from "node:assert/strict"
import http from "node:http"
import { spawn } from "node:child_process"
import { once } from "node:events"
const pause = (ms) => new Promise((r) => setTimeout(r, ms))
test("gateway isolates credentials, preserves ZIPs, and reports upstream failures", async () => {
  let hermesAuth, hermesOrigin
  const fixture = http.createServer(async (req, res) => {
    if (req.url === "/health" || req.url === "/api/v1/health") {
      res.setHeader("Content-Type", "application/json")
      return res.end("{}")
    }
    if (req.url === "/v1/chat/completions") {
      hermesAuth = req.headers.authorization
      hermesOrigin = req.headers.origin
      for await (const _ of req) {
      }
      res.setHeader("Content-Type", "application/json")
      return res.end(
        JSON.stringify({
          choices: [{ message: { content: "real transport test" } }],
        }),
      )
    }
    if (req.url === "/api/v1/sandbox/runs/test/bundle") {
      res.setHeader("Content-Type", "application/zip")
      return res.end(Buffer.from([80, 75, 3, 4]))
    }
    res.writeHead(422, { "Content-Type": "application/json" })
    res.end(JSON.stringify({ detail: "Invalid snapshot" }))
  })
  fixture.listen(0, "127.0.0.1")
  await once(fixture, "listening")
  const upstream = `http://127.0.0.1:${fixture.address().port}`
  const reserve = http.createServer()
  reserve.listen(0, "127.0.0.1")
  await once(reserve, "listening")
  const port = reserve.address().port
  await new Promise((r) => reserve.close(r))
  const proc = spawn(process.execPath, ["server.mjs"], {
    env: {
      ...process.env,
      UI_PORT: String(port),
      DBGUARD_ENV_FILE: "",
      HERMES_API_SERVER_KEY: "fixture-private-key",
      HERMES_API_URL: upstream,
      DBGUARD_API_URL: upstream,
      DBGUARD_DEMO_URL: upstream,
    },
    stdio: "pipe",
  })
  try {
    await once(proc.stdout, "data")
    const base = `http://127.0.0.1:${port}`
    const denied = await fetch(base + "/bridge/chat", {
      method: "POST",
      headers: {
        Origin: "https://untrusted.invalid",
        "Content-Type": "application/json",
      },
      body: "{}",
    })
    assert.equal(denied.status, 403)
    const invalid = await fetch(base + "/bridge/main/api/v1/snapshots/bad")
    assert.equal(invalid.status, 422)
    assert.match(await invalid.text(), /Invalid snapshot/)
    const bundle = await fetch(
      base + "/bridge/main/api/v1/sandbox/runs/test/bundle",
    )
    assert.equal(bundle.headers.get("content-type"), "application/zip")
    assert.deepEqual(
      [...new Uint8Array(await bundle.arrayBuffer())],
      [80, 75, 3, 4],
    )
    const jobResponse = await fetch(base + "/bridge/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        service: "demo",
        messages: [{ role: "user", content: "Hello" }],
      }),
    })
    assert.equal(jobResponse.status, 202)
    const job = await jobResponse.json()
    let final
    for (let i = 0; i < 40; i++) {
      final = await (await fetch(base + "/bridge/chat/" + job.id)).json()
      if (final.status !== "running") break
      await pause(50)
    }
    assert.equal(final.status, "complete")
    assert.equal(hermesAuth, "Bearer fixture-private-key")
    assert.equal(hermesOrigin, undefined)
    assert.ok(!JSON.stringify(final).includes("fixture-private-key"))
  } finally {
    proc.kill("SIGTERM")
    await once(proc, "exit")
    await new Promise((r) => fixture.close(r))
  }
})
