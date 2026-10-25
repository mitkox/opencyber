// opencyber-poc-guard — OpenCode V2 plugin.
//
// Defense-in-depth around OpenCyber's PoC execution gate. The server is the
// authority: `oc_poc_run` refuses without a signed, single-use approval bound to
// the spec/code hashes and an authorization record covering the target and
// technique. This plugin does not re-implement that verification (it cannot: the
// HMAC key lives inside the container). It does three cheap things on the host:
//
//   1. Rejects `oc_poc_run` calls whose shape cannot possibly be approved
//      (missing/empty engagement_id, chain_id, spec_id, or a fabricated
//      approval_id that does not match apr_YYYYMMDD_<32 hex>).
//   2. Leaves a host-side JSONL trail of every PoC run attempt and outcome.
//   3. Keeps the failure message actionable so the model asks the operator
//      instead of retrying with a different id.
//
// Install: copy to ~/.config/opencode/plugins/opencyber-poc-guard.ts
//
// V2 API note: import from `@opencode/plugin`, NOT `@opencode-ai/plugin` (the
// legacy V1 SDK's effect/schema build does not match the CLI). Hooks are
// `ctx.tool.hook("execute.before" | "execute.after", handler)`; throwing from a
// before-hook aborts the tool call.

import { Plugin } from "@opencode/plugin"
import { appendFile, mkdir } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"

// Matches oc_poc_run, opencyber_oc_poc_run, mcp__opencyber__oc_poc_run.
const RUN_TOOL = /(?:^|_)(?:mcp__)?(?:opencyber_+)?oc_poc_run$/
const APPROVAL_ID = /^apr_\d{8}_[0-9a-f]{32}$/
const LOG_DIRECTORY = join(homedir(), ".local", "state", "opencyber-poc")
const LOG_FILE = join(LOG_DIRECTORY, "guard.jsonl")

type AnyRecord = Record<string, unknown>

function asRecord(value: unknown): AnyRecord {
  return value && typeof value === "object" ? (value as AnyRecord) : {}
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : ""
}

async function log(record: AnyRecord): Promise<void> {
  try {
    await mkdir(LOG_DIRECTORY, { recursive: true })
    await appendFile(
      LOG_FILE,
      JSON.stringify({ ts: new Date().toISOString(), plugin: "opencyber-poc-guard", ...record }) + "\n",
      "utf8",
    )
  } catch {
    // Logging must never block an otherwise valid call.
  }
}

export default Plugin.define({
  id: "opencyber-poc-guard",
  async setup(ctx) {
    await ctx.tool.hook("execute.before", async (event) => {
      const toolName = text((event as AnyRecord).tool)
      if (!toolName || !RUN_TOOL.test(toolName)) return

      const input = asRecord((event as AnyRecord).input)
      const engagementId = text(input.engagement_id)
      const chainId = text(input.chain_id)
      const specId = text(input.spec_id)
      const approvalId = text(input.approval_id)
      const session = text((event as AnyRecord).sessionID)
      const agent = text((event as AnyRecord).agent)

      const problems: string[] = []
      if (!engagementId) problems.push("engagement_id is required")
      if (!chainId) problems.push("chain_id is required")
      if (!specId) problems.push("spec_id is required")
      if (!approvalId) {
        problems.push("approval_id is required (the operator mints it with opencyber-poc approve)")
      } else if (!APPROVAL_ID.test(approvalId)) {
        problems.push("approval_id does not look like apr_YYYYMMDD_<32 hex>")
      }

      if (problems.length > 0) {
        await log({
          decision: "denied",
          tool: toolName,
          session,
          agent,
          engagement_id: engagementId,
          chain_id: chainId,
          spec_id: specId,
          approval_id: approvalId,
          problems,
        })
        throw new Error(
          "opencyber-poc-guard blocked this oc_poc_run call: " +
            problems.join("; ") +
            ". Ask the operator to run `opencyber-poc approve` for this exact spec, " +
            "then pass the returned approval_id. Approvals are single-use and bound to " +
            "the spec and code hashes; do not invent one.",
        )
      }

      await log({
        decision: "allowed",
        tool: toolName,
        session,
        agent,
        engagement_id: engagementId,
        chain_id: chainId,
        spec_id: specId,
        approval_id: approvalId,
      })
    })

    await ctx.tool.hook("execute.after", async (event) => {
      const toolName = text((event as AnyRecord).tool)
      if (!toolName || !RUN_TOOL.test(toolName)) return
      const record = event as AnyRecord
      await log({
        decision: "finished",
        tool: toolName,
        session: text(record.sessionID),
        agent: text(record.agent),
        status: text(record.status) || "unknown",
      })
    })

    console.log("[opencyber-poc-guard] PoC run guard active")
  },
})
