# Agent integrations

The connection examples use the current beta guide's container name,
`opencyber-beta`. Complete [beta setup](BETA_TESTING.md) first; substitute your
container name if you chose a different one. The MCP server ID stays `opencyber`.

How to expose OpenCyber to an agent runtime and enable the CVE-chain PoC
workflow for the 0.5.0 private pre-production beta. Start with
[BETA_TESTING.md](BETA_TESTING.md) for a software-only exercise. The MCP surface
is identical everywhere; runtimes differ only in how
they launch the stdio server and how they surface tools.

> Authorized testing only. Integrations do not create authorization or
> approvals; the operator CLI does, inside the container.

## Transport recap

The server speaks MCP over stdio only and publishes no ports:

```sh
docker exec -i opencyber-beta opencyber-mcp
```

`-i` is required. OpenCyber uses MCP Python SDK `mcp>=2.3,<3` and `MCPServer`; the stdio launch command and `oc_*` names remain compatible with existing client configurations. Every client below launches that command. The generic client
matrix and tool-mode trade-offs are in [MCP_INTEGRATION.md](MCP_INTEGRATION.md).

## OpenCode V2 (Code Mode)

`opencode.jsonc` fragment:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "opencyber": {
        "type": "local",
        "command": ["docker", "exec", "-i", "opencyber-beta", "opencyber-mcp"],
        "codemode": true
      }
    }
  }
}
```

With Code Mode enabled (the default), the tools are not on the native tool list;
the agent calls them inside the code sandbox as `tools.opencyber.oc_chain_plan(…)`,
`tools.opencyber.oc_poc_run(…)`, and so on. Permission rules still use the
normalized `opencyber_<tool>` names.

Add the adapter files from [../integrations/](../integrations/README.md):

```sh
mkdir -p ~/.config/opencode/{skills,agents,plugins}
cp -r integrations/skills/cve-chain-poc ~/.config/opencode/skills/
cp integrations/opencode/agents/cve-research.md ~/.config/opencode/agents/
cp integrations/opencode/plugins/opencyber-poc-guard.ts ~/.config/opencode/plugins/
```

Then merge the permission rows from
[`integrations/opencode/opencode.jsonc.example`](../integrations/opencode/opencode.jsonc.example):
`oc_poc_run`, `oc_poc_render`, and `oc_poc_spec_create` ask the operator;
`oc_bash`, `oc_python`, and `oc_workspace_delete` stay denied.

The plugin is defence in depth, not the gate: it rejects `oc_poc_run` calls whose
shape cannot be approved, logs attempts to
`~/.local/state/opencyber-poc/guard.jsonl`, and leaves authorization, scope, and
approval verification to the server.

### Code Mode example

This is a schema example. The CVE and capability labels are illustrative; use
your own observed artifacts and signed target scope. A `200` assertion proves
the response condition, not a CVE or complete exploit chain.

```ts
const engagement = "eng_20261025_…"

const plan = await tools.opencyber.oc_chain_plan({
  engagement_id: engagement,
  entry_capabilities: ["position:internet", "net:http:8080", "auth:none"],
  artifacts: ["artifacts/nuclei.jsonl"],
  steps: [
    {
      cve_id: "CVE-2026-1111",
      asset: "app.lab.test",
      requires: ["net:http:8080", "auth:none"],
      provides: ["net:internal:6379"],
      basis: "advisory: server-side request forgery in the proxy endpoint",
      source: "nuclei",
    },
  ],
})
if (plan.verdict !== "complete") throw new Error(JSON.stringify(plan.missing))

const spec = await tools.opencyber.oc_poc_spec_create({
  engagement_id: engagement,
  chain_id: plan.chain_id,
  step_order: 1,
  technique: "http_sequence",
  target: "http://app.lab.test:8080",
  requests: [{ method: "GET", path: "/proxy?url=http://cache.lab.test:6379/" }],
  assertions: [{ type: "status_in", statuses: [200] }],
})
await tools.opencyber.oc_poc_render({ engagement_id: engagement, spec_id: spec.spec_id })
const lint = await tools.opencyber.oc_poc_lint({ engagement_id: engagement, spec_id: spec.spec_id })
if (!lint.passed) throw new Error(JSON.stringify(lint.blocking))
// Ask the operator for: opencyber-poc approve --engagement … --chain … --spec …
```

## DeepSeek Harness (DSH)

DSH consumes MCP servers through `@deepseek-ai/dsh-mcp-client`. Append the entry
from
[`integrations/dsh/cordis.patch.yml`](../integrations/dsh/cordis.patch.yml) to
the profile patch layer (`~/.dsh/profiles/<profile>/cordis.patch.yml`), install
the skill:

```sh
mkdir -p ~/.dsh/skills
cp -r integrations/skills/cve-chain-poc ~/.dsh/skills/
```

and restart the harness. Tools appear as `mcp__opencyber__oc_*` in the native
tool list; the skill is discovered from `~/.dsh/skills` (user scope) or
`<project>/.dsh/skills` (project scope).

DSH scrubs ambient environment names matching `KEY|PASSWORD|SECRET|TOKEN` from
MCP children, so `OPENCYBER_APPROVAL_KEY` must come from the container
environment (`docker run -e …`), not from the DSH process. That is also the
intended configuration split. This avoids handing the key to the host runtime, but it does not isolate signing material from arbitrary code running as container root; see [SECURITY_MODEL.md](SECURITY_MODEL.md).

A native cordis plugin is deliberately not required. The MCP tool surface and
the server-side gate are runtime-independent; a plugin would duplicate the guard
with no additional enforcement.

## Claude Code, Codex, Gemini CLI, Cursor, VS Code

The generic launch command works unchanged. For example:

```sh
claude mcp add opencyber -- docker exec -i opencyber-beta opencyber-mcp
codex mcp add opencyber -- docker exec -i opencyber-beta opencyber-mcp
gemini mcp add opencyber docker exec -i opencyber-beta opencyber-mcp
```

Copy the `cve-chain-poc` skill into the runtime's skill directory if it has one,
and use the same workflow. Without a skill, the tool descriptions and
[POC_CHAINS.md](POC_CHAINS.md) carry the contract. See [POC_LAB.md](POC_LAB.md)
for a disposable container plus synthetic target that exercises the workflow end
to end, including the Code Mode two-turn approval flow.

## Why the logic lives in OpenCyber, not in the adapter

- Deterministic chain math, scope checks, HMAC verification, evidence capture,
  and audit must be testable and identical across runtimes.
- A host-side plugin is not the server's enforcement point. An operator with
  Docker access may still access the workspace or key; the host is trusted.
- Adapters stay small enough to review: a skill, an agent profile, one guard
  plugin, one config patch.
