# Agent integrations — CVE-chain PoC workflow

Adapters for the 0.5.0 private pre-production beta. Begin with the
[beta guide](../docs/BETA_TESTING.md) before enabling PoC execution.

Thin adapters that let an agent drive OpenCyber's CVE-chain PoC tools. All
deterministic logic, authorization checking, scope enforcement, and evidence
capture live in the OpenCyber MCP server (`oc_chain_*`, `oc_poc_*`); these files
only teach a runtime how to use them and add host-side guardrails.

> Authorized testing only. The workflow requires a signed engagement
> authorization and a signed, single-use approval for every PoC run. The model
> has no signing tool through MCP. Arbitrary container-root code remains trusted;
> the workflow does not isolate signing authority from it. See [../docs/POC_CHAINS.md](../docs/POC_CHAINS.md).

## Layout

| Path | Purpose |
| --- | --- |
| `skills/cve-chain-poc/SKILL.md` | Runtime-neutral skill: gate, capability vocabulary, technique table, workflow, refusal rules. |
| `opencode/agents/cve-research.md` | OpenCode V2 primary agent with narrow permissions. |
| `opencode/plugins/opencyber-poc-guard.ts` | OpenCode V2 plugin: shape-checks `oc_poc_run`, host-side JSONL audit, actionable refusals. |
| `opencode/opencode.jsonc.example` | Code Mode MCP entry + permission fragment. |
| `opencode/opencode.poc-lab.json.example` | Project-scoped Code Mode config for the disposable PoC lab. |
| `dsh/cordis.patch.yml` | DSH `dsh-mcp-client` profile patch. |

## OpenCode V2 (Code Mode)

```sh
mkdir -p ~/.config/opencode/{skills,agents,plugins}
cp -r integrations/skills/cve-chain-poc ~/.config/opencode/skills/
cp integrations/opencode/agents/cve-research.md ~/.config/opencode/agents/
cp integrations/opencode/plugins/opencyber-poc-guard.ts ~/.config/opencode/plugins/
# merge the keys from integrations/opencode/opencode.jsonc.example into
# ~/.config/opencode/opencode.jsonc, then restart the client
opencode mcp list          # expect: ✓ opencyber connected
```

Select the `cve-research` agent and ask for a chain. Code Mode exposes the
tools as `tools.opencyber.oc_chain_plan(...)`, `tools.opencyber.oc_poc_run(...)`.
The guard log is written to `~/.local/state/opencyber-poc/guard.jsonl`.

## Local PoC lab

The adapters above expect the 0.5.0 server and its matching catalog.
[../docs/POC_LAB.md](../docs/POC_LAB.md) sets up a disposable container with the
selected image, a synthetic loopback target,
and a lab-only approval key, then runs the deterministic driver
(`scripts/poc-lab-run.py`) and the Code Mode two-turn flow. Use it to exercise
the gates without touching an engagement of record.

## DeepSeek Harness (DSH)

```sh
mkdir -p ~/.dsh/skills
cp -r integrations/skills/cve-chain-poc ~/.dsh/skills/
# append the insert entry from integrations/dsh/cordis.patch.yml to
# ~/.dsh/profiles/<profile>/cordis.patch.yml, then restart the harness
```

Tools appear as `mcp__opencyber__oc_*`. The skill is discovered from
`~/.dsh/skills` (user scope) or `<project>/.dsh/skills` (project scope). A
native cordis plugin is intentionally not required: the MCP surface is the same,
and the server-side gate is runtime-independent.

## What the adapters deliberately do not do

- They do not sign authorizations or approvals. The supported creator is the
  operator CLI, with
  `OPENCYBER_APPROVAL_KEY`, inside the container.
- They do not enforce scope or approval validity. The server does; a plugin that
  ran outside the container could not be trusted to.
- They do not enable `oc_bash` / `oc_python`. Arbitrary code execution stays a
  separate, denied-by-default capability, and the approval key is scrubbed from
  every tool child environment to reduce accidental disclosure. Container-root
  code remains trusted; this is not key isolation.
