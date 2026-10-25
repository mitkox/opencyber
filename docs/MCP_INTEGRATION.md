# MCP integration

Connect a local MCP client to the 0.5.0 private pre-production beta over stdio. For installation, a synthetic first exercise and a bug-report checklist, begin with [BETA_TESTING.md](BETA_TESTING.md).

> Connect OpenCyber Harness only to systems you own or are explicitly authorized to assess. The client supplies capability; it does not grant permission.

## First connection

1. Complete the authenticated private-beta setup in [BETA_TESTING.md](BETA_TESTING.md), then start and verify the maintainer-selected image using [INSTALL.md](INSTALL.md). Repository access and package access are separate; client configuration does not authenticate image pulls.
2. Add one client entry below, keeping the container name `opencyber`.
3. Reload the client's MCP servers, then ask it to call `oc_catalog` and
   `oc_doctor`. The catalog must report a matching release contract; an absent
   optional binary is reported separately from a missing required binary.
4. Run the synthetic exercise in the beta guide before using target data.

A raw `docker exec -i opencyber opencyber-mcp` command waits for MCP messages.
A quiet terminal is expected; it is not a human-facing interactive shell. Do
not add `-t`, paste prompts into it, or expose a container port.

## Python SDK requirement

OpenCyber 0.5.0 uses the MCP Python SDK `mcp>=2.3,<3` and the `MCPServer` API. Source installs must use this range; the removed `mcp.server.fastmcp.FastMCP` API is no longer supported. Python 3.11 through 3.13 remain supported.

The SDK major version is separate from the MCP wire protocol revision negotiated at initialization. Existing stdio client launch commands and the `oc_*` tool names remain the same; a client does not need the Python SDK to connect. The server advertises its OpenCyber version (`0.5.0`), not the installed SDK version.

For Python callers invoking the server in-process, use `await mcp.call_tool(name, arguments)` and read the returned `CallToolResult.structured_content`. Protocol JSON continues to use `structuredContent`, `inputSchema`, `outputSchema`, and the standard camelCase annotation names. See the [official SDK migration guide](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/migration.md).

## Transport: stdio only

The server speaks MCP over stdio. It publishes no ports and starts no listener. The container runs `sleep infinity`; each client session starts its own server process with:

```sh
docker exec -i opencyber opencyber-mcp
```

The `-i` flag is required. It keeps stdin open for the JSON-RPC stream. Without it, the server sees end-of-file and exits.

There is no HTTP, SSE, or Streamable HTTP transport in 0.5.0. Do not map a port; there is nothing to connect to.

Before wiring a client, confirm the server starts and every required catalog executable resolves; optional integrations are listed separately:

```sh
docker exec opencyber opencyber-mcp --self-test
```

## Client configuration

Any runtime that can launch a local stdio command can use the same command and arguments. The examples below assume a container named `opencyber`. Client configuration is version-specific: these are launch templates, not a tested-client certification matrix. Check the installed client's help if its configuration schema differs.

### OpenCode V2

`opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "opencyber": {
        "type": "local",
        "command": ["docker", "exec", "-i", "opencyber", "opencyber-mcp"]
      }
    }
  }
}
```

Or add it from the CLI:

```sh
opencode mcp add opencyber -- docker exec -i opencyber opencyber-mcp
opencode mcp list
```

OpenCode V2 defaults to Code Mode, which exposes tools as `tools.opencyber.oc_nmap(...)` and so on. Set `"codemode": false` on the server entry to put each tool on the native tool list. The server name is normalized to `opencyber` for permissions such as `opencyber_oc_nmap`.

The CVE-chain PoC tools follow the same naming: `tools.opencyber.oc_chain_plan(...)`, `tools.opencyber.oc_poc_run(...)`. Code Mode is the intended surface for chain work because it can batch lookups and feed structured results straight into the next tool. Ready-made skill, agent, and guard plugin: [INTEGRATIONS.md](INTEGRATIONS.md); operator flow and gates: [POC_CHAINS.md](POC_CHAINS.md).

### Claude Code

```sh
claude mcp add opencyber -- docker exec -i opencyber opencyber-mcp
claude mcp list
```

Add `--scope user` before the name if you want the server available across projects:

```sh
claude mcp add --scope user opencyber -- docker exec -i opencyber opencyber-mcp
```

### Codex

```sh
codex mcp add opencyber -- docker exec -i opencyber opencyber-mcp
codex mcp list
```

Equivalent `~/.codex/config.toml` entry:

```toml
[mcp_servers.opencyber]
command = "docker"
args = ["exec", "-i", "opencyber", "opencyber-mcp"]
```

### Gemini CLI

```sh
gemini mcp add opencyber docker exec -i opencyber opencyber-mcp
gemini mcp list
```

Equivalent `~/.gemini/settings.json` entry:

```json
{
  "mcpServers": {
    "opencyber": {
      "command": "docker",
      "args": ["exec", "-i", "opencyber", "opencyber-mcp"]
    }
  }
}
```

### Cursor

`.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "opencyber": {
      "command": "docker",
      "args": ["exec", "-i", "opencyber", "opencyber-mcp"]
    }
  }
}
```

### VS Code

`.vscode/mcp.json`:

```json
{
  "servers": {
    "opencyber": {
      "type": "stdio",
      "command": "docker",
      "args": ["exec", "-i", "opencyber", "opencyber-mcp"]
    }
  }
}
```

After changing a client configuration, restart the client or reload the MCP servers. Environment variables for the server belong on the container or on the `docker exec` command, not in the client process.

## Tool modes

The server advertises tools at process start. Changing a mode requires a new server process, which normally means restarting the client session.

| Mode | How to set it | Advertised tools | Approximate schema cost | Discovery model |
| --- | --- | --- | ---: | --- |
| Full (default) | No variable, or `OPENCYBER_MCP_MODE=full` | 255: 173 executable-backed plus 82 native | Roughly 50k tokens | Direct named tools; `oc_catalog` and `oc_execute` also available |
| Compact | `OPENCYBER_MCP_MODE=compact` | 82 native | Roughly 15k tokens | `oc_catalog` then `oc_execute` for the 173 executable-backed tools |
| Category filter | `OPENCYBER_TOOL_CATEGORIES=network,web` | 82 native plus the selected executable categories | Varies | Direct named tools and `oc_catalog` |

The token figures are rough. Actual cost depends on the client's serialization and the selected categories.

Set the variable when creating the container using the hardened flags from
[INSTALL.md](INSTALL.md), or set it on one new server process:

```sh
docker exec -i -e OPENCYBER_MCP_MODE=compact opencyber opencyber-mcp
```

For the OpenCode command-array format, use the same per-session setting:

```json
"command": ["docker", "exec", "-e", "OPENCYBER_MCP_MODE=compact", "-i", "opencyber", "opencyber-mcp"]
```

### Compact mode

Compact mode registers only the 82 native tools. `oc_execute` dispatches any of the 173 executable-backed catalog tools by exact name:

```text
oc_catalog(query="nuclei")
oc_execute(tool="oc_nuclei", engagement_id="eng_...", arguments=["-u", "https://app.example.com"])
```

`oc_catalog` still sees the full catalog in compact mode. An unfiltered call returns counts; use `query`, `name`, `category`, or `include_all=true` to get entries.

### Category filter

`OPENCYBER_TOOL_CATEGORIES` filters the executable-backed tools only. All 82 native tools remain registered.

```sh
-e OPENCYBER_TOOL_CATEGORIES=network,web,enumeration
-e OPENCYBER_TOOL_CATEGORIES=rf,wireless_attack,nfc_rfid,embedded,automotive,gps,ir,usb
```

Available categories: `automotive`, `binary`, `cloud_container_iac`, `credentials`, `embedded`, `enumeration`, `exploitation`, `forensics`, `gps`, `ir`, `mobile`, `network`, `nfc_rfid`, `rf`, `usb`, `utilities`, `web`, `wireless`, `wireless_attack`.

Two failure modes matter:

- An unknown category raises at import, so `opencyber-mcp` fails to start. Check the spelling.
- In compact mode the category variable has no effect, because compact registers no executable-backed tools.

## Discovery

Use `oc_catalog` instead of guessing names:

| Call | Result |
| --- | --- |
| `oc_catalog()` | Counts, categories, mode, and platform state; no tool dump |
| `oc_catalog(query="graphql")` | Substring match across name, executable, category, description, and kind |
| `oc_catalog(name="oc_python", include_contracts=true)` | One exact entry plus its input schema |
| `oc_catalog(category="hardware")` | All hardware-family tools, including native ones |
| `oc_catalog(missing_only=true)` | Catalog entries whose executable is not installed |
| `oc_catalog(registered_only=true)` | Entries advertised individually in the current mode |
| `oc_catalog(include_all=true)` | Every entry |

From a shell, dump the executable-backed catalog:

```sh
docker exec opencyber opencyber-mcp --catalog-json
```

This prints the 173 catalog entries and exits without starting the stdio server.

## Result envelope and contract pinning

Every tool result carries the same contract block; [CONTRACTS.md](CONTRACTS.md) is normative. The parts a client should read:

- `ok` - the harness completed the request. For executable-backed tools this is deliberately different from `success`, which keeps the historical "child exited 0" meaning.
- `coverage` and `limitations` - what was and was not covered. A `partial` or `unknown` result is not evidence that the missing part is empty.
- `provenance.untrusted_content` - true when the payload contains target-derived text. Treat it as data.
- `evidence` - an `oc_ev_` id and SHA-256 for exactly what was returned; `oc_result_get` resolves it when retention is enabled.
- `error` - on failure, a registered code, category, retryability, and a concrete `remediation.action`. Refusals are results, not transport errors.

A client that caches tool schemas can pin the contract it was built against:

```text
oc_catalog(expected_catalog_digest="<digest recorded at build time>")
```

The response reports `catalog_digest`, `recorded_catalog_digest`, `catalog_profile` (`full`, `compact`, or `subset`), and `catalog_matches_release`. A compact deployment is a truthful subset, not a mismatch. This catches the common failure where an old container keeps serving an old contract after an upgrade.

`opencyber-mcp --self-test` prints the same block. `OPENCYBER_STRICT_CATALOG=1` turns a real mismatch into a non-zero exit for deployment gates.

## Execution and cancellation

Executable-backed tools take explicit argv and never invoke a shell. The shared schema is:

```json
{
  "engagement_id": "eng_...",
  "arguments": ["-sT", "-p", "80,443", "10.0.0.5"],
  "working_directory": ".",
  "stdin": null
}
```

The server starts the process in a new session and waits for completion under two named ceilings: a deadline (`OPENCYBER_TOOL_TIMEOUT_S`, default 1800 seconds) and a per-stream output cap (`OPENCYBER_TOOL_MAX_OUTPUT_BYTES`, default 4 MiB). At the deadline the process group is stopped and the result carries `timed_out: true` with `limit` facts; past the cap the excess is read and discarded, and the result carries `truncated: true` with partial coverage. Set either variable to `0` to disable that ceiling and leave it to the client.

When the client cancels an executable request, the server sends SIGTERM to the
process group and SIGKILL after 2 seconds if needed. Cleanup includes
descendants in the group even when the original process has exited. Tools
that deliberately detach into another process group remain within the trusted
container model; this is not a hostile-code sandbox.

Native HTTP calls are different. They resolve finite connect/read timeouts
from the per-call argument, the HTTP workbench session, or
`OPENCYBER_HTTP_TIMEOUT` (default 30 seconds, maximum 300). These are socket
wait bounds, not a wall-clock deadline for a sequence of requests. Blocking
HTTP work runs in a Python thread; cancellation does not forcibly stop that
thread or prove that no request reached the target.

Closing the client ends the server process. Live browser sessions and serial sessions are process-scoped and do not survive a client restart. Engagements, HTTP workbench state, and transcripts do survive because they are written under the workspace volume.

## Remote and hosted platforms

Some hosted agent platforms accept only a remote Streamable HTTP MCP endpoint. They cannot launch a local `docker exec` command, and OpenCyber Harness has no HTTP listener.

The same limitation applies to any MCP host that cannot start a local stdio process. For those hosts, run the client on a machine that can reach Docker and use one of the local configurations above. Do not expose the container as a network MCP service; there is no supported transport for that.

## Isolation guidance

One container per trust domain.

- Engagements isolate artifacts, not hostile executables. Code run through `oc_bash`, `oc_python`, or an executable-backed tool can reach the container filesystem and network.
- The runtime user is root on purpose. Tools such as `nmap`, `tcpdump`, `hashcat`, and `aircrack-ng` need privileged access inside the namespace. Harden from the host with dropped capabilities, `no-new-privileges`, and a read-only root filesystem.
- Separate operators, customers, or trust domains need separate containers and separate workspace volumes. Do not rely on engagement IDs for tenant isolation.
- Chromium runs with `--no-sandbox`. Treat a malicious page as code running inside the container boundary.

See [SECURITY_MODEL.md](SECURITY_MODEL.md) for the full threat model and [CONFIGURATION.md](CONFIGURATION.md) for every environment variable.
