# MCP server

`cais mcp` lets an agent that speaks the Model Context Protocol use Cais through typed
tools instead of composing command lines. It runs locally, next to the CLI, and talks
to the client over standard input and output.

```sh
cais mcp --config /private/client.json --root /path/to/workspace
```

Register that command in your MCP client as a stdio server. For example:

```json
{
  "mcpServers": {
    "cais": {
      "command": "cais",
      "args": ["mcp", "--config", "/private/client.json", "--root", "/path/to/workspace"]
    }
  }
}
```

## What an agent can and cannot do

Each tool is exactly one CLI command with typed arguments. The server starts the same
`cais` executable for every call, so validation, SSH transport, server-side
authorization, exit codes and error messages are the CLI's. An agent has the authority
of the SSH identities in the client configuration and nothing more.

* There is no tool that runs a shell, an arbitrary command or SQL.
* The client configuration is fixed when the server starts. Tools choose a target by
  name; they cannot supply another configuration, host, key or SSH option.
* File arguments are paths relative to `--root`. Absolute paths, `..` and links that
  leave the root are refused before anything runs. The check is made once: the
  workspace itself is trusted not to swap a file for a link afterwards.
* Interactive and long-lived commands are not exposed: `db-psql`, `db-tunnel` and the
  credential export `db-config`.
* Secrets do not pass through the protocol. `cais_env_set` takes the path of a values
  file, never the values, and results never contain them. An agent with other tools
  that can read your workspace can still read that file: keep it outside `--root` if the
  agent must not see it, and set the environment yourself with the CLI.

## Tools

| Tool | CLI command | Changes the server |
|---|---|---|
| `cais_capabilities` | `capabilities` | No |
| `cais_validate` | `validate` | No (local) |
| `cais_schema` | `schema` | No (local) |
| `cais_package` | `package` | No (local, writes the artifact) |
| `cais_list` | `list` | No |
| `cais_plan` | `plan` | No |
| `cais_status` | `status` | No |
| `cais_register` | `register` | Yes |
| `cais_deploy` | `deploy` | Yes |
| `cais_env_set` | `env-set` | Yes |
| `cais_restart` | `restart` | Yes |
| `cais_metadata_set` | `metadata-set` | Yes |
| `cais_proxy_apply`, `cais_proxy_remove` | `proxy-apply`, `proxy-remove` | Yes |
| `cais_backup_register` | `backup-register` | Yes |
| `cais_db_create`, `cais_db_reconcile` | `db-create`, `db-reconcile` | Yes |

Remote tools take a `target`. Where the CLI reads a saved status or plan from a file,
the tool takes the object inline: pass the result of `cais_status` as `expected`, and
the result of `cais_plan` as `plan`.

## Results

A tool result carries the CLI's JSON result in `structuredContent`, and the same text in
`content`. `isError` is true when the CLI exited with a nonzero code; the `error.code`
then tells why (`conflict`, `not_authorized`, `operation_failed`, ...).

The CLI's rules apply unchanged. Read `cais_status` before each mutation. A stale
revision is a `conflict`: read the status again and decide, do not loop. An
`unknown_outcome` means the mutation may or may not have happened; inspect the status
and involve a person before repeating anything.

Arguments that are malformed, unknown or outside the workspace are refused by the MCP
server itself: the result has `isError: true`, a short message and no
`structuredContent`, and no command was run. A command that ran and ended without a
result is reported as `unknown_outcome`, never as a refusal.

## Verification

`cargo test -p cais-cli --test mcp` runs a real session against the built binary:
handshake, discovery, local tools, path escapes, untyped input and protocol errors.
`tools/verify_integrations.py` ends with a session against a real server over SSH:
capabilities, list, plan, status, an allowed mutation, a stale revision, metadata, a
deployment identity exceeding its authority and a file outside the workspace. Both use
a small client that speaks the protocol directly; no third-party MCP client is part of
the tests.
