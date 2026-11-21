<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo-light.svg" alt="Cais" width="240">
  </picture>
</h1>

Declarative application operations for people and agents, using Rust, JSON and SSH.

> **Pre-release (0.1 beta).** Interfaces can still change before 1.0, and the project
> has had no external security audit. The server side runs a root broker through sudo:
> read [SECURITY.md](SECURITY.md) before installing it on a machine you care about.

What works today: registration, packaging, publication, environment, restart and status
of isolated applications on Linux/systemd ([native mode](docs/NATIVE.md)), plus optional
PostgreSQL databases with private credential export, unprivileged psql and SSH tunnels
([PostgreSQL operations](docs/POSTGRES.md)), and optional Caddy routes and backup
registration ([integrations](docs/INTEGRATIONS.md)), and project metadata with a catalog
file for dashboards and other consumers ([catalog](docs/CATALOG.md)). Agents can use the
same operations through a local [MCP server](docs/MCP.md). What is planned before 1.0
is in [the roadmap](docs/ROADMAP.md).

To install it, follow [the quickstart](docs/QUICKSTART.md). The releases page has
binaries for the Linux host and for Windows, macOS and Linux clients.
Installations managed by other tools can be referenced for read-only `list`/`status`;
their deployments, services and databases stay with those tools.

Licensed under [Apache 2.0](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) to build,
test and propose changes.

## Try it locally

Requires Rust 1.88 or newer (verified with 1.98), Cargo, and OpenSSH 8.5+ for remote commands.
Run from this directory:

```sh
cargo build --workspace --locked
cargo run --bin cais -- capabilities --json
cargo run --bin cais -- validate --file examples/cais.json --json
cargo run --bin cais -- schema project
```

Windows defaults to the native `%SystemRoot%/System32/OpenSSH/ssh.exe`, avoiding the
incompatible Git/MSYS executable on PATH. Set `ssh_executable` in a target to use a
different local OpenSSH binary explicitly. Linux/macOS use `ssh` from PATH by default.

Configuration validation is deliberately local: it does not check that artifacts exist,
resolve DNS, inspect systemd or prove a service is healthy. Paths are relative POSIX
paths even on Windows; declare Linux executable permissions explicitly.

Three configurations have separate owners:

* `cais.json`: versionable project intent, without secrets.
* A client JSON file: named SSH targets and private key/known_hosts **paths**, never keys.
* `/etc/cais/server.json`: administrator-controlled project access and delegated hosts.

Examples use fictional accounts and domains. Nothing requires a specific host, domain,
reverse proxy, identity provider, database or backup service. A named access provider in a policy is a
declaration for planning, not an implemented authentication integration.

## Linux planning server

This section describes the unprivileged foundation when `host` is omitted. Native
application management uses the separate root broker described in [NATIVE.md](docs/NATIVE.md).

An administrator installs the Linux executable at `/usr/local/bin/cais-server` and a
policy like `examples/server.json` at `/etc/cais/server.json`. The server and policy
should be administratively owned. Policy files must not be group/world writable;
parents must have trusted ownership and modes, without symlinks. A private installation
owned by the process account is also supported, without creating an elevated boundary.
Writable parents are rejected even with a sticky bit: do not put host policies under
`/tmp`. An operator-owned policy provides no protection from that operator's own shell.

Run the server as the SSH login, **without sudo**. It uses the operating-system account
lookup and ignores client identity claims and environment variables such as `SUDO_USER`.
Only the fixed operations in the protocol are accepted. One process handles one request.
No daemon, listener, new sudo rule, mutable host registry or production install is needed
for this phase. Project policies describe delegated names, not existing app deployments.

Copy `examples/client.json` outside the repository and configure a verified host key and
an appropriate operator identity. Paths to identity, SSH config and known_hosts files are
relative to that client configuration file. No implicit home or `~` expansion is performed.
When `port` is omitted, the port from the OpenSSH alias is preserved. An explicit `port`
overrides it. Agent/X11/port forwarding, local commands, host-key updates, DNS host-key
trust and external known-hosts commands are disabled for control sessions.
SSH connection multiplexing and tunnel devices are disabled too: a control session
must establish its own connection and cannot inherit another master's host trust or identity.
Remote executable paths must be absolute POSIX paths without whitespace or shell syntax.
If an administrator needs a nondefault server policy, use an administratively installed
wrapper executable; the wire protocol cannot choose a configuration path.

```sh
cais capabilities --target staging --config /path/to/client.json --json
cais list --target staging --config /path/to/client.json --json
cais plan --file cais.json --target staging --config /path/to/client.json --json
```

OpenSSH's host key verification is mandatory. Obtain the host public key through a
trusted channel; discovery by `ssh-keyscan` alone is not verification. Supply a dedicated
`ssh_config` to avoid inheriting unrelated aliases/proxies if appropriate. The client
uses BatchMode, no PTY, strict host checking, and an overall deadline. It emits fixed
transport errors rather than forwarding arbitrary SSH stderr.

`plan` is explicitly a **non-executable preview**: it validates the project and delegated
hostname/access profile/backup request. It does not compare against deployed files or
verify provider availability. The output says `execution_supported: false` and
`current_runtime_state: not_observed`. A digest identifies normalized project intent,
not an approval token or proof of an operation running exactly once.

## Agent interface

`--json` emits one result on stdout and no CLI diagnostic on stderr. A result has
`schema_version`, `outcome` and either `data` or `error`. Schema export is intentionally
raw JSON; `--help` and `--version` retain their standard display behavior. The long-lived
`db-tunnel` command instead emits documented readiness/closed NDJSON events. `db-psql`
is a human session and refuses JSON mode.

Exit codes: `0` success; `1` internal error; `2` invalid config/usage; `3` denied by
identity/policy; `4` incompatible/unsupported; `5` transport/protocol/deadline;
`6` busy/conflict; `7` operation failed; `8` unknown mutation outcome.
No command is automatically retried. No partial operation is inferred to have succeeded.
Native mutating operations require current revisions and server authorization. Secrets
use only the explicit private-file transfer, never JSON results. `cais mcp` exposes the
same operations as typed tools; see [MCP.md](docs/MCP.md).

Schemas in `schemas/` are generated from the Rust types. They cover structural rules;
use `cais validate` for semantic checks such as path overlap and policy references.

## Verification

```sh
cargo test --workspace --locked
python tools/export_schemas.py --client target/debug/cais --check
```

`python3 tools/verify_client.py` runs the client against a private sshd on the current
machine, without Docker or root: host-key trust, key permissions, adversarial peers,
private exports and an MCP call. CI runs it on Linux against the planning server and on
macOS against a protocol peer, since the server itself runs only on Linux.

Tests also exercise OpenSSH's effective configuration using `ssh -G`. For Linux Docker
tests, build `docker build -t cais-rust-test:local -f tests/runner/Dockerfile .` and use
that image with the source mounted at `/work`, a Cargo cache volume, and a separate
target directory such as `target/linux`.

On Windows use `target/debug/cais.exe`. The SSH journey uses a real local Docker sshd,
real CLI, and Linux server with synthetic keys, including denials, host-key mismatch,
bad peers, deadline, spoofed environment, and writable policy rejection. Build a Linux
server **and client** with Rust locally or in `rust:1.98-slim` (keep its target directory
separate). The helper requires `target/linux/debug/cais-server` and `target/linux/debug/cais`:

```sh
python tools/verify_ssh.py --client target/debug/cais.exe --server target/linux/debug/cais-server --report .local/verification/windows-ssh.json
```

The test image is defined in `tests/ssh/Dockerfile`; Docker and Python 3.9+ are needed.
The helper generates synthetic keys in a temporary directory and removes its own
container in `finally`. It never uses a production SSH alias, key or credential.

## Project boundaries

Cais is standalone. Dashboards, monitors and other tools integrate by reading the
[catalog](docs/CATALOG.md); Cais never depends on one of them to operate, and none is required.
The repository contains the implementation and fictional examples.
