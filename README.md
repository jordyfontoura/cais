<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img src="docs/assets/logo-light.svg" alt="Cais" width="240">
  </picture>
</h1>

<p align="center">
  Deploy and operate applications on your own Linux server, over SSH.<br>
  For people and for agents. No containers, no daemon, no web panel.
</p>

<p align="center">
  <a href="https://github.com/jordyfontoura/cais/actions/workflows/ci.yml"><img src="https://github.com/jordyfontoura/cais/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

> **Pre-release (0.1 beta).** Interfaces can still change before 1.0, and the project
> has had no external security audit. The server side runs a root broker through sudo:
> read [SECURITY.md](SECURITY.md) before installing it on a machine you care about.

## What it is

Cais (Portuguese for *quay*) takes an application you built, uploads it to a Linux
server you already have, and runs it as a systemd service under its own account. You
describe the application in a small JSON file and drive everything with one command-line
tool, or let an agent drive the same operations through MCP.

* **Nothing stays running on the server.** The server program starts when you connect
  over SSH and exits when the request ends. There is no daemon, no listening port and
  no web administration interface.
* **Identity comes from SSH and Linux accounts.** There are no Cais users, passwords or
  tokens. An administrative policy file says which account may operate which project.
* **Deployment is a separate, narrow identity.** Each project gets its own deployment
  key that can publish that project and nothing else. Setting the environment and
  restarting stay with the operator.
* **One small privileged component.** A root broker accepts a fixed list of typed
  operations. It cannot run an arbitrary command, and a caller cannot tell it who they
  are or which policy to use.
* **Results you can trust in a script.** Every command prints one JSON result and
  returns a documented exit code. Nothing is retried behind your back, and an operation
  that may or may not have completed is reported as an unknown outcome, never as a
  success.
* **Optional pieces stay optional.** PostgreSQL databases, public routes through Caddy,
  backup registration and a catalog for dashboards are available, and none is required.

## A first look

A project is described by a `cais.json` like this one, from
[`examples/demo-python`](examples/demo-python):

```json
{
  "schema_version": 1,
  "project": "hello-python",
  "artifact": { "directory": "./dist", "publish": ["app.py"] },
  "app": { "kind": "http", "runtime": "python", "entrypoint": "app.py", "health": "/health" }
}
```

Registering and publishing it looks like this:

```sh
# Once, as the operator: check the plan and register the project with its deployment key.
cais plan     --file cais.json --target operator --config client.json --json > plan.json
cais register --file cais.json --plan plan.json --deploy-public-key deploy_key.pub --target operator --config client.json --json

# Every release: package, read the current state, and publish as the deployment identity.
cais package --file cais.json --output hello-python.tar.gz --json
cais status hello-python --target operator --config client.json --json > status.json
cais deploy  --file cais.json --artifact hello-python.tar.gz --expected status.json --target deploy --config client.json --json
```

An HTTP deployment is confirmed only when the application answers on its health path, on a
loopback port, from its own account. `--expected` carries the state you last read, so a
change you did not see makes the command refuse instead of overwriting it. The
[quickstart](docs/QUICKSTART.md) walks through the whole journey on a new host.

## How it works

```text
 your machine                          Linux host
 ------------                          ----------
 cais (CLI or MCP)  -- SSH -->  cais-server   runs as your login, without privileges
                                    |
                                    |  sudo, fixed path, no arguments
                                    v
                                cais-broker   root, fixed operations, reads the policy
                                    |
                                    v
                                one systemd service per application,
                                each with its own account and loopback port
```

Three configuration files have separate owners:

* `cais.json`: the project's intent, safe to commit, without secrets.
* A client JSON file: named SSH targets and the **paths** of private keys and
  `known_hosts`, never the keys themselves.
* `/etc/cais/server.json`: written by the host administrator; says who may operate what
  and which hostnames, databases and backups are delegated to each project.

Host key verification is mandatory, and the client never accepts an unknown host. The
details of the transport are in [CLIENT.md](docs/CLIENT.md) and
[PROTOCOL.md](docs/PROTOCOL.md).

## What works today

| Area | What you get | Guide |
|---|---|---|
| Applications | Register, package, publish, set the environment, restart and read the status of HTTP and static applications on Linux with systemd | [NATIVE.md](docs/NATIVE.md) |
| PostgreSQL (optional) | A database per project, private credential export, unprivileged `psql` and time-limited SSH tunnels | [POSTGRES.md](docs/POSTGRES.md) |
| Public routes (optional) | Routes through Caddy on hostnames the policy delegates to the project | [INTEGRATIONS.md](docs/INTEGRATIONS.md) |
| Backups (optional) | Registration of what a project needs backed up, with reported coverage | [INTEGRATIONS.md](docs/INTEGRATIONS.md) |
| Metadata and catalog (optional) | Project metadata and a catalog file for dashboards and other consumers | [CATALOG.md](docs/CATALOG.md) |
| Agents | The same operations as typed tools in a local MCP server | [MCP.md](docs/MCP.md) |

Installations managed by other tools can be referenced for read-only `list` and
`status`; their deployments, services and databases stay with those tools. What is
planned before 1.0, and what is out of scope, is in [the roadmap](docs/ROADMAP.md).

## Install

Follow [the quickstart](docs/QUICKSTART.md). The
[releases page](https://github.com/jordyfontoura/cais/releases) has archives with
checksums for the Linux host and for Windows, macOS and Linux clients.

* **Host:** Linux x86_64 with systemd, OpenSSH server and sudo, glibc 2.36 or newer
  (Debian 12, Ubuntu 24.04 and later). Exercised on Debian 13.
* **Client:** Windows, macOS or Linux with OpenSSH 8.5 or newer.
* **Applications:** Node, Python or a Linux executable, with interpreters installed by
  the administrator. Nothing is installed as root during a deployment.

Do not use it to adopt an existing installation: Cais manages only what it creates.

## For scripts and agents

With `--json`, a command prints one result on stdout and nothing on stderr. A result has
`schema_version`, `outcome` and either `data` or `error`. Secrets never appear in a
result; they travel only through an explicit private-file export.

| Exit code | Meaning |
|---|---|
| `0` | Success |
| `1` | Internal error |
| `2` | Invalid configuration or usage |
| `3` | Denied by identity or policy |
| `4` | Incompatible or unsupported |
| `5` | Transport, protocol or deadline |
| `6` | Busy or conflict |
| `7` | The operation failed |
| `8` | Unknown outcome of a mutation: read the status before repeating anything |

Two commands differ on purpose: `db-tunnel` is long-lived and prints readiness and
closing events as NDJSON, and `db-psql` is a human session that refuses JSON mode.
`--help`, `--version` and the raw schema export keep their usual output.

`cais mcp` exposes the same operations as typed tools for agents; see
[MCP.md](docs/MCP.md). The schemas in [`schemas/`](schemas) are generated from the Rust
types and cover structure; `cais validate` adds the semantic checks, such as overlapping
paths and policy references. Validation is local: it does not check that artifacts
exist, resolve DNS or prove that a service is healthy.

## Security

The model and its known limits are described in [SECURITY.md](SECURITY.md); read it
before installing the server side. Please report suspected vulnerabilities privately,
through the repository's *Report a vulnerability* button, and not in a public issue.

Every release archive has a checksum, and releases after 0.1.0-beta.1 also carry signed
build provenance. The quickstart shows how to check both.

## Documentation

| Page | Contents |
|---|---|
| [QUICKSTART.md](docs/QUICKSTART.md) | Install a host, configure a client and publish the example |
| [NATIVE.md](docs/NATIVE.md) | Application operations, state, failures and recovery |
| [POSTGRES.md](docs/POSTGRES.md) | Databases, credentials, `psql` and tunnels |
| [INTEGRATIONS.md](docs/INTEGRATIONS.md) | Caddy routes and backup registration |
| [CATALOG.md](docs/CATALOG.md) | Project metadata and the catalog file |
| [MCP.md](docs/MCP.md) | The MCP server for agents |
| [CLIENT.md](docs/CLIENT.md) | Client behaviour, SSH targets and the planning server |
| [PROTOCOL.md](docs/PROTOCOL.md) | The control protocol |
| [VERIFICATION.md](docs/VERIFICATION.md) | Running the tests and the journeys against local fixtures |
| [ROADMAP.md](docs/ROADMAP.md) | Design decisions, what is planned and what is out of scope |

## Build from source

Requires Rust 1.88 or newer and Cargo.

```sh
cargo build --workspace --locked
cargo run --bin cais -- capabilities --json
cargo run --bin cais -- validate --file examples/cais.json --json
cargo run --bin cais -- schema project
```

The server and the broker work only when built on Linux. See
[CONTRIBUTING.md](CONTRIBUTING.md) to build, test and propose changes.

## Project boundaries

Cais is standalone. Dashboards, monitors and other tools integrate by reading the
[catalog](docs/CATALOG.md); Cais never depends on one of them to operate, and none is
required. Nothing requires a specific host, domain, reverse proxy, identity provider,
database or backup service. The examples use fictional accounts and domains.

## License

[Apache License 2.0](LICENSE).
