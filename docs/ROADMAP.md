# Roadmap

Cais is in pre-release. This page says what works today, what is planned before 1.0
and what is deliberately out of scope. A capability is reported as available
only after it is implemented and exercised; configuration can declare intent for a
provider without proving that the provider is present.

## Design decisions

* Rust CLI clients for Windows, macOS and Linux; a Linux/systemd server; the system
  OpenSSH as the only transport.
* Versioned protocol, structured output for agents, explicit capabilities and stable
  error codes.
* JSON project intent, personal target profiles and an administrative host policy, each
  with a JSON Schema. No particular username, domain, IP address, filesystem layout or
  vendor is required.
* The SSH/operating-system identity is the authority. Nothing a client writes in JSON
  grants permissions. Operator and deployment identities are distinct, and deployment or
  runtime accounts cannot update administrative code.
* Reverse proxy, database, backup, access-control and catalog consumers are optional
  providers. None of them is a dependency of the core.
* No web administration UI, no arbitrary privileged shell and no privileged plugins
  loaded from a project.

## Available today

| Area | Status |
|---|---|
| Configuration validation, schemas, capabilities, list and non-executable plan | Implemented and exercised over real OpenSSH from Windows and Linux clients; the macOS client is exercised against protocol peers |
| Native applications on Linux/systemd: register, package, deploy, environment, restart, status | Implemented; see [NATIVE.md](NATIVE.md) |
| Preservation of declared data directories across deployments | Implemented |
| Revision checks, project lock and explicit unknown/partial outcomes | Implemented; see the [fault journey](NATIVE.md#fault-journey) |
| Optional PostgreSQL: own database and role, private credential export, unprivileged psql and SSH tunnel | Implemented; see [POSTGRES.md](POSTGRES.md) |
| Optional Caddy routes: one host per project at the root or under a prefix, public or behind an administrator snippet, automatic HTTPS, checked reload and removal | Implemented and exercised against a real Caddy, including a forward-auth login flow; see [INTEGRATIONS.md](INTEGRATIONS.md) |
| Optional backup registration: manifests of data paths and databases, coverage reported by an administrator check | Implemented and exercised with a real PostgreSQL database |
| Project metadata and an optional catalog file for read-only consumers | Implemented; see [CATALOG.md](CATALOG.md) |
| Local MCP server exposing the CLI's typed operations, without a terminal | Implemented; see [MCP.md](MCP.md) |
| Read-only references to installations managed by other tools | Implemented |

## Planned before 1.0

| Area | Planned result |
|---|---|
| Reverse proxy | A journey with a real identity product in place of the forward-auth stand-in, and a documented recovery after an unknown reload outcome. DNS stays external. |
| Backups | A reference coverage check for a common backup tool. |
| MCP | Sessions exercised with widely used MCP clients, in addition to the protocol-level tests. |
| Failure handling | The faults not yet injected: a proxy reload that times out, a full disk, and a lost connection while the server keeps running. |
| Platforms | A full journey from a macOS client to a real broker (today the macOS client is covered against protocol peers over the system OpenSSH, because the server runs only on Linux); spoofed-caller and secret-canary tests on each platform. |
| Distribution | Reproducible builds of the published per-platform archives, and Linux binaries for ARM64. |
| Review | An external security audit. |

## Semantics that will not change

* Metadata registration is separate from deployment: a partial success is reported and
  metadata is repaired without publishing again.
* A request ID is a correlation value, not an exactly-once guarantee.
* No command is retried automatically and no application rollback is promised.

## Out of scope

* Adopting or migrating applications, directories or databases that Cais did not create.
* Installing a PostgreSQL cluster, a reverse proxy or a backup service.
* A resident management daemon or a network listener.
