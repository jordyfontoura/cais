# Native application operations

This mode uses systemd, OpenSSH,
sudo, standard Linux account tools, and optionally administrator-installed Node/Python.
It has no web API or resident management daemon.

An administrator installs **both** Linux binaries `cais-server` and `cais-broker`, owned
by root in trusted directories. The default locations are `/usr/local/bin/cais-server`
and `/usr/local/libexec/cais/cais-broker`. The policy is always `/etc/cais/server.json`;
protocol callers cannot override it. Configure `host` as in `examples/server-native.json`.
All configured operators must already have Linux accounts and SSH access.

Run `/usr/local/libexec/cais/cais-broker --init` as an administrator. It creates dedicated
roots with installation markers and refuses to adopt populated directories. It validates
and installs no-argument sudo rules for configured operators. The broker, server, policy
and their parents must be root-owned and not writable by group/others. Initialization
must not be exposed to an operator's sudo rule. Reinitializing an unchanged installation
is supported; failed/partially initialized installations require administrative inspection.
Neither the client nor deploy accounts can install or update privileged binaries.

The ordinary SSH login invokes `cais-server` without sudo arguments. Native mode delegates
the inherited byte streams to the fixed no-argument broker through sudo. The broker derives
the actor from sudo's OS identity, independently loads the root policy and authorizes every
operation. An operator-owned planning policy can never select elevated native mode.

## Reference existing installations safely

An administrator can add `external_projects` to the fixed server policy:

```json
"external_projects": {
  "existing-app": {
    "operators": ["alice"],
    "app": { "kind": "service", "unit": "existing-app.service" },
    "directory": "/srv/existing-app/current",
    "databases": ["existing_app"]
  }
}
```

For a static site use `"app": {"kind":"static"}`. These references appear only to
the declared operators in `list`; `status` queries the configured service's activity
or reports `static`. Paths and database names are display-only metadata: no application
files or credentials are read, no SQL is executed, and database connectivity/health is
not claimed. `status` reports `management: external`, `operations: ["status"]` and
does not issue a native revision. Registration, publication, environment, restart and
database operations for these names are refused. Existing project tools/CI continue
to own those operations; this is not a migration or database adoption.

References cannot collide with native records/policies. Do not manufacture native
records or rerun `register` to import a running installation. Updating this policy is
administrative and does not require `--init`, a daemon restart, or application restarts.

## Exercise the CLI

Configure an `operator` target in a private client JSON file with a verified host key and
operator identity. Keep the project's **separate** deployment private key outside Git.
All files below containing environment values belong outside the repository too.
The commands assume an HTTP project named `website`, such as
`examples/demo-python/cais.json` with its name changed; a static project has no
environment and no restart.

```sh
cais plan --file cais.json --target operator --config client.json --json > plan.json
cais register --file cais.json --plan plan.json --deploy-public-key deploy.pub --target operator --config client.json --json
cais status website --target operator --config client.json --json > status.json
cais env-set website --values private-values.json --expected status.json --target operator --config client.json --json
cais package --file cais.json --output website.tar.gz --json
```

Add a second target for the returned `deploy_user`, with the **deployment** identity.
It can only publish and inspect that project; it cannot change environment or restart it.
Its authorized key has a fixed server command and disallows forwarding/PTY. The broker
rejects publication through the operator identity. Refresh status after each mutation:

```sh
cais status website --target operator --config client.json --json > status.json
cais deploy --file cais.json --artifact website.tar.gz --expected status.json --target website-deploy --config client.json --json
cais status website --target operator --config client.json --json > status.json
cais restart website --expected status.json --target operator --config client.json --json
```

`private-values.json` is an object of string values. `env-set` replaces the app environment,
does not print values, rejects multiline values, and reserves `PORT` and `APP_DATA_DIR`.
The stored file is `root:<runtime-group> 0640` in a `0750` project config directory.
Configuration cannot contain environment values or private keys. Node/Python dependencies
must already be included for Linux or installed administratively; Cais never runs package
install hooks as root. Binary executability comes from `artifact.executables`, including
when packages originate on Windows.
Configured interpreters must have administrative ownership/permissions. Their resolved
executables and parents must be root-owned and non-writable by others. Units pin the
trusted canonical executable path, so later changes to intermediate symlinks cannot
redirect an existing unit to operator code. Distribution-managed symlinks are supported.
Deploy and restart regenerate the managed unit when its runtime or administrative limits
change, then reload systemd. Do not customize generated units by editing them in place.

## State and failure semantics

A saved plan/status contains the installation identity, current policy hash and record
revision. Mutations check these again under a nonblocking project lock. A stale revision
is a conflict, never a retry. An accepted request ID is only a correlation value.
The reported lock state is an advisory kernel snapshot; it is not proof of execution or
success. Linux ext4 was exercised; lock observation on overlay/NFS/btrfs is unproved.

Upload uses a framed declaration, a ready response, exactly the declared number of binary
bytes, then a final framed result. Checksums, extraction limits and paths are validated
in inactive root-owned staging before stopping a service or changing publish paths.
Packages are deterministic, refuse secrets/symlinks/special files/case collisions, and
do not include preserved paths. GNU long names are read only after their declared payload
is bounded to 241 bytes and validated as a portable publish path. Other extensions,
including PAX and sparse files, are rejected. Active code is `root:<runtime-group>` with `0640/0750` modes and private
project traversal; other local runtimes cannot read it. The runtime can write only
its own data directory through its unit's filesystem restrictions. This is not a complete
sandbox for hostile application code.

Entries in `data.preserve` are **directories** that survive publication. Store persistent
files beneath them. Duplicate, nested and case-colliding paths are rejected before any
account is created. The exact root entry `.env` is a special file link to the managed
environment file. Prefer the process environment; dotenv parsers may interpret expansion
and quoting differently from systemd's canonical EnvironmentFile. Removing a project's
publish roots is not atomic across all roots. No application rollback is promised.
Operations checkpoint progress and result; status exposes unresolved interrupted work
and lock state. Interrupted/unknown operations require inspection before another mutation.
Transport failure after a mutating request was submitted reports `unknown_outcome` (exit 8).
Never automatically repeat a mutation to resolve it.

Connection/hello uses the client profile's `timeout_seconds`. For native mutations, Hello
declares separate upload and execution budgets, and the client waits for those budgets
plus five seconds for framing/exit. Defaults are 120 seconds upload and 180 execution;
administrative bounds are 1–600 and 10–1800 seconds respectively. Commands and artifact
processing use the remaining execution budget; health checks also stop at that deadline.
This does not turn an unresponsive operating system or disk into a confirmed result.

## Administrative recovery

Recovery is outside the no-argument operator/deploy sudo rule. An administrator first
inspects status, the service and retained files, and obtains a fresh `expected.revision`.
For a completed registration with an interrupted operation:

```sh
sudo /usr/local/libexec/cais/cais-broker --resolve website REVISION --acknowledge-inspected
```

This updates only the operation record. It marks the operation `resolved`, records who
inspected it, and keeps an interrupted deployment's outcome `unknown`. It does not repeat
commands, change application files or claim deployment success. Another mutation requires
the new revision. A stale revision, busy project or incomplete registration is refused.

For a **failed/incomplete registration**, inspect the record and the configured host roots.
Disable any generated unit; quarantine its unit, app/config/data directories and deploy
home in an administrator-only directory, preserving ownership and bytes. Remove only the
generated deployment sudo rule and the two generated accounts/groups; account removal
must not remove their home/data directories. Retain the quarantine and backups. Confirm
that the original managed paths, unit, accounts/groups and deployment sudo rule are absent.
Then archive the failed record with its fresh revision:

```sh
sudo /usr/local/libexec/cais/cais-broker --forget-failed-registration website REVISION --acknowledge-inspected
```

The command refuses while any listed resource remains, archives the record privately and
releases the name. It does not delete application data or perform cleanup for the admin.
A subsequent registration creates fresh resources and never adopts quarantined data.
Do not edit registry JSON by hand to skip these checks.

`busy`/`conflict` exit 6; `operation_failed` exit 7; `unknown_outcome` exit 8.
Administrative command errors contain fixed
diagnostics, never child stderr. A healthy deployment requires HTTP 200 on the configured
loopback health endpoint, and every listener on that port must belong to the project's
runtime account: an answer from another local process is refused. Restart also verifies that endpoint; static publication checks
the public directory, not HTTP health.

Reverse-proxy routes and backup registration are optional and described in
[INTEGRATIONS.md](INTEGRATIONS.md); without their host settings, projects that declare
`exposure` or `data.backup` are refused. PostgreSQL provisioning/private export and
unprivileged psql/tunneling are described in [POSTGRES.md](POSTGRES.md).
Project metadata and the catalog are described in [CATALOG.md](CATALOG.md).
Agents can use these operations through the local MCP server in [MCP.md](MCP.md).

## Fault journey

`tools/verify_integrations.py` (see [INTEGRATIONS.md](INTEGRATIONS.md#verification))
ends with faults injected against a real server in a disposable container:

* Two clients using the same revision: exactly one succeeds, the other gets exit 6 and
  leaves nothing to resolve.
* A project lock held by another operation: `status` reports it, a mutation is refused
  as `busy`, and works with a fresh revision once the lock is released.
* A deployment whose application never becomes healthy: `operation_failed` (exit 7),
  recorded as failed, no inspection required, and a corrected artifact deploys normally.
* The broker killed in the middle of a deployment: the client reports `unknown_outcome`
  (exit 8) once and does not retry; `status` shows the operation in progress and
  requiring inspection; further mutations, including the same deployment, are refused;
  the operator's sudo rule cannot run the recovery command; after the administrator's
  `--resolve`, the deployment is recorded as unknown and work resumes.
* A plan and a status saved before the host policy changed are refused; fresh ones work.

Not yet
injected: a proxy reload that times out, a full disk, and a lost connection while the
server keeps running.

## Disposable verification

`tools/verify_integrations.py` builds a disposable Debian container with systemd and
OpenSSH, installs the Linux binaries there and runs the whole journey above as an
unprivileged account. It never accepts a remote hostname; removing the container is its
cleanup boundary.
