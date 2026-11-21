# PostgreSQL operations

Optional: project-authorized database and role creation, verification-only
reconciliation, private credential export and unprivileged psql and tunnel sessions over
SSH. The `database_management` capability is true when the host has PostgreSQL settings.

## Administrator configuration

PostgreSQL 16+ must already be installed locally. Cais does not install a cluster or adopt
existing databases/roles. Set `host.postgres` in the root policy, for example:

```json
{"psql":"/usr/bin/psql","os_user":"postgres","socket_directory":"/var/run/postgresql","port":5432,"admin_database":"postgres","hba_directory":"/etc/cais/postgres-hba","role_prefix":"cais_","connection_limit":5}
```

Administrative provisioning requires util-linux `setpriv`; it directly executes psql
after dropping UID, GID and supplementary groups. The socket directory must be protected
from unrelated users: only root/PostgreSQL may own it, and any writable group must be
the PostgreSQL group. The actual Unix socket peer UID is checked through the kernel.

Grant `database:true` explicitly in the project's administrative policy or the operator's
delegated creation role. It defaults to false.
The delegated creation permission is captured on the registered project; sharing it with
another operator does not add database permission. An explicit administrative project
policy can subsequently grant or remove it. Removing the permission from the policy
takes effect at the next request.

Run the administrative broker `--init` to
create an installation-bound HBA directory; populated foreign directories are refused.
As a separate administrative step, put this as the **first active directive** in the
cluster's main `pg_hba.conf`, preserving all existing rules below it:

```text
include_dir /etc/cais/postgres-hba
```

Cais checks that position and HBA parser errors before provisioning. It does not edit
the main HBA file. Rules are evaluated in order, and the rules view describes disk
contents rather than the last loaded state; actual own-database and cross-database
authentication probes are therefore part of verification.
[HBA configuration](https://www.postgresql.org/docs/17/auth-pg-hba-conf.html),
[rules view](https://www.postgresql.org/docs/17/view-pg-hba-file-rules.html).

## CLI journey

Register the app normally, then save its current status. Use the operator target:

```sh
cais status example --target operator --config client.json --json > status.json
cais db-create example --expected status.json --target operator --config client.json --json
cais status example --target operator --config client.json --json > status.json
```

Names derive from the configured prefix and project identity. Existing names, paths or
roles are conflicts. The database uses template0; the role owns that database, has no
global administrative privileges or memberships, and has a connection limit. PUBLIC
database privileges are revoked. Managed per-role HBA rules allow only its own database
over local connections and reject that role for other databases.

The generated password is random; administrative SQL receives a SCRAM verifier on stdin,
never a plaintext password in argv. The verifier can be supplied directly to PostgreSQL.
The provisioning session disables ordinary statement/error-statement, duration and
transaction-sampling logging before
sending the verifier. Administrators must separately configure extensions or external
SQL auditing to avoid recording password verifiers.
[CREATE ROLE](https://www.postgresql.org/docs/17/sql-createrole.html).

Credentials stay in a root-only private JSON file. A separate `database.env` is
`root:<runtime-group> 0640` and is loaded after the app environment on its next start.
No automatic restart occurs. `state:ready` means provisioning was verified, not continuous
database health. No password or verifier appears in status or normal JSON results.
Managed `DATABASE_URL` and `PG*` values override the same variables in the app environment.

## Export

Use a **new directory**, outside a Git worktree, with an existing parent:

```sh
cais db-config example --output-dir /private/new-export --target operator --config client.json --json
```

The response contains the file path, not its contents. The secret travels in a separate
bounded binary phase over SSH and is persisted only after the confirmed final result.
Unix uses directory 0700/file 0600. Windows replaces inherited and explicit default ACEs
before receiving bytes, then grants access only to the current user's SID. Existing
directories/files are never overwritten. Deployment identities cannot export credentials.

## Interrupted creation

No automatic retry, SQL rollback, DROP or adoption is performed. With a fresh status:

```sh
cais db-reconcile example --expected status.json --target operator --config client.json --json
```

This verifies existing objects, cluster identity, grants, authentication and isolation;
it only finishes managed environment/bookkeeping when verification succeeds. It never
repeats CREATE. Partial SQL resources require administrative inspection and completion
of the intended owned resources before reconciliation. Retain data/backups; do not clear
registry fields or drop databases blindly to bypass a conflict.

Reconciliation does not reload HBA. An administrator who repairs HBA must validate it and
reload the cluster before reconciliation. Managed fragments are published with final
ownership/mode already applied to their temporary file. For a fragment left unreadable,
restore `root:<postgres-group> 0640` administratively, check
`pg_hba_file_rules`, and reload; do not restart a shared cluster with an unreadable include.

If creation stopped before SQL objects existed, inspect the resources and preserve any
evidence. An administrator may quarantine the managed fragment and secret/environment
files **only after confirming no application/database data needs them**. With no role,
database, fragment, secret or `database.env` remaining, release just the checkpoint:

```sh
sudo /usr/local/libexec/cais/cais-broker --forget-empty-database PROJECT REVISION --acknowledge-inspected
```

The command is root-only, checks cluster identity and the current revision under both
locks, verifies absence of every resource and of any other administrative SQL session
tagged for this Cais installation, and never deletes anything. Killing psql does not
guarantee immediate cancellation of an already submitted server statement; session tags
keep recovery blocked while such a backend is active. It refuses a ready
database, stale revision or an unrelated interrupted mutation. A later `db-create` needs
a newly observed snapshot. If SQL objects exist, retain them and complete/inspect the
intended resources; this command cannot bypass their presence or adopt them.

## Human psql and SSH forwarding

```sh
cais db-psql example --target operator --config client.json
cais db-tunnel example --target operator --config client.json --local-port 15432 --duration-seconds 600 --json
```

`db-psql` runs the installed psql on the Linux host as the SSH login, never as root or
the app runtime. Only credential retrieval uses the fixed broker; that broker exits
before the session. psql uses the protected Unix socket, mandatory SCRAM and an anonymous
0600 passfile through an inherited `/proc/self/fd` descriptor.
There is no named password
file to remain after a process is killed. Ctrl-C cancels a query while the parent stays
alive; validated TERM is retained. A local psql installation is unnecessary. This is
a human SQL session with ordinary psql output; `--json` and an MCP terminal are refused.

`db-tunnel` binds only `127.0.0.1`, forwarding to the configured PostgreSQL **Unix socket**
over OpenSSH. It requires an explicit `user@hostname`, identity file and optional SSH
port in the profile. For this command, SSH aliases/ssh_config are intentionally unused
(`-F none`), preventing inherited additive forwards. All other host-key, identity and
no-agent/no-multiplexing protections still apply. Port zero chooses an available port;
an occupied port is refused. Credentials are not printed; use the private export in your
database client. Existing SQL authentication and database grants remain authoritative.

JSON mode for this long-lived command is NDJSON: one `tunnel_ready` event with the bound
port and nonsecret connection metadata, followed by `tunnel_closed` on its normal time
limit. Startup errors use the usual error envelope. Disconnection is not a closed-success
event. The helper reauthorizes before readiness; it runs as the SSH login. A private local
watchdog owns OpenSSH and explicitly terminates it on CLI stdin EOF or its deadline,
including active forwarded connections. The CLI confirms watchdog shutdown before its
normal closed event. This avoids relying on SSH command EOF to close active channels.
`host.limits.database_session_seconds` defaults to 3600 (10–86400); local forwarding
closes two seconds before that upper bound. This is an access check at session creation,
not continuous revocation of already established database sessions.

## Verification

`tools/verify_integrations.py` (see [INTEGRATIONS.md](INTEGRATIONS.md)) creates project
databases on a disposable host with PostgreSQL 17 and checks that each one exists in the
cluster, is reported as ready and is named in the backup manifest without credentials.
The SSH journey in `tools/verify_ssh.py` covers malformed and truncated private
downloads and confirms that no file is published after an error.

Not exercised yet: a crash at each SQL and HBA boundary on a real host. Recovery from
those states is implemented as described above and tested with synthetic checkpoints.
