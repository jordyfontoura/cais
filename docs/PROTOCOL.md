# Control protocol 1

One SSH process handles one request. No PTY or arbitrary shell command is accepted.
Planning-only installations support read operations. Native installations additionally
support the fixed application operations below; archives use a bounded binary phase.

1. Server writes the 8 bytes `43 41 49 53 00 00 00 01` (CAIS + version marker).
2. Server writes `Hello`: supported protocol versions, build version, actual capabilities.
3. Client selects a supported version and writes one `Request`.
4. Server writes one final `Response` and exits. Client checks response version, request ID
   and successful SSH exit. Missing/invalid result is never inferred as success.

Every message is UTF-8 JSON preceded by a four-byte unsigned big-endian byte length,
between 1 and 131,072 bytes inclusive. A file loaded as project/client/server configuration
has a separate 65,536-byte limit. Unknown fields and operations are errors. The client
has an overall deadline (1–120 seconds configured in its profile).

```json
{"protocol_version":1,"request_id":"example-1","operation":{"name":"list"}}
```

```json
{"protocol_version":1,"request_id":"example-1","result":{"outcome":"success","data":["example"]}}
```

```json
{"protocol_version":1,"request_id":"example-1","result":{"outcome":"error","error":{"code":"not_authorized","message":"Project is unavailable to this identity."}}}
```

Foundation operations: `capabilities`, `list`, and `plan` with a `project` configuration.
Native operations: `status`, `register`, `environment`, `restart` and `deploy`.
`metadata` replaces a project's presentation metadata; see [CATALOG.md](CATALOG.md).
Optional integration operations, advertised in `capabilities.operations` only when the host
configures them: `proxy_apply`, `proxy_remove` and `backup_register`, each with a `project`
and an `expected` revision. See [INTEGRATIONS.md](INTEGRATIONS.md).
Administratively declared `external_projects` also appear in `list`. Their `status`
has `management: "external"`, `operations: ["status"]`, display-only directory/database
references and no native revision. All mutating/database operations on these references
return `unsupported`; no application files, credentials or SQL are accessed.
PostgreSQL installations also accept `database_connection` with `project` (authorized
nonsecret socket/role/database metadata), `database_create` and `database_reconcile` with
`project` and `expected`, and `database_credentials` with `project`. These require
project database authorization and an operator identity. In the capabilities,
`deployment` is true in native mode, `proxy_management` when the host has proxy
settings and `database_management` when it has PostgreSQL settings. `observations` and
`mcp` are reserved and always false: the MCP server is part of the client.
Mutations include an `expected` snapshot with `instance`, `policy_sha256` and `revision`.
Registration also includes project configuration and a deployment **public** key;
environment accepts a bounded object of values but never returns them.
There is no caller/username field. Identity comes from the SSH OS account; in native
mode the fixed sudo broker derives it from sudo's UID/user pair and verifies the lookup.
The root policy and binaries cannot be selected through the request.
Malformed requests use a fixed
`invalid` identifier if no valid request ID can be safely echoed. Error messages are from
a closed catalog, not forwarded parser, SSH, policy-path or command error text.

Client stdout for `--json` is a separate presentation envelope with `schema_version: 1`,
`outcome` and `data`/`error`; it is not the raw wire format. Error codes and exit values
are documented in README. Raw JSON Schema export and help/version are special cases.

## Artifact upload

`deploy` declares `project`, `expected`, `compressed_bytes`, lowercase `sha256` and the
normalized `configuration_sha256`. Only that project's restricted deployment identity
can upload. After authorization, revision, limits and manifest checks, the broker sends
a response with `result:{"outcome":"upload_ready","compressed_bytes":N}`. The client
checks version/ID/size, writes exactly N archive bytes and closes stdin. The server then
returns the normal final response. An early error has no binary phase. Extra responses
or bytes after the final response are protocol errors. Native Hello additionally declares
optional `execution_limits:{upload_seconds,execution_seconds}`. Client connection/hello
keeps the target deadline; a native mutation gets the declared upload+execution budgets
plus five seconds for final framing/exit. Upload defaults to 120 seconds and execution
to 180; accepted bounds are 1–600 and 10–1800 respectively. The server limits command,
health and artifact processing to the remaining execution budget. Receiving ready does
not mean publication occurred. No request ID is an exactly-once execution token.

The client reports an unknown mutation outcome when a submitted mutation loses its
confirmed final result. A request too large to send is refused before submission. Inspect status before retrying. A normal final server refusal
retains its specific code. No raw child stderr or environment is forwarded.

## Private file download

`database_credentials` first returns either a normal error or a response whose result
is `{"outcome":"private_file_ready","bytes":N}` (1–65536 bytes). After checking its
version and request ID, the client reads exactly N binary bytes into a private temporary
file, then requires a normal final success response, EOF and successful SSH exit. Only
then is the file published without overwriting. No secret is part of a JSON result or
error. An incomplete or malformed exchange discards the temporary file and removes the new
directory; a client killed during the download can leave a private temporary file
there. This operation
has no server-side mutation and uses the target read deadline.

## Unprivileged database sessions

The fixed server `--db-psql PROJECT` human entrypoint is outside the framed agent API.
It retrieves credentials through authorized broker RPC and runs psql as the SSH login;
no root process or JSON terminal handles interactive SQL.
Its passfile is anonymous/unlinked, explicitly chmodded 0600 before writing any secret,
and inherited by descriptor through procfs; normal query interrupts
are handled by psql without terminating the parent. Session failures preserve the shared
Cais exit-code classes, including code 3 for authorization denial.

`--db-hold PROJECT` is a bounded unprivileged lifetime lease for one explicitly configured
SSH forward. It reauthorizes `database_connection`, writes the eight-byte `CAISDB01`
readiness preamble, then one framed `DatabaseConnection` (schema version 1), and waits
for stdin EOF or its administrative session deadline. The client compares that metadata
with its initial authorized snapshot before announcing readiness. No secrets, application
bytes or further control requests travel over this lease. The database connection itself
uses OpenSSH's separate local-TCP-to-remote-Unix-socket forwarding channel.
A private local watchdog is the owner of that OpenSSH process. CLI EOF/death and the
watchdog deadline explicitly terminate OpenSSH; remote command EOF alone is insufficient
when forwarded channels are active. The watchdog accepts only a bounded typed database
tunnel launch, never arbitrary commands. It has no elevated privileges or public tool API.

The protocol can still change before 1.0. After that, changing its wire contract
requires a deliberate migration. Operator and deployment identities remain separate.
