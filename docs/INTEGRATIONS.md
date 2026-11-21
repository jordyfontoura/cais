# Reverse proxy and backups (optional)

Both integrations are optional and independent of each other. Without their host
settings the rest of Cais is unaffected, and a project that declares `exposure` or `data.backup`
is refused at planning. Cais does not install Caddy or a backup tool, manage DNS, or
edit any configuration it did not create.

## Reverse proxy with Caddy

### What the administrator sets up

1. Install Caddy as a systemd service, with its own account.
2. Add **one line** to the main Caddyfile, after any snippets it defines:

   ```
   import /etc/caddy/cais/*.caddy
   ```

3. Add `caddy` to `host` in `/etc/cais/server.json`. Every field has a default:

   ```json
   "caddy": {
     "executable": "/usr/bin/caddy",
     "caddyfile": "/etc/caddy/Caddyfile",
     "routes": "/etc/caddy/cais",
     "user": "caddy",
     "group": "caddy",
     "unit": "caddy.service"
   }
   ```

4. Run `sudo /usr/local/libexec/cais/cais-broker --init` again. It creates the routes
   directory with an installation marker, and refuses a populated directory it did not
   create.

Cais writes one file per project, `<routes>/<project>.caddy`, and nothing else. The main
Caddyfile is read by Caddy's own configuration check and is never modified. Global
options, TLS settings, other sites and snippets remain the administrator's.

### Access profiles

A project declares an `access_profile` by name. The host policy decides what it means:

```json
"access_profiles": {
  "open": { "kind": "public" },
  "members": { "kind": "private", "provider": "sso", "snippet": "sso_gate" }
}
```

For a private profile, `snippet` is the name of a snippet the administrator wrote in the
main Caddyfile, for example a `forward_auth` block for the identity provider in use:

```
(sso_gate) {
	forward_auth 127.0.0.1:9091 {
		uri /api/authz/forward-auth
		copy_headers Remote-User Remote-Groups
	}
}
```

Cais only writes `import sso_gate` into the route. It knows nothing about the provider,
and `provider` is a label. On a host with proxy settings, a project that uses a private
profile without a snippet is refused at planning and registration.
Operators can use only the profiles and hostnames the policy delegates to them
(`access_profiles`, and `domain_suffixes` or a project's `hosts`). A suffix covers its
subdomains only: never the suffix itself, and never a hostname the policy names in a
project's `hosts`. The delegation is checked again at every `proxy-apply`, so removing
it from the policy stops further publication. A route that is already published stays
until `proxy-remove`.

An HTTP application must listen on loopback only. A deployment or restart is refused
when the application listens on another address, and `status` reports `listener:
"exposed"` if it starts doing so later. Cais detects this; it does not confine the
application, so a host firewall on the configured port range is still good practice.

### Publishing a route

A project declares its public address in `cais.json`:

```json
"exposure": { "host": "app.example.org", "path": "/", "access_profile": "members" }
```

Registration records the intent and publishes nothing. The operator publishes or removes
the route explicitly, with a fresh status as for any mutation:

```sh
cais status website --target operator --config client.json --json > status.json
cais proxy-apply website --expected status.json --target operator --config client.json --json
cais proxy-remove website --expected status.json --target operator --config client.json --json
```

`path` is `/` for the whole hostname, or a prefix of plain segments such as `/docs` or
`/api/v1`, without a trailing slash. Under a prefix:

* The bare prefix redirects to `<prefix>/`, and every other path on that hostname gets a
  404. Nothing outside the prefix reaches the application.
* An HTTP application receives the full request path, prefix included, so its links,
  redirects and cookie paths keep working. Add `"strip_prefix": true` to `exposure` to
  remove the prefix first, for an application that expects to live at `/`; such an
  application must then generate its own links and cookie paths with the prefix.
* A static site is always served relative to the prefix.

An HTTP application is proxied to its loopback port. A static site is served from its
published directory, which is then readable by the proxy's group instead of the
project's runtime account; preserved data directories of a static site are not served.
Caddy obtains certificates as it does for any site: HTTPS needs DNS pointing at the host,
or the administrator's own TLS configuration.

`proxy-apply` writes the route file, runs `caddy validate` on the whole configuration
with the proxy's own account, and reloads the unit. If the configuration is rejected,
for example because the hostname collides with a hand-written site or the snippet does
not exist, the previous route file is restored, the running proxy is not reloaded and
the command fails with `operation_failed` (exit 7). Other routes keep working. If the
reload itself times out the result is `unknown_outcome` (exit 8): the file is left in
place for an administrator to inspect, and nothing is retried.

`status` reports `route.state` from the managed file: `published`, `absent`, or `stale`
when the file differs from what Cais would write, for example after a manual edit or a
policy change; `proxy-apply` writes it again. It is `unavailable` when the host has no
usable proxy settings for the project and `unknown` when the file cannot be read. The state describes the file. It does not
prove DNS, certificates or reachability from the internet.

A hostname belongs to one project, including when the project uses only a prefix of
it: two projects on one hostname would share cookies and browser storage, so this is
refused rather than left to each application. The deployment identity cannot change
routes.

## Backups

Cais does not copy data. It declares what must be covered, and reports what the backup
tool says about it.

### What the administrator sets up

Add `backup` to `host` in the policy, allow it for an operator or a project with
`"backup": true`, and run the broker `--init` again:

```json
"backup": {
  "manifests": "/var/lib/cais-backup",
  "check": "/usr/local/libexec/backup-check"
}
```

`check` is optional.

### The manifest

A project lists the preserved directories to back up in `data.backup`. The operator then
registers it:

```sh
cais backup-register website --expected status.json --target operator --config client.json --json
```

This writes `<manifests>/<project>.json`, readable by any backup tool:

```json
{
  "schema_version": 1,
  "project": "website",
  "instance": "7e04e069-485e-460f-bef9-1cbeae6e695f",
  "paths": ["/var/lib/cais-data/website/uploads"],
  "databases": [{ "name": "cais_website", "cluster": "18", "port": 5432 }]
}
```

`paths` are absolute directories. `databases` lists a database Cais created for the
project once it is ready; dumping it is the backup tool's job, and Cais never creates
or stores dumps. A manifest contains no credentials. A project with only a database can
be registered when backups are allowed for it. Register again after creating a database:
until then `status` shows the manifest as `stale`.

### Coverage

If `check` is configured, `status` runs it as `<check> <project>` with a short deadline.
It is an executable the administrator installs; it runs as root, with a fixed minimal
environment (`PATH` and `LANG` only) and no input. Its contract:

| Exit code | Meaning | Reported `backup.coverage` |
|---|---|---|
| 0 | The latest backup covered this manifest. It may print the Unix time of that backup. | `covered`, with `last_success_at` |
| 3 | No backup has covered this manifest. | `not_covered` |
| anything else, or a timeout | The provider could not answer. | `check_failed` |

Without a `check`, or when the manifest directory is unavailable, coverage is
`unverified`: Cais says what should be backed up and claims nothing more. A missing or stale manifest is always `not_covered`. A provider
failure is never reported as coverage.

## Verification

```sh
python tools/verify_integrations.py --linux-bin target/linux/release
```

The tool builds a disposable local container with systemd, OpenSSH, PostgreSQL and a
real Caddy, and runs the journey in `tests/integrations`. It needs Docker and the Linux
binaries, uses synthetic keys and removes its container. The journey covers:

* HTTPS for a private application and a public static site.
* A private route through `forward_auth`: the redirect to a login page on another
  hostname, the session cookie for the parent domain, the return to the application, the
  identity header copied from the provider and a client-supplied identity header being
  replaced. The provider is a small stand-in that speaks the forward-auth contract
  (`tests/integrations/authgate.py`); no real identity product is part of the tests.
* Path prefixes for static sites and applications, with and without stripping.
* Hostname collisions, policy denials and a route the proxy rejects.
* Drift, removal and republication, and an unchanged administrator Caddyfile.
* Manifest and coverage states, including a real PostgreSQL database created by Cais
  and a project that has only a database.
* The catalog, an MCP session, and the faults listed in
  [NATIVE.md](NATIVE.md#fault-journey).
