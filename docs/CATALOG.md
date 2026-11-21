# Metadata and catalog (optional)

Dashboards, monitors and similar tools often need to know which projects exist on a
host, what to call them and where they live. The catalog is a single nonsecret JSON
file with that information. Cais writes it; anything may read it. Cais never calls a
consumer and works the same whether or not one exists.

## Project metadata

Metadata is presentation only. See `examples/metadata.json` and
`schemas/metadata.schema.json`:

```json
{
  "schema_version": 1,
  "title": "Example API",
  "description": "Internal service used by the example project.",
  "url": "https://api.example.org/",
  "labels": { "dashboard": true, "tier": "internal" }
}
```

| Field | Rule |
|---|---|
| `title` | Required, 1-80 characters. |
| `description` | Optional, at most 280 characters. |
| `url` | Optional HTTPS address without credentials, port, query or fragment. Its hostname must be the one the project declares in `exposure`. |
| `labels` | Optional, at most 16. Keys are identifiers; values are booleans or text of at most 120 characters. |

`labels` are hints for consumers, for example an opt-in that a particular dashboard
understands. Cais stores and publishes them and gives none of them a meaning. Metadata
cannot name a systemd unit, a path or a command: those come only from the host's own
records, so a project cannot point a consumer at something it does not own.

The operator sets metadata with a fresh status, like any mutation:

```sh
cais validate --kind metadata --file metadata.json --json
cais status website --target operator --config client.json --json > status.json
cais metadata-set website --file metadata.json --expected status.json --target operator --config client.json --json
```

The command replaces the previous metadata and is separate from deployment. It never
publishes an artifact or restarts a service, and a deployment never changes metadata. A
pipeline that deploys and then sets metadata should report the two results separately:
if the deployment succeeded and metadata failed, repeat only `metadata-set`. The
deployment identity cannot set metadata. `status` returns the stored metadata.

Metadata works without a catalog; it is then visible only through `status`.

## The catalog

Add `catalog` to `host` in `/etc/cais/server.json` and run the broker `--init` again:

```json
"catalog": { "directory": "/var/lib/cais-catalog", "group": "dashboards" }
```

Both fields are optional. With `group`, only root and that group can read the catalog;
without it, any local account can. Cais writes `<directory>/catalog.json`:

```json
{
  "schema_version": 1,
  "instance": "7e04e069-485e-460f-bef9-1cbeae6e695f",
  "generated_at": 1795210436,
  "projects": [
    {
      "project": "api",
      "management": "native",
      "kind": "http",
      "unit": "cais-app-6bbdf8ebd171.service",
      "port": 8200,
      "host": "api.example.org",
      "access_profile": "members",
      "metadata": { "schema_version": 1, "title": "Example API", "labels": { "dashboard": true } }
    },
    { "project": "legacy", "management": "external", "kind": "service", "unit": "legacy.service" }
  ]
}
```

| Field | Meaning |
|---|---|
| `management` | `native` for projects Cais registered, `external` for the policy's read-only references. |
| `kind` | `http` or `static` for native projects; `service` or `static` for external ones. |
| `unit`, `port` | The systemd unit and loopback port of an HTTP application. |
| `host`, `access_profile` | The declared exposure, whether or not its route is currently published. |
| `metadata` | What the operator set, if anything. |

The catalog describes intent and identity. It carries no health, deployment or route
state, no filesystem paths, no environment and no credentials; a consumer that wants
live state observes the unit or the address itself. Projects are sorted by name, and
only complete registrations are listed.

A consumer should check `schema_version`, ignore fields it does not know, treat a
missing or unreadable file as "no information" and never write to the directory.
`instance` changes only if the host is initialized again from scratch.

### When it is rewritten

The whole file is rebuilt, atomically, after a registration, after `metadata-set` and
on the broker `--init`. After editing `external_projects` in the policy, run `--init`
to publish the change. A registration does not fail because the catalog could not be
written; `status` then reports `catalog: stale`, and `metadata-set` or `--init`
rebuilds it. `catalog` in `status` is `current` when the file lists the project exactly
as Cais would write it, otherwise `stale`, `absent` or `unknown`.

## Verification

`tools/verify_integrations.py` covers the catalog after registration and metadata,
refusal of foreign addresses and of unit/path fields, the deployment identity, a stale
catalog and its rebuild. See [INTEGRATIONS.md](INTEGRATIONS.md#verification).
