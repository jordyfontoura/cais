# Quickstart

This walk-through installs Cais on a new Linux host, connects a client from Windows,
macOS or Linux and publishes the HTTP example. It needs administrator access to the
host once, for the installation. Do not follow it to adopt an existing installation:
Cais manages only what it creates.

Public URLs through Caddy and backup registration are optional and described in
[INTEGRATIONS.md](INTEGRATIONS.md), metadata and the catalog in [CATALOG.md](CATALOG.md),
and the MCP server for agents in [MCP.md](MCP.md).

## Get the binaries

Download the archive for each machine from the project's releases page and check it
against `SHA256SUMS` from the same release:

| Machine | Archive | Contains |
|---|---|---|
| Linux host (x86_64) | `cais-VERSION-linux-x86_64.tar.gz` | `bin/cais`, `bin/cais-server`, `bin/cais-broker` |
| Windows client (x86_64) | `cais-VERSION-windows-x86_64.zip` | `bin/cais.exe` |
| macOS client | `cais-VERSION-macos-arm64.tar.gz` or `-macos-x86_64.tar.gz` | `bin/cais` |

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

The checksum shows the download is intact. To check that an archive was built by this
repository's release workflow, verify its signed provenance with the GitHub CLI
(available for releases after 0.1.0-beta.1):

```sh
gh attestation verify cais-VERSION-linux-x86_64.tar.gz --repo jordyfontoura/cais
```

Every archive also carries this documentation, the examples and the schemas. The Linux
binaries need glibc 2.36 or newer (Debian 12, Ubuntu 24.04 and later). To build from
source instead, see [CONTRIBUTING.md](../CONTRIBUTING.md); the server and the broker
must be built on Linux, against a glibc no newer than the host's.

## Install on a new Linux host

Requirements:

* Linux x86_64 with systemd, a merged `/usr`, OpenSSH server and sudo. Exercised on
  Debian 13.
* These tools at these paths: `/usr/bin/sudo`, `/usr/sbin/visudo`, `/usr/sbin/useradd`,
  `/usr/sbin/nologin`, `/usr/bin/systemctl`, `/usr/bin/id`, `/usr/bin/getent`,
  `/usr/bin/chown`, `/usr/bin/env`, `/usr/bin/ssh-keygen` and `/usr/bin/setpriv`
  (util-linux).
* `sshd` using PAM, the default on Debian and Ubuntu. The deployment accounts Cais
  creates have no password, and an `sshd` with `UsePAM no` refuses such accounts.
* An interpreter for the applications you will run. The example uses a Python 3
  installed by the administrator. Node and Linux executables are supported too; no
  dependency is installed as root during a deploy.

Steps, as an administrator on the host, from the extracted archive:

1. Edit `examples/server-quickstart.json`: replace `alice` with an account that
   **already exists** and that you log in to over SSH, and adjust paths, ports and
   interpreters. The four data/state/configuration/apps directories must be empty or
   absent.
2. Install the executables and the policy:

```sh
sudo install -d -o root -g root -m 0755 /usr/local/libexec/cais /etc/cais
sudo install -o root -g root -m 0755 bin/cais-server /usr/local/bin/cais-server
sudo install -o root -g root -m 0755 bin/cais-broker /usr/local/libexec/cais/cais-broker
sudo install -o root -g root -m 0644 examples/server-quickstart.json /etc/cais/server.json
sudo /usr/local/libexec/cais/cais-broker --init
```

The broker installs a sudo rule only for its own fixed path, without arguments. The
server runs on demand over SSH; there is no daemon and no web administration interface.
Keep the configuration you used. Do not replace paths or files of another installation
to get around an initialization refusal.

3. Print the host's public key while you are on its console. You will need it on the
   client, and this is the moment you can trust it:

```sh
cat /etc/ssh/ssh_host_ed25519_key.pub
```

## Configure the client

Put `cais.exe` on the Windows PATH (with the native OpenSSH client enabled), or `cais`
on the macOS or Linux PATH. Then create a private directory outside any repository,
for example `~/cais-private`, and work inside it:

1. Create two keys without sharing them: one for you as operator, one for deployments.

```sh
ssh-keygen -t ed25519 -f operator_key
ssh-keygen -t ed25519 -N "" -f deploy_key
```

   Accepted deployment key types are `ssh-ed25519`, `ssh-rsa` and
   `ecdsa-sha2-nistp256`.
2. Add the content of `operator_key.pub` to `~/.ssh/authorized_keys` of your account on
   the host.
3. Create `known_hosts` with one line: the host name exactly as you will write it in
   the configuration, followed by the public key printed on the host's console.

```text
server.example.org ssh-ed25519 AAAA...
```

   With a port other than 22 the name is written `[server.example.org]:2222`. A key
   fetched with `ssh-keyscan` alone is not verified. Cais never accepts an unknown host.
4. Copy `examples/client-quickstart.json` to `client.json` in this directory and set the
   host and the user. Relative paths are relative to that file.

```sh
cais capabilities --target operator --config client.json --json
cais list --target operator --config client.json --json
```

If these commands fail with a `transport` error, test the same host, user, key and
`known_hosts` with plain `ssh`: Cais reports fixed errors and does not forward SSH
diagnostics. A common cause is a private key readable by other accounts, which OpenSSH
ignores. On Windows restrict it to your user, for example with
`icacls operator_key /inheritance:r /grant:r "%USERNAME%:F"`.

## Publish the HTTP example

Copy `examples/demo-python` from the archive next to `client.json`, then:

```sh
cais plan --file demo-python/cais.json --target operator --config client.json --json > plan.json
cais register --file demo-python/cais.json --plan plan.json --deploy-public-key deploy_key.pub --target operator --config client.json --json
cais package --file demo-python/cais.json --output hello-python.tar.gz --json
```

Registration returns `deploy_user`. Add a second target named `deploy` to `client.json`:
the same host and `known_hosts`, the user exactly as returned, and `identity_file` set
to `./deploy_key`. Then:

```sh
cais status hello-python --target operator --config client.json --json > status.json
cais deploy --file demo-python/cais.json --artifact hello-python.tar.gz --expected status.json --target deploy --config client.json --json
cais status hello-python --target operator --config client.json --json
```

The application listens on loopback, on the port returned by status. A deployment is
confirmed by a 200 answer on its health path; a public URL needs the optional proxy
integration. Read the status again before each mutation. The operator sets the
environment and restarts; only the deployment identity publishes. See
[NATIVE.md](NATIVE.md) for environment, persistence and recovery.

## Optional PostgreSQL

With PostgreSQL 16+ already installed, enable `host.postgres` and the `database: true`
permission in the administrative policy. Preparing the HBA is an explicit administrative
step; follow [POSTGRES.md](POSTGRES.md). Then:

```sh
cais status hello-python --target operator --config client.json --json > status.json
cais db-create hello-python --expected status.json --target operator --config client.json --json
cais db-config hello-python --output-dir ./database-export --target operator --config client.json --json
cais db-psql hello-python --target operator --config client.json
cais db-tunnel hello-python --target operator --config client.json --duration-seconds 600 --json
```

Credentials are never returned in JSON. `db-psql` is a human session without a JSON
mode. The tunnel reports its local port in an event and has a bounded duration.

## When something is interrupted

A result with exit code 8 (`unknown_outcome`) means the operation may or may not have
happened. Read the status and follow the recovery section of [NATIVE.md](NATIVE.md)
before repeating anything. Cais never retries a mutation, promises no application
rollback, and reports backup coverage only when the backup integration is configured.
