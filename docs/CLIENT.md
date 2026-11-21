# Client, targets and the planning server

This page describes how the `cais` client reaches a host and what the server does when
no native `host` section is configured. To install a host that runs applications, follow
the [quickstart](QUICKSTART.md); native application management is described in
[NATIVE.md](NATIVE.md).

## Client behaviour

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
application management uses the separate root broker described in [NATIVE.md](NATIVE.md).

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
