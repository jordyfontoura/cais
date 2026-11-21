# Security policy

Cais is a pre-release and has had no external security audit. Its server side
includes a broker that runs as root through sudo and creates accounts, systemd units and
files. Evaluate it on a disposable machine before trusting it with anything important.

## Reporting a vulnerability

Report privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue or pull request for a suspected
vulnerability, and do not include real credentials, keys, hostnames or dumps in a report;
a synthetic reproduction is enough.

Useful details: the Cais version or commit, client and server operating systems, the
host policy with names replaced, the exact command and its JSON result, and what you
expected instead.

This is a volunteer project without a response-time commitment. You should get an
acknowledgement, and a fix or an explanation will be coordinated with you before any
public disclosure.

## Supported versions

Only the latest release and the `main` branch receive fixes.

## What counts as a vulnerability

The security boundary Cais is meant to enforce:

* The operating-system identity of the SSH login decides what a caller may do. Anything
  a client sends, including claimed identities and environment variables, grants nothing.
* An operator can act only on projects the root-owned host policy delegates to that
  operator. A deployment identity can only publish and inspect its own project.
* Operator, deployment and runtime accounts cannot replace or reconfigure the server,
  the broker or the host policy.
* An application runtime cannot read another project's code, environment or data, and
  can write only to its own data directories.
* Secrets and credentials never appear in JSON results, diagnostics or logs, and are
  written only to files with private ownership and permissions.
* Artifacts cannot write outside their project, plant links or special files, or change
  what runs with elevated privileges.
* The client never trusts an unverified host key and never forwards agents or ports for
  a control session.

Reports that break any of these are in scope, as are memory-safety or parsing flaws
reachable from the wire protocol or from an artifact.

## Known limits

These are documented behaviour, not vulnerabilities:

* The administrator who installs Cais, and anyone with general root or sudo access, is
  fully trusted.
* The runtime restrictions are not a complete sandbox for hostile application code.
* An operator-owned policy in the unprivileged planning mode does not protect anything
  from that same operator.
* A request ID is not an exactly-once guarantee, and an interrupted mutation reports an
  unknown outcome rather than a result.
* Application ports are loopback ports, not private ones: any local account can connect
  to them, and an application that listens on every interface is reachable unless a
  firewall blocks the port range. A deployment or restart is confirmed only when the
  project's own runtime account holds the port.
* Any identity admitted to the server can learn whether a project name is registered.
* A delegation removed from the policy stops new operations at once. What was already
  done stays: a published route, a created database, a registered manifest.
* Backup manifest paths point inside directories the application can write. A backup
  tool must not follow links found there.
