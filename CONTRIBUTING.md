# Contributing

Cais is a pre-release with a small scope on purpose. Issues and pull requests are welcome;
for anything larger than a fix, open an issue first so the design can be agreed before
you write code. The [roadmap](docs/ROADMAP.md) lists what is planned and what is out of
scope.

Report suspected vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Build and test

Requires Rust 1.88 or newer, Cargo and Python 3.11+. Remote commands need OpenSSH 8.5+.

```sh
cargo build --workspace --locked
cargo fmt --all --check
cargo test --workspace --locked
python tools/export_schemas.py --client target/debug/cais --check
```

`cais-server` and `cais-broker` work only when built on Linux; on other systems they
compile to stubs that say so. A Linux build depends on the glibc of the machine that
built it, so build on a system no newer than the host that will run it. From Windows
or macOS, build them in a container with the source mounted, as described in
[README.md](README.md#verification).

On Windows the client is `target/debug/cais.exe`. The files in `schemas/` are generated
from the Rust types: after changing a configuration type, regenerate them with
`tools/export_schemas.py` and commit the result.

The SSH and integration journeys need Docker and run only against disposable local
fixtures. The commands are in [README.md](README.md#verification) and
[docs/INTEGRATIONS.md](docs/INTEGRATIONS.md). Never point a
verification tool at a machine you use.

## Rules for changes

* **No secrets or real infrastructure in the repository.** No keys, tokens, environment
  files, dumps, real hostnames, IP addresses or usernames, in code, tests, examples,
  issues or commit messages. Examples use fictional names such as `alice` and
  `example.org`.
* **Identity comes from the operating system.** Do not add a field, flag or environment
  variable that lets a client state who it is or which policy applies.
* **No generic execution.** New operations are fixed and typed. Do not add a way to run
  an arbitrary command, load a privileged plugin or choose a remote path over the wire.
* **Optional providers stay optional.** The core must build and work without a reverse
  proxy, database, backup service or any particular consumer of its metadata.
* **Report what happened.** A mutation that may or may not have completed returns an
  unknown outcome. Do not add automatic retries or infer success.
* **Protocol and schema changes are versioned.** Unknown fields and versions are
  refused; describe the compatibility impact in the pull request.
* **Errors carry no input.** Diagnostics are fixed strings and never echo configuration
  values, peer stderr or file contents.

Add tests for the behaviour you change, including the refusal cases. A change to the
broker or to the Linux host code should come with a journey against a disposable fixture.

## Licensing

Contributions are accepted under the [Apache License 2.0](LICENSE), as stated in its
section 5. New dependencies must have a compatible license (CI checks them against
`deny.toml`) and be reflected in
[NOTICE](NOTICE) where it applies.
