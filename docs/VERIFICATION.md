# Verification

How to run the checks that CI runs, and the journeys against disposable local fixtures.
Never point a verification tool at a machine you use.

```sh
cargo test --workspace --locked
python tools/export_schemas.py --client target/debug/cais --check
```

`python3 tools/verify_client.py` runs the client against a private sshd on the current
machine, without Docker or root: host-key trust, key permissions, adversarial peers,
private exports and an MCP call. CI runs it on Linux against the planning server and on
macOS against a protocol peer, since the server itself runs only on Linux.

Tests also exercise OpenSSH's effective configuration using `ssh -G`. For Linux Docker
tests, build `docker build -t cais-rust-test:local -f tests/runner/Dockerfile .` and use
that image with the source mounted at `/work`, a Cargo cache volume, and a separate
target directory such as `target/linux`.

On Windows use `target/debug/cais.exe`. The SSH journey uses a real local Docker sshd,
real CLI, and Linux server with synthetic keys, including denials, host-key mismatch,
bad peers, deadline, spoofed environment, and writable policy rejection. Build a Linux
server **and client** with Rust locally or in `rust:1.98-slim` (keep its target directory
separate). The helper requires `target/linux/debug/cais-server` and `target/linux/debug/cais`:

```sh
python tools/verify_ssh.py --client target/debug/cais.exe --server target/linux/debug/cais-server --report .local/verification/windows-ssh.json
```

The test image is defined in `tests/ssh/Dockerfile`; Docker and Python 3.9+ are needed.
The helper generates synthetic keys in a temporary directory and removes its own
container in `finally`. It never uses a production SSH alias, key or credential.

The journeys for the optional integrations are described in
[INTEGRATIONS.md](INTEGRATIONS.md#verification), and the native and PostgreSQL ones in
[NATIVE.md](NATIVE.md#disposable-verification) and [POSTGRES.md](POSTGRES.md#verification).
