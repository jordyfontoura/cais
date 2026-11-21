"""Exercise the client on this operating system over the system's real OpenSSH.

Starts a private sshd as the current user on a loopback port, in a temporary directory
with synthetic keys, and points the client at the planning server and at adversarial
protocol peers. Needs no Docker and no root, so it runs on macOS as well as Linux.
It proves the client side: transport, host-key trust, error handling and private files.
The Linux broker is exercised by the other journeys.
"""
import argparse
import getpass
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--client", type=Path, default=ROOT / "target/debug/cais")
parser.add_argument("--server", type=Path, default=ROOT / "target/debug/cais-server")
parser.add_argument("--sshd", default=shutil.which("sshd") or "/usr/sbin/sshd")
args = parser.parse_args()
CLIENT, SERVER = args.client.resolve(), args.server.resolve()
assert CLIENT.is_file() and SERVER.is_file(), "Build cais and cais-server first"
assert os.name == "posix", "This journey needs a Unix sshd; Windows is covered by tools/verify_ssh.py"
USER = getpass.getuser()
CANARY = "synthetic-peer-canary"
passed = 0


def check(label, condition, detail=None):
    global passed
    if not condition:
        raise SystemExit(f"FAIL: {label}: {json.dumps(detail, default=str)[:800]}")
    passed += 1
    print(f"PASS: {label}")


def keygen(path):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)


# The planning server refuses a policy below a world-writable directory such as /tmp,
# so the fixture lives in the home directory.
with tempfile.TemporaryDirectory(prefix=".cais-client-", dir=Path.home()) as temporary:
    case = Path(temporary).resolve()
    binaries = case / "bin"
    binaries.mkdir()
    keygen(case / "host_key")
    keygen(case / "client_key")
    keygen(case / "other_host_key")
    shutil.copy(case / "client_key.pub", case / "authorized_keys")
    os.chmod(case / "authorized_keys", 0o600)

    policy = case / "policy" / "server.json"
    policy.parent.mkdir(mode=0o755)
    policy.write_text(json.dumps({"schema_version": 1, "projects": {
        "example": {"operators": [USER], "hosts": ["api.example.org"], "access_profiles": ["private"]}},
        "access_profiles": {"private": {"kind": "private", "provider": "sso"}}}), encoding="utf-8")
    os.chmod(policy, 0o644)
    server = binaries / "cais-planning"
    server.write_text(f"#!/bin/sh\nexec '{SERVER}' --config '{policy}'\n", encoding="utf-8")
    os.chmod(server, 0o755)
    peer_source = (ROOT / "tests/ssh/fake_peer.py").read_text(encoding="utf-8")
    peer_source = peer_source.replace("#!/usr/bin/python3", "#!" + sys.executable, 1)
    modes = ["polluted", "incompatible", "truncated", "mismatch", "failed-exit", "timeout", "trailing",
             "private-ok", "private-truncated", "private-mismatch", "private-error", "private-failed-exit",
             "ok"]
    for mode in modes:
        peer = binaries / f"cais-fake-{mode}"
        peer.write_text(peer_source, encoding="utf-8")
        os.chmod(peer, 0o755)

    # The server itself runs only on Linux. Elsewhere a well-behaved protocol peer stands
    # in for it, which still exercises this system's OpenSSH and the whole client.
    REAL_SERVER = sys.platform == "linux"
    LISTED = ["example"] if REAL_SERVER else []
    if not REAL_SERVER:
        server = binaries / "cais-fake-ok"
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    (case / "sshd_config").write_text(f"""Port {port}
ListenAddress 127.0.0.1
HostKey {case / 'host_key'}
AuthorizedKeysFile {case / 'authorized_keys'}
PidFile {case / 'sshd.pid'}
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTTY no
LogLevel ERROR
""", encoding="utf-8")
    daemon = subprocess.Popen([args.sshd, "-D", "-e", "-f", str(case / "sshd_config")],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            with socket.socket() as attempt:
                if attempt.connect_ex(("127.0.0.1", port)) == 0:
                    break
            if daemon.poll() is not None:
                raise SystemExit("sshd did not start: " + daemon.stderr.read().decode(errors="replace")[:400])
            time.sleep(0.1)
        host_key = " ".join((case / "host_key.pub").read_text().split()[:2])
        other_key = " ".join((case / "other_host_key.pub").read_text().split()[:2])
        (case / "known_hosts").write_text(f"[127.0.0.1]:{port} {host_key}\n", encoding="utf-8")
        (case / "wrong_hosts").write_text(f"[127.0.0.1]:{port} {other_key}\n", encoding="utf-8")
        (case / "empty_hosts").write_text("", encoding="utf-8")
        config = case / "client.json"

        def configure(**changes):
            target = {"ssh": f"{USER}@127.0.0.1", "port": port, "server_path": str(server),
                      "known_hosts": "./known_hosts", "identity_file": "./client_key", "timeout_seconds": 10}
            target.update(changes)
            config.write_text(json.dumps({"schema_version": 1, "targets": {"fixture": target}}), encoding="utf-8")

        def cli(arguments, expected=0, remote=True):
            command = [str(CLIENT), *arguments]
            if remote:
                command += ["--target", "fixture", "--config", str(config)]
            result = subprocess.run(command + ["--json"], capture_output=True, text=True, timeout=60)
            check("exit code of " + arguments[0], result.returncode == expected,
                  [result.returncode, result.stdout[-300:], result.stderr[-300:]]) if result.returncode != expected else None
            assert CANARY not in result.stdout + result.stderr, "peer output leaked"
            assert result.stderr == "", "JSON mode wrote diagnostics to stderr"
            return json.loads(result.stdout)

        configure()
        first = subprocess.run([str(CLIENT), "list", "--target", "fixture", "--config", str(config), "--json"],
                               capture_output=True, text=True, timeout=60)
        if first.returncode != 0:
            # Synthetic keys and paths only: safe to print when the fixture itself is broken.
            raw = subprocess.run(["ssh", "-v", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                                  "-o", f"UserKnownHostsFile={case / 'known_hosts'}", "-i", str(case / "client_key"),
                                  "-p", str(port), f"{USER}@127.0.0.1", "echo reached"],
                                 capture_output=True, text=True, timeout=30)
            print("raw ssh:", raw.returncode, raw.stdout.strip(), " | ".join(raw.stderr.splitlines()[-25:]))
            local = subprocess.run([str(server)], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            print("server alone:", local.returncode, local.stdout[:40], local.stderr.decode(errors="replace")[-400:])
            daemon.terminate()
            print("sshd:", daemon.stderr.read().decode(errors="replace")[-1500:])
        check("the system OpenSSH reaches the server", cli(["list"])["data"] == LISTED)
        if REAL_SERVER:
            capabilities = cli(["capabilities"])["data"]
            check("server capabilities are read", "list" in capabilities["operations"], capabilities)
            plan = cli(["plan", "--file", str(ROOT / "examples/cais.json")])["data"]
            check("a plan round-trips a project configuration", plan["policy_checked"] is True, plan)

        configure(known_hosts="./wrong_hosts")
        check("a changed host key is refused", cli(["list"], expected=5)["error"]["code"] == "transport")
        configure(known_hosts="./empty_hosts")
        check("an unknown host is refused", cli(["list"], expected=5)["error"]["code"] == "transport")
        check("an unknown host key is never recorded", (case / "empty_hosts").read_text() == "")
        os.chmod(case / "client_key", 0o644)
        configure()
        check("a private key readable by others is not used", cli(["list"], expected=5)["error"]["code"] == "transport")
        os.chmod(case / "client_key", 0o600)
        check("the same key works once private again", cli(["list"])["data"] == LISTED)

        for mode, code, expected in [("polluted", "protocol", 5), ("incompatible", "incompatible_version", 4),
                                     ("truncated", "transport", 5), ("mismatch", "protocol", 5),
                                     ("failed-exit", "transport", 5), ("timeout", "timeout", 5),
                                     ("trailing", "protocol", 5)]:
            configure(server_path=str(binaries / f"cais-fake-{mode}"), timeout_seconds=1 if mode == "timeout" else 10)
            check(f"the {mode} peer is rejected", cli(["list"], expected=expected)["error"]["code"] == code)

        for mode, code, expected in [("ok", None, 0), ("truncated", "protocol", 5), ("mismatch", "protocol", 5),
                                     ("error", "not_authorized", 3), ("failed-exit", "transport", 5)]:
            configure(server_path=str(binaries / f"cais-fake-private-{mode}"))
            directory = case / f"export-{mode}"
            value = cli(["db-config", "example", "--output-dir", str(directory)], expected=expected)
            final = directory / "credentials.private.json"
            if expected == 0:
                check("a private export is written only for its owner",
                      final.read_bytes() == b"synthetic-private-payload"
                      and stat.S_IMODE(final.stat().st_mode) == 0o600
                      and stat.S_IMODE(directory.stat().st_mode) == 0o700,
                      [oct(final.stat().st_mode), oct(directory.stat().st_mode)])
            else:
                check(f"the {mode} private export leaves no file behind",
                      not directory.exists() and value["error"]["code"] == code, value)

        configure()
        session = subprocess.Popen([str(CLIENT), "mcp", "--config", str(config), "--root", str(case)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        session.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                        "params": {"name": "cais_list", "arguments": {"target": "fixture"}}}) + "\n")
        session.stdin.flush()
        answer = json.loads(session.stdout.readline())["result"]
        session.stdin.close()
        session.wait(timeout=10)
        check("the MCP server reaches the same target", answer["isError"] is False
              and answer["structuredContent"]["data"] == LISTED, answer)
    finally:
        daemon.terminate()
        daemon.wait(timeout=10)
print(f"ALL PASS ({passed} checks on {sys.platform}, {'real planning server' if REAL_SERVER else 'protocol peer'})")
