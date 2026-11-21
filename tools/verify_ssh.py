"""Exercise a real Cais CLI -> OpenSSH -> Linux server journey in disposable Docker.

Synthetic keys only. Never connects to a user's configured SSH targets.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import uuid
from source_manifest import collect_source_manifest

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--client", type=Path, required=True)
parser.add_argument("--server", type=Path, required=True)
parser.add_argument("--linux-client", type=Path, default=ROOT / "target/linux/debug/cais")
parser.add_argument("--report", type=Path)
args = parser.parse_args()
CLIENT, SERVER = args.client.resolve(), args.server.resolve()
LINUX_CLIENT = args.linux_client.resolve()
assert CLIENT.is_file() and SERVER.is_file() and LINUX_CLIENT.is_file(), "Build native client and Linux binaries first"
source_before = collect_source_manifest()
binary_hashes_before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (CLIENT, SERVER, LINUX_CLIENT)]

def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, timeout=kwargs.pop("timeout", 120), **kwargs)

passed = []
def check(name, condition):
    assert condition, name
    passed.append(name)
    print(f"PASS {name}", flush=True)

def cli(command, config=None, expected=0):
    argv = [str(CLIENT), *command, "--json"]
    if config is not None:
        argv += ["--target", "fixture", "--config", str(config)]
    result = subprocess.run(argv, capture_output=True, timeout=25)
    assert result.returncode == expected, f"Unexpected exit for {command[0]}: {result.returncode}"
    assert not result.stderr, "JSON mode wrote to stderr"
    value = json.loads(result.stdout)
    assert value["outcome"] == ("success" if expected == 0 else "error")
    assert b"synthetic-peer-canary" not in result.stdout + result.stderr
    return value

with tempfile.TemporaryDirectory(prefix="cais SSH ") as temporary:
    case = Path(temporary)
    key = case / "client_key"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    policy = json.loads((ROOT / "examples/server.json").read_text())
    (case / "server.json").write_text(json.dumps(policy), encoding="utf-8")
    shutil.copy(ROOT / "examples/cais.json", case / "project.json")
    (case / "ssh_config").write_text("Host *\n  LogLevel ERROR\n", encoding="utf-8")
    shutil.copytree(ROOT / "schemas", case / "schemas")
    run(["docker", "build", "-t", "cais-ssh-test:local", "-f", str(ROOT / "tests/ssh/Dockerfile"), str(ROOT)], timeout=300)
    name = "cais-ssh-" + uuid.uuid4().hex[:12]
    container = run(["docker", "run", "--rm", "-d", "--name", name,
                     "-p", "127.0.0.1::22",
                     "--mount", f"type=bind,source={case},target=/case,readonly",
                     "--mount", f"type=bind,source={SERVER},target=/build/cais-server,readonly",
                     "--mount", f"type=bind,source={LINUX_CLIENT},target=/build/cais,readonly",
                     "cais-ssh-test:local"]).stdout.decode().strip()
    try:
        port = int(run(["docker", "port", container, "22/tcp"]).stdout.decode().strip().rsplit(":", 1)[1])
        for attempt in range(60):
            ready = subprocess.run(["docker", "exec", container, "test", "-f", "/run/sshd-test.pid"], capture_output=True)
            if ready.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("Synthetic SSH server did not start")
        host_key = run(["docker", "exec", container, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"]).stdout.decode().split()
        known = case / "known hosts"
        known.write_text(f"[127.0.0.1]:{port} {host_key[0]} {host_key[1]}\n127.0.0.1 {host_key[0]} {host_key[1]}\n", encoding="utf-8")
        profile = {"schema_version": 1, "targets": {"fixture": {
            "ssh": "operator@127.0.0.1", "port": port,
            "server_path": "/usr/local/bin/cais-server", "known_hosts": known.name,
            "identity_file": key.name, "ssh_config": "ssh_config", "timeout_seconds": 10}}}
        config = case / "client.json"
        def configure(**changes):
            profile["targets"]["fixture"].update(changes)
            config.write_text(json.dumps(profile), encoding="utf-8")
        configure()
        before = run(["docker", "exec", container, "sha256sum", "/etc/cais/server.json"]).stdout
        check("local configuration validation", cli(["validate", "--file", str(ROOT / "examples/cais.json")])["data"]["valid"])
        check("remote capabilities are honest", not cli(["capabilities"], config)["data"]["deployment"])
        check("project list uses authenticated identity", cli(["list"], config)["data"] == ["example", "website"])
        plan = cli(["plan", "--file", str(ROOT / "examples/cais.json")], config)["data"]
        check("plan is policy-checked and not executable", plan["policy_checked"] and not plan["execution_supported"] and plan["current_runtime_state"] == "not_observed")
        digest = cli(["plan", "--file", str(ROOT / "examples/cais.json")], config)["data"]["configuration_sha256"]
        check("repeated planning preserves intent digest", digest == plan["configuration_sha256"])
        configure(ssh="outsider@127.0.0.1")
        check("unauthorized projects are hidden", cli(["list"], config)["data"] == [])
        denied = cli(["plan", "--file", str(ROOT / "examples/cais.json")], config, expected=3)
        check("unauthorized plan is refused", denied["error"]["code"] == "not_authorized")
        configure(ssh="operator@127.0.0.1")
        altered = json.loads((ROOT / "examples/cais.json").read_text())
        altered["exposure"]["host"] = "other.example.org"
        changed = case / "changed.json"
        changed.write_text(json.dumps(altered), encoding="utf-8")
        check("undelegated host is refused", cli(["plan", "--file", str(changed)], config, expected=3)["error"]["code"] == "policy_denied")
        altered["secret-canary"] = "synthetic-peer-canary"
        changed.write_text(json.dumps(altered), encoding="utf-8")
        check("unknown fields are refused without echo", cli(["validate", "--file", str(changed)], expected=2)["error"]["code"] == "invalid_config")
        invalid_policy = json.loads(json.dumps(policy))
        invalid_policy["access_profiles"]["private"] = {"kind": "public", "provider": "sso"}
        (case / "invalid-policy.json").write_text(json.dumps(invalid_policy), encoding="utf-8")
        check("public profile cannot silently ignore a provider", cli(["validate", "--kind", "server", "--file", str(case / "invalid-policy.json")], expected=2)["error"]["code"] == "invalid_config")
        for mode, code, expected in [("polluted", "protocol", 5), ("incompatible", "incompatible_version", 4),
                                     ("truncated", "transport", 5), ("mismatch", "protocol", 5),
                                     ("failed-exit", "transport", 5), ("timeout", "timeout", 5),
                                     ("trailing", "protocol", 5)]:
            configure(server_path="/usr/local/bin/cais-fake-" + mode, timeout_seconds=1 if mode == "timeout" else 10)
            check("rejects " + mode + " peer", cli(["list"], config, expected=expected)["error"]["code"] == code)
        configure(server_path="/usr/local/bin/cais-server", timeout_seconds=10)
        for mode, code, expected in [("ok", None, 0), ("zero", "protocol", 5), ("large", "protocol", 5),
                                     ("truncated", "protocol", 5), ("mismatch", "protocol", 5),
                                     ("error", "not_authorized", 3), ("failed-exit", "transport", 5), ("trailing", "protocol", 5)]:
            configure(server_path="/usr/local/bin/cais-fake-private-" + mode)
            directory = case / ("private-export-" + mode)
            value = cli(["db-config", "example", "--output-dir", str(directory)], config, expected=expected)
            final = directory / "credentials.private.json"
            check("private download " + mode + " validates framing and publishes only confirmed success",
                  (final.exists() and final.read_bytes() == b"synthetic-private-payload") if expected == 0 else
                  (not directory.exists() and value["error"]["code"] == code))
        for mode, expected in [("terminal", 0), ("terminal-error", 2)]:
            configure(server_path="/usr/local/bin/cais-fake-" + mode)
            output = subprocess.run([str(CLIENT), "list", "--target", "fixture", "--config", str(config)],
                                    capture_output=True, timeout=20)
            combined = output.stdout + output.stderr
            check("filters " + mode + " control text", output.returncode == expected and b"\x1b" not in combined
                  and "\u202e".encode() not in combined)
        for mode in ["writable", "owner", "parent-owner", "sticky", "link"]:
            configure(server_path="/usr/local/bin/cais-policy-" + mode)
            check("rejects policy " + mode + " ancestry or ownership", cli(["list"], config, expected=5)["error"]["code"] == "transport")
        for mode in ["good", "operator"]:
            configure(server_path="/usr/local/bin/cais-policy-" + mode)
            check("accepts trusted " + mode + " policy ownership", cli(["list"], config)["data"] == ["example", "website"])
        configure(server_path="/usr/local/bin/cais-server")
        # An alias's Port must survive when the optional profile port is omitted.
        (case / "ssh_config").write_text(f"Host fixture-alias\n HostName 127.0.0.1\n Port {port}\n User operator\nHost *\n LogLevel ERROR\n", encoding="utf-8")
        configure(ssh="fixture-alias", port=None)
        check("honors OpenSSH alias port", cli(["list"], config)["data"] == ["example", "website"])
        configure(ssh="operator@127.0.0.1", port=port)
        wrong = case / "wrong known hosts"
        client_pub = (case / "client_key.pub").read_text().split()
        wrong.write_text(f"[127.0.0.1]:{port} {client_pub[0]} {client_pub[1]}\n", encoding="utf-8")
        configure(known_hosts=wrong.name)
        check("rejects unexpected SSH host identity", cli(["list"], config, expected=5)["error"]["code"] == "transport")
        configure(known_hosts=known.name)
        run(["docker", "exec", container, "chmod", "666", "/etc/cais/server.json"])
        check("rejects writable host policy", cli(["list"], config, expected=5)["error"]["code"] == "transport")
        run(["docker", "exec", container, "chmod", "644", "/etc/cais/server.json"])
        run(["docker", "exec", container, "python3", "-c", "from pathlib import Path; p=Path('/etc/cais/server.json'); p.rename('/etc/cais/policy.json'); p.symlink_to('policy.json')"])
        try:
            check("rejects symlinked host policy", cli(["list"], config, expected=5)["error"]["code"] == "transport")
        finally:
            run(["docker", "exec", container, "python3", "-c", "from pathlib import Path; Path('/etc/cais/server.json').unlink(); Path('/etc/cais/policy.json').rename('/etc/cais/server.json')"])
        linux_profile = json.loads(json.dumps(profile))
        linux_profile["targets"]["fixture"].update(port=22, identity_file="/run/cais-test-key")
        linux_profile["targets"]["fixture"]["ssh_config"] = "/run/cais-multiplex-config"
        # Establish a genuine master authenticated as outsider, then configure a shared
        # ControlPath. A control session must not inherit that master's OS identity.
        run(["docker", "exec", container, "ssh", "-F", "none", "-M", "-S", "/run/cais-master",
             "-fNT", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=\"/case/known hosts\"",
             "-i", "/run/cais-test-key", "outsider@127.0.0.1"])
        master_identity = run(["docker", "exec", container, "ssh", "-F", "none", "-S", "/run/cais-master", "operator@127.0.0.1", "id", "-un"]).stdout.decode().strip()
        assert master_identity == "outsider", "Synthetic cross-identity master precondition is missing"
        run(["docker", "exec", container, "python3", "-c",
             "from pathlib import Path; Path('/run/cais-multiplex-config').write_text('Host *\\n ControlMaster auto\\n ControlPath /run/cais-master\\n ControlPersist yes\\n')"])
        (case / "linux-client.json").write_text(json.dumps(linux_profile), encoding="utf-8")
        for command in [["capabilities"], ["list"], ["plan", "--file", "/case/project.json"]]:
            output = run(["docker", "exec", container, "/usr/local/bin/cais", *command,
                          "--target", "fixture", "--config", "/case/linux-client.json", "--json"])
            data = json.loads(output.stdout)
            check("Linux client " + command[0], not output.stderr and data["outcome"] == "success")
            if command == ["list"]:
                check("Linux client refuses another identity's SSH master", data["data"] == ["example", "website"])

        def raw(request, spoof=False):
            payload = json.dumps(request).encode()
            remote = ["/usr/local/bin/cais-server"]
            if spoof:
                remote = ["/usr/bin/env", "USER=outsider", "LOGNAME=outsider", "SUDO_USER=outsider", *remote]
            output = run(["ssh", "-F", str(case / "ssh_config"), "-T", "-o", "BatchMode=yes",
                          "-o", "StrictHostKeyChecking=yes", "-o", f'UserKnownHostsFile="{str(known).replace(chr(92), chr(47))}"',
                          "-p", str(port), "-i", str(key), "operator@127.0.0.1", *remote],
                         input=struct.pack(">I", len(payload)) + payload).stdout
            stream = io.BytesIO(output)
            assert stream.read(8) == b"CAIS\0\0\0\1"
            for _ in range(2):
                size = struct.unpack(">I", stream.read(4))[0]
                result = json.loads(stream.read(size))
            assert not stream.read()
            return result["result"]
        request = {"protocol_version": 1, "request_id": "identity-test", "operation": {"name": "list"}}
        check("identity ignores spoofed environment", raw(request, spoof=True)["data"] == ["example", "website"])
        request["caller"] = "root"
        check("wire cannot select identity", raw(request)["error"]["code"] == "protocol")
        del request["caller"]
        request["operation"] = {"name": "list", "caller": "root"}
        check("operation cannot carry unknown identity fields", raw(request)["error"]["code"] == "protocol")
        request["operation"] = {"name": "capabilities", "x": 1}
        check("capabilities refuses unknown fields", raw(request)["error"]["code"] == "protocol")
        request["operation"] = {"name": "list"}
        request["protocol_version"] = 99
        check("request version is checked", raw(request)["error"]["code"] == "incompatible_version")
        check("planning leaves host policy unchanged", before == run(["docker", "exec", container, "sha256sum", "/etc/cais/server.json"]).stdout)
        run(["docker", "exec", container, "python3", "-c",
             "import json,jsonschema; from pathlib import Path; "
             "schemas={p.stem.split('.')[0]:json.loads(p.read_text()) for p in Path('/case/schemas').glob('*.json')}; "
             "[jsonschema.Draft202012Validator.check_schema(s) for s in schemas.values()]; "
             "assert not jsonschema.Draft202012Validator(schemas['server']).is_valid({'schema_version':99,'projects':{}})"])
        check("exported schemas are valid and reject unknown versions", True)
    finally:
        subprocess.run(["docker", "rm", "--force", container], capture_output=True, timeout=30)
assert collect_source_manifest() == source_before, "Source changed during verification"
assert binary_hashes_before == [hashlib.sha256(path.read_bytes()).hexdigest() for path in (CLIENT, SERVER, LINUX_CLIENT)], "Binaries changed during verification"
report = {"status": "passed", "checks": passed, "count": len(passed),
          "source_sha256": source_before["source_sha256"],
          "client_sha256": binary_hashes_before[0],
          "server_sha256": binary_hashes_before[1],
          "linux_client_sha256": binary_hashes_before[2],
          "scope": "synthetic SSH planning; no production access or application deployment"}
if args.report:
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(f"{len(passed)} real-SSH checks passed")
