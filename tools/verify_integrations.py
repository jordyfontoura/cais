"""Exercise proxy routes, backups, the catalog and an MCP session against a real host.

Builds a disposable local Docker container running systemd, OpenSSH and Caddy, installs
the supplied Linux binaries and runs the journey in tests/integrations. Synthetic keys
only; it never connects to a configured SSH target and removes its own container.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--linux-bin", type=Path, default=ROOT / "target/linux/release",
                    help="Directory with Linux cais, cais-server and cais-broker")
parser.add_argument("--keep", action="store_true", help="Leave the container running for inspection")
args = parser.parse_args()
binaries = [args.linux_bin.resolve() / name for name in ("cais", "cais-server", "cais-broker")]
assert all(path.is_file() for path in binaries), "Build the Linux binaries first"

fixture = ROOT / "tests" / "integrations"
image = "cais-integrations-test:local"
name = "cais-integrations-" + uuid.uuid4().hex[:10]


def docker(*command, **kwargs):
    return subprocess.run(["docker", *command], check=True, **kwargs)


docker("build", "--quiet", "--tag", image, str(fixture), stdout=subprocess.DEVNULL)
docker("run", "--detach", "--name", name, "--privileged", "--cgroupns=private",
       "--tmpfs", "/run", "--tmpfs", "/run/lock", image, stdout=subprocess.DEVNULL)
try:
    for _ in range(60):
        probe = subprocess.run(["docker", "exec", name, "systemctl", "is-active", "ssh", "caddy", "postgresql@17-main"],
                               capture_output=True, text=True)
        if probe.stdout.split() == ["active", "active", "active"]:
            break
        time.sleep(1)
    else:
        raise SystemExit("The fixture's ssh, caddy and postgresql services did not start")
    docker("exec", name, "mkdir", "-p", "/fixture/bin")
    for path in binaries:
        docker("cp", str(path), f"{name}:/fixture/bin/{path.name}")
    for path in (fixture / "setup.sh", fixture / "journey.sh", fixture / "mcp_session.py",
                 fixture / "app.py", fixture / "authgate.py"):
        docker("cp", str(path), f"{name}:/fixture/{path.name}")
    docker("exec", name, "sh", "-c",
           "chmod 0755 /fixture/bin/* && chmod 0644 /fixture/app.py && "
           "echo 'dev ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/fixture-dev && chmod 0440 /etc/sudoers.d/fixture-dev")
    docker("exec", name, "sh", "/fixture/setup.sh")
    result = subprocess.run(["docker", "exec", "--user", "dev", "--env", "HOME=/home/dev", name,
                             "bash", "/fixture/journey.sh"])
    if result.returncode != 0:
        subprocess.run(["docker", "exec", name, "sh", "-c",
                        "cat /home/dev/last.json 2>/dev/null; journalctl -u caddy -n 15 --no-pager"])
        sys.exit(result.returncode)
finally:
    if args.keep:
        print(f"Container left running: {name}")
    else:
        subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL)
