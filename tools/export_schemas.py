"""Export or check schemas using the same binary users run. No external packages."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--client", type=Path, required=True)
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
client = args.client.resolve()
KINDS = ("project", "client", "server", "metadata")
for kind in KINDS:
    output = subprocess.run([str(client), "schema", kind], check=True, capture_output=True)
    schema = json.loads(output.stdout)
    destination = ROOT / "schemas" / f"{kind}.schema.json"
    if args.check:
        assert json.loads(destination.read_text(encoding="utf-8")) == schema, f"Schema drift: {kind}"
    else:
        destination.parent.mkdir(exist_ok=True)
        destination.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
print(f"{len(KINDS)} schemas match" if args.check else f"{len(KINDS)} schemas exported")
