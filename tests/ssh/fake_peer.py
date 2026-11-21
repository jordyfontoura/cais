#!/usr/bin/python3
"""Adversarial synthetic peers, only installed in the disposable test container."""
import json
import os
import struct
import sys
import time

mode = os.path.basename(sys.argv[0]).removeprefix("cais-fake-")
if mode == "timeout":
    time.sleep(10)
    sys.exit(0)
if mode == "polluted":
    print("synthetic-peer-canary")
    sys.exit(0)
if mode == "truncated":
    sys.stdout.buffer.write(b"CAIS\0\0\0\1\0\0")
    sys.exit(0)

def frame(value):
    data = json.dumps(value).encode()
    sys.stdout.buffer.write(struct.pack(">I", len(data)) + data)
    sys.stdout.buffer.flush()

hello = {"protocol_versions": [99 if mode == "incompatible" else 1], "server_version": "test", "capabilities": {
    "configuration_versions": [1], "operations": ["list"], "deployment": False, "proxy_management": False,
    "database_management": False, "observations": False, "mcp": False}}
sys.stdout.buffer.write(b"CAIS\0\0\0\1")
frame(hello)
if mode == "incompatible":
    sys.exit(0)
length = struct.unpack(">I", sys.stdin.buffer.read(4))[0]
request = json.loads(sys.stdin.buffer.read(length))
if mode.startswith("private-"):
    def response(result, request_id=None):
        frame({"protocol_version": 1, "request_id": request_id or request["request_id"], "result": result})
    payload = b"synthetic-private-payload"
    size = 0 if mode == "private-zero" else 65537 if mode == "private-large" else len(payload)
    response({"outcome": "private_file_ready", "bytes": size})
    if mode not in {"private-zero", "private-large"}:
        sys.stdout.buffer.write(payload[:3] if mode == "private-truncated" else payload)
        sys.stdout.buffer.flush()
        if mode != "private-truncated":
            result = {"outcome": "error", "error": {"code": "not_authorized", "message": "Private export refused."}} if mode == "private-error" else {"outcome": "success", "data": {"exported": True}}
            response(result, "wrong" if mode == "private-mismatch" else None)
            if mode == "private-trailing":
                sys.stdout.buffer.write(b"trailing")
    sys.exit(7 if mode == "private-failed-exit" else 0)
result = {"outcome": "success", "data": []}
if mode == "terminal":
    result["data"] = {"project": "example\x1b[31m", "notes": ["unsafe\x1b[2J\u202edirection"]}
if mode == "terminal-error":
    result = {"outcome": "error", "error": {"code": "invalid_config", "message": "unsafe\x1b[2J\u202eerror",
              "issues": [{"path": "/unsafe\x1b", "message": "unsafe\x1b[31m"}]}}
frame({"protocol_version": 1, "request_id": "wrong" if mode == "mismatch" else request["request_id"], "result": result})
if mode == "trailing":
    sys.stdout.buffer.write(b"unexpected trailing data")
    sys.stdout.buffer.flush()
sys.exit(7 if mode == "failed-exit" else 0)
