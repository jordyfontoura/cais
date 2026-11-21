"""MCP session against the fixture's real server: discovery, planning, allowed
operations and denials, through the same SSH identities as the CLI journey."""
import json
import os
import subprocess

HOME = os.environ["HOME"]
server = subprocess.Popen(
    ["cais", "mcp", "--config", f"{HOME}/client.json", "--root", HOME],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
counter = 0


def request(method, params=None):
    global counter
    counter += 1
    server.stdin.write(json.dumps({"jsonrpc": "2.0", "id": counter, "method": method, "params": params or {}}) + "\n")
    server.stdin.flush()
    response = json.loads(server.stdout.readline())
    assert response["id"] == counter, response
    return response


def call(name, **arguments):
    return request("tools/call", {"name": name, "arguments": arguments})["result"]


def check(label, condition, detail=None):
    if not condition:
        raise SystemExit(f"FAIL: {label}: {json.dumps(detail)[:600]}")
    print(f"PASS: {label}")


hello = request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "fixture", "version": "0"}})
check("MCP server completes the handshake", hello["result"]["serverInfo"]["name"] == "cais", hello)
tools = {tool["name"] for tool in request("tools/list")["result"]["tools"]}
check("MCP lists typed tools and no terminal",
      {"cais_status", "cais_plan", "cais_restart", "cais_proxy_apply"} <= tools
      and not any(word in name for name in tools for word in ("shell", "exec", "psql", "ssh")), sorted(tools))

capabilities = call("cais_capabilities", target="operator")
check("MCP discovers the server's capabilities", capabilities["structuredContent"]["data"]["proxy_management"] is True, capabilities)
listed = call("cais_list", target="operator")
check("MCP lists the operator's projects", "api" in listed["structuredContent"]["data"], listed)
plan = call("cais_plan", file="api/cais.json", target="operator")
check("MCP plans without changing anything",
      plan["isError"] is False and plan["structuredContent"]["data"]["actions"] == ["deploy_registered_project"], plan)

status = call("cais_status", project="api", target="operator")
check("MCP reads project status", status["structuredContent"]["data"]["service"] == "active", status)
restarted = call("cais_restart", project="api", target="operator", expected=status["structuredContent"])
check("MCP performs an allowed mutation with a fresh revision",
      restarted["isError"] is False and restarted["structuredContent"]["data"]["last_operation"]["kind"] == "restart", restarted)
stale = call("cais_restart", project="api", target="operator", expected=status["structuredContent"])
check("MCP reports a stale revision as a conflict, without retrying",
      stale["isError"] is True and stale["structuredContent"]["error"]["code"] == "conflict", stale)

fresh = call("cais_status", project="api", target="operator")["structuredContent"]
metadata = call("cais_metadata_set", project="api", file="api/metadata.json", target="operator", expected=fresh)
check("MCP sets metadata from a workspace file",
      metadata["isError"] is False and metadata["structuredContent"]["data"]["metadata"]["title"] == "Fixture API", metadata)

fresh = call("cais_status", project="api", target="operator")["structuredContent"]
denied = call("cais_proxy_remove", project="api", target="api-deploy", expected=fresh)
check("MCP cannot exceed the SSH identity's authority",
      denied["isError"] is True and denied["structuredContent"]["error"]["code"] == "not_authorized", denied)
outsider = call("cais_status", project="ghost", target="operator")
check("MCP gets the server's refusal for an unknown project", outsider["isError"] is True, outsider)
escape = call("cais_env_set", project="api", values="../../etc/passwd", target="operator", expected=fresh)
check("MCP refuses a file outside the workspace before contacting the server",
      escape["isError"] is True and "structuredContent" not in escape, escape)
unknown = call("cais_run", command="id")
check("MCP has no generic command tool", unknown["isError"] is True and "structuredContent" not in unknown, unknown)

server.stdin.close()
check("MCP server exits when the client disconnects", server.wait(timeout=10) == 0)
