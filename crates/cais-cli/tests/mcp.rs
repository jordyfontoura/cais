//! A real MCP session over stdio against the built binary: discovery, typed calls,
//! refusals and protocol errors. Remote operations are exercised by the Docker journey.
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

struct Session {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    next: u64,
}

impl Session {
    fn start(root: &Path) -> Self {
        fs::write(
            root.join("client.json"),
            br#"{"schema_version":1,"targets":{}}"#,
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_cais"))
            .args(["mcp", "--config"])
            .arg(root.join("client.json"))
            .arg("--root")
            .arg(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
            next: 1,
        }
    }
    fn send(&mut self, message: &Value) {
        writeln!(self.input, "{message}").unwrap();
        self.input.flush().unwrap();
    }
    fn read(&mut self) -> Value {
        let mut line = String::new();
        self.output.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let response = self.read();
        assert_eq!(response["id"], id);
        response
    }
    fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name":name,"arguments":arguments}))["result"].clone()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn project(root: &Path) {
    fs::create_dir_all(root.join("dist/public")).unwrap();
    fs::write(root.join("dist/public/index.html"), b"fixture").unwrap();
    fs::write(
        root.join("cais.json"),
        serde_json::to_vec(&json!({"schema_version":1,"project":"website",
            "artifact":{"directory":"dist","publish":["public"]},
            "app":{"kind":"static","public":"public"}}))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn session_discovers_and_runs_typed_tools() {
    let root = tempfile::tempdir().unwrap();
    project(root.path());
    let mut session = Session::start(root.path());

    let hello = session.request(
        "initialize",
        json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}),
    );
    assert_eq!(hello["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(hello["result"]["serverInfo"]["name"], "cais");
    assert!(hello["result"]["capabilities"]["tools"].is_object());
    // A notification gets no reply; the next response belongs to the next request.
    session.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    assert_eq!(session.request("ping", json!({}))["result"], json!({}));

    let listed = session.request("tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for expected in [
        "cais_capabilities",
        "cais_plan",
        "cais_status",
        "cais_register",
        "cais_deploy",
        "cais_restart",
        "cais_proxy_apply",
        "cais_backup_register",
        "cais_metadata_set",
    ] {
        assert!(names.contains(&expected), "missing {expected}");
    }
    // The server offers fixed operations only: nothing resembling a terminal.
    for name in &names {
        assert!(name.starts_with("cais_"));
        for forbidden in ["shell", "exec", "run", "command", "psql", "tunnel", "ssh"] {
            assert!(!name.contains(forbidden), "unexpected tool {name}");
        }
    }
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    }

    let valid = session.call("cais_validate", json!({"file":"cais.json"}));
    assert_eq!(valid["isError"], false);
    assert_eq!(valid["structuredContent"]["data"]["valid"], true);
    let text: Value = serde_json::from_str(valid["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, valid["structuredContent"]);

    let schema = session.call("cais_schema", json!({"kind":"metadata"}));
    assert_eq!(schema["isError"], false);
    assert_eq!(
        schema["structuredContent"]["data"]["title"],
        "ProjectMetadata"
    );

    let packaged = session.call(
        "cais_package",
        json!({"file":"cais.json","output":"site.tar.gz"}),
    );
    assert_eq!(packaged["isError"], false, "{packaged}");
    assert!(root.path().join("site.tar.gz").is_file());
    // The CLI's own refusal comes back as a structured error, not a protocol failure.
    let again = session.call(
        "cais_package",
        json!({"file":"cais.json","output":"site.tar.gz"}),
    );
    assert_eq!(again["isError"], true);
    assert_eq!(again["structuredContent"]["outcome"], "error");

    let local = session.call("cais_capabilities", json!({}));
    assert_eq!(local["isError"], false);
    assert!(
        local["structuredContent"]["data"]["commands"]
            .as_array()
            .unwrap()
            .contains(&json!("mcp"))
    );
}

#[test]
fn session_refuses_escapes_and_untyped_input() {
    let root = tempfile::tempdir().unwrap();
    project(root.path());
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("cais.json"), b"{}").unwrap();
    let mut session = Session::start(root.path());
    session.request("initialize", json!({"protocolVersion":"2024-11-05"}));

    let absolute = outside.path().join("cais.json");
    for file in [
        "../cais.json",
        "dist/../../cais.json",
        absolute.to_str().unwrap(),
        "--config",
        "",
    ] {
        let result = session.call("cais_validate", json!({"file":file}));
        assert_eq!(result["isError"], true, "accepted {file}");
        assert!(result.get("structuredContent").is_none());
    }
    for (tool, arguments) in [
        ("cais_shell", json!({})),
        ("cais_validate", json!({"file":"cais.json","extra":true})),
        ("cais_validate", json!({"file":"cais.json","kind":"--help"})),
        ("cais_validate", json!({"file":["cais.json"]})),
        ("cais_validate", json!({})),
        ("cais_status", json!({"project":"website"})),
        ("cais_status", json!({"project":"-x","target":"prod"})),
        (
            "cais_status",
            json!({"project":"website","target":"--config"}),
        ),
        (
            "cais_restart",
            json!({"project":"website","target":"prod","expected":"status.json"}),
        ),
        ("cais_validate", json!(["cais.json"])),
    ] {
        let result = session.call(tool, arguments.clone());
        assert_eq!(result["isError"], true, "accepted {tool} {arguments}");
        assert!(
            result.get("structuredContent").is_none(),
            "{tool} reached the CLI"
        );
    }
    // A well-formed remote call runs the CLI, which refuses the unknown target itself.
    let unknown = session.call("cais_status", json!({"project":"website","target":"prod"}));
    assert_eq!(unknown["isError"], true);
    assert_eq!(unknown["structuredContent"]["outcome"], "error");

    let missing = session.request("resources/list", json!({}));
    assert_eq!(missing["error"]["code"], -32601);
    session.send(&json!("not an object"));
    assert_eq!(session.read()["error"]["code"], -32600);
    session.send(&json!({"jsonrpc":"2.0","id":41}));
    assert_eq!(session.read()["error"]["code"], -32600);
    writeln!(session.input, "{{ not json").unwrap();
    session.input.flush().unwrap();
    assert_eq!(session.read()["error"]["code"], -32700);
    assert_eq!(session.request("ping", json!({}))["result"], json!({}));
}
