//! Local MCP server over stdio. Every tool is one fixed CLI command with typed arguments:
//! the server re-invokes this executable, so an agent gets exactly the CLI's behaviour,
//! authorization and errors. There is no tool that runs a shell or an arbitrary command.
use serde_json::{Value, json};
use std::{
    io::{BufRead, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_LINE: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// A project or target name.
    Name,
    /// One of a fixed set of words.
    Choice(&'static [&'static str]),
    /// A file inside the workspace root, given as a relative path.
    File,
    /// A JSON object passed inline and handed to the CLI as a temporary file.
    Object,
}

struct Param {
    name: &'static str,
    /// `None` is the positional project argument.
    flag: Option<&'static str>,
    kind: Kind,
    required: bool,
    about: &'static str,
}

struct Tool {
    name: &'static str,
    command: &'static str,
    about: &'static str,
    params: &'static [Param],
    /// Adds the required `target` and the server's fixed client configuration.
    remote: bool,
    /// `capabilities` accepts an optional target.
    optional_target: bool,
}

const fn param(
    name: &'static str,
    flag: Option<&'static str>,
    kind: Kind,
    required: bool,
    about: &'static str,
) -> Param {
    Param {
        name,
        flag,
        kind,
        required,
        about,
    }
}

const PROJECT: Param = param(
    "project",
    None,
    Kind::Name,
    true,
    "Registered project name.",
);
const EXPECTED: Param = param(
    "expected",
    Some("--expected"),
    Kind::Object,
    true,
    "The result of cais_status (or its `expected` object) read just before this mutation.",
);
const PROJECT_FILE: Param = param(
    "file",
    Some("--file"),
    Kind::File,
    true,
    "Project configuration (cais.json), relative to the workspace root.",
);
const MUTATION: &[Param] = &[PROJECT, EXPECTED];
const CONFIG_KINDS: &[&str] = &["project", "client", "server", "metadata"];

const fn remote(
    name: &'static str,
    command: &'static str,
    about: &'static str,
    params: &'static [Param],
) -> Tool {
    Tool {
        name,
        command,
        about,
        params,
        remote: true,
        optional_target: false,
    }
}
const fn local(
    name: &'static str,
    command: &'static str,
    about: &'static str,
    params: &'static [Param],
) -> Tool {
    Tool {
        name,
        command,
        about,
        params,
        remote: false,
        optional_target: false,
    }
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "cais_capabilities",
        command: "capabilities",
        about: "Discover local commands, or the operations a target's server offers this identity.",
        params: &[],
        remote: false,
        optional_target: true,
    },
    local(
        "cais_validate",
        "validate",
        "Validate a configuration file locally. Contacts no server.",
        &[
            PROJECT_FILE,
            param(
                "kind",
                Some("--kind"),
                Kind::Choice(CONFIG_KINDS),
                false,
                "Configuration kind; defaults to project.",
            ),
        ],
    ),
    local(
        "cais_schema",
        "schema",
        "Return the JSON Schema of a configuration kind.",
        &[param(
            "kind",
            None,
            Kind::Choice(CONFIG_KINDS),
            true,
            "Configuration kind.",
        )],
    ),
    local(
        "cais_package",
        "package",
        "Create a deterministic artifact from a project's publish paths. Never overwrites a file.",
        &[
            PROJECT_FILE,
            param(
                "output",
                Some("--output"),
                Kind::File,
                true,
                "New artifact path (.tar.gz), relative to the workspace root.",
            ),
        ],
    ),
    remote(
        "cais_list",
        "list",
        "List the projects visible to the target's SSH identity.",
        &[],
    ),
    remote(
        "cais_plan",
        "plan",
        "Check project intent against the server policy and return a plan with a state revision. Changes nothing.",
        &[PROJECT_FILE],
    ),
    remote(
        "cais_status",
        "status",
        "Inspect a project: registration, service, deployment, route, backup, catalog and unresolved operations.",
        &[PROJECT],
    ),
    remote(
        "cais_register",
        "register",
        "Register a new isolated project from a plan. Creates accounts, directories and a service unit.",
        &[
            PROJECT_FILE,
            param(
                "plan",
                Some("--plan"),
                Kind::Object,
                true,
                "The result of cais_plan for this same file.",
            ),
            param(
                "deploy_public_key",
                Some("--deploy-public-key"),
                Kind::File,
                true,
                "Public SSH key of the deployment identity, relative to the workspace root.",
            ),
        ],
    ),
    remote(
        "cais_deploy",
        "deploy",
        "Publish an artifact. The target must be the project's deployment identity.",
        &[
            PROJECT_FILE,
            param(
                "artifact",
                Some("--artifact"),
                Kind::File,
                true,
                "Artifact created by cais_package, relative to the workspace root.",
            ),
            EXPECTED,
        ],
    ),
    remote(
        "cais_env_set",
        "env-set",
        "Replace the application environment from a private JSON file. Values are never returned.",
        &[
            PROJECT,
            param(
                "values",
                Some("--values"),
                Kind::File,
                true,
                "JSON object of string values, relative to the workspace root. Pass the path, not the values.",
            ),
            EXPECTED,
        ],
    ),
    remote(
        "cais_restart",
        "restart",
        "Restart an HTTP service and confirm its health.",
        MUTATION,
    ),
    remote(
        "cais_metadata_set",
        "metadata-set",
        "Replace the project's presentation metadata. Never deploys or restarts.",
        &[
            PROJECT,
            param(
                "file",
                Some("--file"),
                Kind::File,
                true,
                "Metadata file, relative to the workspace root.",
            ),
            EXPECTED,
        ],
    ),
    remote(
        "cais_proxy_apply",
        "proxy-apply",
        "Publish the project's declared route in the reverse proxy and reload it.",
        MUTATION,
    ),
    remote(
        "cais_proxy_remove",
        "proxy-remove",
        "Take the project's route out of the reverse proxy and reload it.",
        MUTATION,
    ),
    remote(
        "cais_backup_register",
        "backup-register",
        "Declare the project's backup paths and database to the host's backup tool.",
        MUTATION,
    ),
    remote(
        "cais_db_create",
        "db-create",
        "Provision a project-owned PostgreSQL database. Credentials are never returned.",
        MUTATION,
    ),
    remote(
        "cais_db_reconcile",
        "db-reconcile",
        "Verify an interrupted database provision without repeating it.",
        MUTATION,
    ),
];

fn name_like(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

fn schema(tool: &Tool) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    let mut add = |name: &str, value: Value, needed: bool| {
        properties.insert(name.into(), value);
        if needed {
            required.push(Value::from(name));
        }
    };
    for param in tool.params {
        let value = match param.kind {
            Kind::Name | Kind::File => json!({"type":"string","description":param.about}),
            Kind::Choice(choices) => {
                json!({"type":"string","enum":choices,"description":param.about})
            }
            Kind::Object => json!({"type":"object","description":param.about}),
        };
        add(param.name, value, param.required);
    }
    if tool.remote || tool.optional_target {
        add(
            "target",
            json!({"type":"string","description":"Target name from the server's client configuration."}),
            tool.remote,
        );
    }
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}

struct Server {
    executable: PathBuf,
    config: PathBuf,
    root: PathBuf,
}

impl Server {
    /// Resolves a workspace-relative path and refuses anything that leaves the root,
    /// including through a symbolic link.
    fn file(&self, value: &str) -> Result<PathBuf, String> {
        let relative = Path::new(value);
        if value.is_empty()
            || value.len() > 1024
            || value.starts_with('-')
            || value.contains('\0')
            || !relative
                .components()
                .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
        {
            return Err("Use a relative path inside the workspace root.".into());
        }
        let joined = self.root.join(relative);
        let outside = || String::from("The path leaves the workspace root.");
        let resolved = if joined.exists() {
            joined.canonicalize().map_err(|_| outside())?
        } else {
            let parent = joined.parent().ok_or_else(outside)?;
            let name = joined.file_name().ok_or_else(outside)?;
            parent.canonicalize().map_err(|_| outside())?.join(name)
        };
        if resolved.starts_with(&self.root) {
            Ok(resolved)
        } else {
            Err(outside())
        }
    }

    fn call(&self, name: &str, arguments: &Value) -> Result<Value, String> {
        let tool = TOOLS
            .iter()
            .find(|tool| tool.name == name)
            .ok_or("Unknown tool.")?;
        let empty = serde_json::Map::new();
        let arguments = match arguments {
            Value::Object(map) => map,
            Value::Null => &empty,
            _ => return Err("Arguments must be an object.".into()),
        };
        let known = |key: &str| {
            tool.params.iter().any(|param| param.name == key)
                || (key == "target" && (tool.remote || tool.optional_target))
        };
        if arguments.keys().any(|key| !known(key)) {
            return Err("Unknown argument for this tool.".into());
        }
        let mut positional = Vec::new();
        let mut flags: Vec<std::ffi::OsString> = Vec::new();
        // Inline objects live only for the duration of this call.
        let mut temporary = Vec::new();
        for param in tool.params {
            let Some(value) = arguments.get(param.name) else {
                if param.required {
                    return Err(format!("Missing required argument: {}.", param.name));
                }
                continue;
            };
            let invalid = || format!("Invalid argument: {}.", param.name);
            let rendered: std::ffi::OsString = match param.kind {
                Kind::Name => value
                    .as_str()
                    .filter(|text| name_like(text))
                    .ok_or_else(invalid)?
                    .into(),
                Kind::Choice(choices) => value
                    .as_str()
                    .filter(|text| choices.contains(text))
                    .ok_or_else(invalid)?
                    .into(),
                Kind::File => self.file(value.as_str().ok_or_else(invalid)?)?.into(),
                Kind::Object => {
                    if !value.is_object() {
                        return Err(invalid());
                    }
                    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
                    let mut file = tempfile::NamedTempFile::new().map_err(|_| invalid())?;
                    file.write_all(&bytes).map_err(|_| invalid())?;
                    file.flush().map_err(|_| invalid())?;
                    let path = file.path().to_owned();
                    temporary.push(file);
                    path.into()
                }
            };
            match param.flag {
                Some(flag) => {
                    flags.push(flag.into());
                    flags.push(rendered);
                }
                None => positional.push(rendered),
            }
        }
        match arguments.get("target") {
            Some(target) => {
                let target = target
                    .as_str()
                    .filter(|text| name_like(text))
                    .ok_or("Invalid argument: target.")?;
                flags.extend(["--target".into(), target.into()]);
                flags.extend(["--config".into(), self.config.clone().into()]);
            }
            None if tool.remote => return Err("Missing required argument: target.".into()),
            None => {}
        }
        let output = Command::new(&self.executable)
            .arg(tool.command)
            .args(positional)
            .args(flags)
            .arg("--json")
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| String::from("The operation could not be started."))?;
        drop(temporary);
        let Ok(result) = serde_json::from_slice::<Value>(&output.stdout) else {
            // The command ran and ended without a result, so nothing is known about it.
            let lost = json!({"schema_version":1,"outcome":"error","error":{
                "code":"unknown_outcome",
                "message":"The operation ended without a result and may have taken effect. Inspect the status before repeating it."}});
            return Ok(json!({
                "content":[{"type":"text","text":lost.to_string()}],
                "structuredContent": lost,
                "isError": true
            }));
        };
        let code = output.status.code().unwrap_or(1);
        // `schema` prints a raw document; every other command prints the result envelope.
        let structured = if tool.command == "schema" && code == 0 {
            json!({"schema_version":1,"outcome":"success","data":result})
        } else {
            result
        };
        Ok(json!({
            "content":[{"type":"text","text":structured.to_string()}],
            "structuredContent": structured,
            "isError": code != 0
        }))
    }

    fn handle(&self, method: &str, params: &Value) -> Result<Value, (i64, &'static str)> {
        match method {
            "initialize" => {
                let requested = params["protocolVersion"].as_str().unwrap_or_default();
                let version = PROTOCOL_VERSIONS
                    .iter()
                    .find(|version| **version == requested)
                    .unwrap_or(&PROTOCOL_VERSIONS[0]);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name":"cais","version":env!("CARGO_PKG_VERSION")},
                    "instructions": "Typed Cais operations. Read cais_status before each mutation and pass its result as `expected`. A result with outcome `error` and code `unknown_outcome` must be inspected, never repeated blindly."
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": TOOLS.iter().map(|tool| json!({
                "name": tool.name, "description": tool.about, "inputSchema": schema(tool)
            })).collect::<Vec<_>>()})),
            "tools/call" => {
                let name = params["name"].as_str().ok_or((-32602, "Invalid params"))?;
                Ok(self.call(name, &params["arguments"]).unwrap_or_else(
                    |message| json!({"content":[{"type":"text","text":message}],"isError":true}),
                ))
            }
            _ => Err((-32601, "Method not found")),
        }
    }
}

/// Serves until standard input closes. Returns a process exit code.
pub fn serve(config: &Path, root: &Path) -> i32 {
    let (Ok(executable), Ok(config), Ok(root)) = (
        std::env::current_exe(),
        // Not canonicalized: OpenSSH on Windows does not accept verbatim paths.
        std::path::absolute(config),
        root.canonicalize(),
    ) else {
        eprintln!("The client configuration and the workspace root must exist.");
        return 2;
    };
    if !config.is_file() || !root.is_dir() {
        eprintln!("The client configuration and the workspace root must exist.");
        return 2;
    }
    let server = Server {
        executable,
        config,
        root,
    };
    let mut output = std::io::stdout().lock();
    let mut input = std::io::stdin().lock();
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut input).take(MAX_LINE as u64 + 1).read_line(&mut line) {
            Ok(0) | Err(_) => return 0,
            Ok(_) => {}
        }
        if line.len() > MAX_LINE {
            return 1;
        }
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Err(_) => Some(
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}),
            ),
            Ok(message) => {
                let id = if message.is_object() {
                    message.get("id").cloned()
                } else {
                    // Batches and bare values are not supported.
                    Some(Value::Null)
                };
                match (message["method"].as_str(), id) {
                    // Notifications and responses from the client need no reply.
                    (_, None) => None,
                    (None, Some(_))
                        if message.get("result").is_some() || message.get("error").is_some() =>
                    {
                        None
                    }
                    (None, Some(id)) => Some(
                        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32600,"message":"Invalid Request"}}),
                    ),
                    (Some(method), Some(id)) => {
                        Some(match server.handle(method, &message["params"]) {
                            Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
                            Err((code, text)) => {
                                json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":text}})
                            }
                        })
                    }
                }
            }
        };
        if let Some(response) = response
            && (writeln!(output, "{response}").is_err() || output.flush().is_err())
        {
            return 0;
        }
    }
}
