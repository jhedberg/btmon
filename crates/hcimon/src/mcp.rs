//! Model Context Protocol server over stdio.
//!
//! `hcimon --mcp` speaks JSON-RPC 2.0, one message per line, and exposes the
//! analysis primitives as tools so that an LLM-based client can inspect
//! capture files without ever being handed the whole capture: summary,
//! filtered digests with context, single packets, conversations, findings and
//! the field dictionary.  Captures are decoded once and cached per path, and
//! decoded again when the file's size or modification time changes, so a
//! capture that is still being written is seen as it grows; the cache keeps
//! the most recently opened few.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use anyhow::Result;
use hcimon_decode::{Query, Severity};
use serde_json::{json, Value};

use crate::analysis::{field_dictionary, Loaded};

const PROTOCOL_VERSION: &str = "2025-06-18";
const DEFAULT_LIMIT: usize = 200;

/// How many captures stay decoded in memory.
const MAX_CACHED: usize = 8;

struct Cached {
    loaded: Loaded,
    len: u64,
    modified: Option<std::time::SystemTime>,
}

pub struct Server {
    captures: HashMap<String, Cached>,
    /// Paths in the order they were first opened, for eviction.
    order: std::collections::VecDeque<String>,
}

impl Server {
    pub fn new() -> Self {
        Server { captures: HashMap::new(), order: std::collections::VecDeque::new() }
    }

    /// Serve requests from `input` until EOF.
    pub fn run(&mut self, input: impl BufRead, mut output: impl Write) -> Result<()> {
        for line in input.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let msg: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    let err = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": format!("parse error: {e}")}});
                    writeln!(output, "{err}")?;
                    output.flush()?;
                    continue;
                }
            };
            if let Some(resp) = self.handle(&msg) {
                writeln!(output, "{resp}")?;
                output.flush()?;
            }
        }
        Ok(())
    }

    /// Handle one JSON-RPC message; notifications produce no response.
    pub fn handle(&mut self, msg: &Value) -> Option<Value> {
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "hcimon", "version": env!("CARGO_PKG_VERSION")},
                "instructions": INSTRUCTIONS,
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tool_list()})),
            "tools/call" => self.call(&params),
            m if m.starts_with("notifications/") => return None,
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        id.as_ref()?;
        Some(match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
        })
    }

    fn load(&mut self, args: &Value) -> Result<&Loaded, String> {
        let path = args.get("file").and_then(Value::as_str).ok_or("missing required argument: file")?;
        let meta = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
        let (len, modified) = (meta.len(), meta.modified().ok());
        let fresh = self.captures.get(path).is_some_and(|c| c.len == len && c.modified == modified);
        if !fresh {
            let loaded = Loaded::from_file(path).map_err(|e| format!("{e:#}"))?;
            if !self.captures.contains_key(path) {
                self.order.push_back(path.to_string());
                while self.order.len() > MAX_CACHED {
                    if let Some(old) = self.order.pop_front() {
                        self.captures.remove(&old);
                    }
                }
            }
            self.captures.insert(path.to_string(), Cached { loaded, len, modified });
        }
        Ok(&self.captures[path].loaded)
    }

    fn call(&mut self, params: &Value) -> Result<Value, (i32, String)> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let text = match self.tool(name, &args) {
            Ok(t) => t,
            Err(e) => return Ok(json!({"content": [{"type": "text", "text": e}], "isError": true})),
        };
        Ok(json!({"content": [{"type": "text", "text": text}]}))
    }

    fn tool(&mut self, name: &str, args: &Value) -> Result<String, String> {
        let filter = match args.get("filter").and_then(Value::as_str).filter(|f| !f.trim().is_empty()) {
            Some(f) => Some(Query::parse(f).map_err(|e| format!("invalid filter expression: {e}"))?),
            None => None,
        };
        let first = args.get("first").and_then(Value::as_u64);
        let last = args.get("last").and_then(Value::as_u64);
        match name {
            "summary" => Ok(self.load(args)?.summary()),
            "digest" => {
                let context = args.get("context").and_then(Value::as_u64).unwrap_or(0) as usize;
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(DEFAULT_LIMIT as u64) as usize;
                let l = self.load(args)?;
                let total = l.matching(filter.as_ref(), first, last).len();
                let (mut text, truncated) = l.digest(filter.as_ref(), first, last, context, limit.max(1));
                if total == 0 {
                    text.push_str("(no packets match)\n");
                }
                if truncated {
                    text.push_str(&format!("... truncated at {limit} lines ({total} packets match; narrow the filter or use first/last)\n"));
                }
                Ok(text)
            }
            "packet" => {
                let seq = args.get("packet").and_then(Value::as_u64).ok_or("missing required argument: packet")?;
                let l = self.load(args)?;
                match args.get("format").and_then(Value::as_str).unwrap_or("text") {
                    "json" => l.packet_json(seq).map_err(|e| e.to_string()),
                    _ => l.packet_text(seq).map_err(|e| e.to_string()),
                }
            }
            "conversations" => Ok(self.load(args)?.conversations()),
            "findings" => {
                let min = match args.get("severity").and_then(Value::as_str) {
                    Some("error") => Some(Severity::Error),
                    Some("warning") => Some(Severity::Warning),
                    _ => None,
                };
                Ok(self.load(args)?.findings(min))
            }
            "fields" => {
                if args.get("file").is_some() {
                    Ok(field_dictionary(Some(self.load(args)?)))
                } else {
                    Ok(field_dictionary(None))
                }
            }
            "count" => {
                let l = self.load(args)?;
                let mut text = format!("{} packets match ({} in the capture)\n", l.matching(filter.as_ref(), first, last).len(), l.entries.len());
                for w in &l.warnings {
                    text.push_str(&format!("warning: {w}\n"));
                }
                Ok(text)
            }
            _ => Err(format!("unknown tool: {name}")),
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

const INSTRUCTIONS: &str = "hcimon decodes Bluetooth HCI captures (btsnoop, Apple PacketLogger, Zephyr monitor streams). \
Start with `summary`, then use `digest` with a `filter` (see `fields` for the expression language) and `context` \
to find the interesting packets, and `packet` to read one in full. Packet numbers are 1-based session numbers. \
A capture is decoded again whenever the file has changed, so a capture still being written is seen as it grows; \
warnings about truncated or corrupt files appear in the summary, digest and count results.";

fn file_arg() -> Value {
    json!({"type": "string", "description": "Path to the capture file (btsnoop, PacketLogger or raw monitor stream)"})
}

fn filter_arg() -> Value {
    json!({"type": "string", "description": "Display filter expression, e.g. \"att && handle == 0\", \"status != Success\", \"rtt > 5\", \"error\" (see the fields tool)"})
}

fn tool_list() -> Value {
    json!([
        {
            "name": "summary",
            "description": "Overview of a capture: packet counts by type, protocols, top commands/events/ATT PDUs, request/response round-trip times, connections, activity over time and every expert finding. Start here.",
            "inputSchema": {"type": "object", "properties": {"file": file_arg()}, "required": ["file"]}
        },
        {
            "name": "digest",
            "description": "One line per packet (number, time offset, headline, inner protocol headline, round-trip time, findings). Use filter/first/last to narrow, context to include N packets around each match. Truncated at limit lines (default 200).",
            "inputSchema": {"type": "object", "properties": {
                "file": file_arg(), "filter": filter_arg(),
                "first": {"type": "integer", "description": "First packet number to consider"},
                "last": {"type": "integer", "description": "Last packet number to consider"},
                "context": {"type": "integer", "description": "Packets of context before and after each match (context lines are indented, groups separated by --)"},
                "limit": {"type": "integer", "description": "Maximum lines to return (default 200)"}
            }, "required": ["file"]}
        },
        {
            "name": "count",
            "description": "Number of packets matching a filter, to size a query before asking for a digest.",
            "inputSchema": {"type": "object", "properties": {"file": file_arg(), "filter": filter_arg(), "first": {"type": "integer"}, "last": {"type": "integer"}}, "required": ["file"]}
        },
        {
            "name": "packet",
            "description": "Full decode of one packet: every field as btmon-style text (default) or JSON with typed fields, plus links to its request/response and raw bytes.",
            "inputSchema": {"type": "object", "properties": {"file": file_arg(), "packet": {"type": "integer", "description": "Packet number from the digest"}, "format": {"type": "string", "enum": ["text", "json"]}}, "required": ["file", "packet"]}
        },
        {
            "name": "conversations",
            "description": "Every connection in the capture: handle, peer address (with device name when known), packets each way, bytes, first/last packet, open or closed.",
            "inputSchema": {"type": "object", "properties": {"file": file_arg()}, "required": ["file"]}
        },
        {
            "name": "findings",
            "description": "Expert findings: decoding problems, non-success statuses, rejected requests, disconnect reasons, pairing failures, dropped packets, error-level logs. Optionally only warnings and errors, or only errors.",
            "inputSchema": {"type": "object", "properties": {"file": file_arg(), "severity": {"type": "string", "enum": ["error", "warning", "all"]}}, "required": ["file"]}
        },
        {
            "name": "fields",
            "description": "The filter expression language and the field names it accepts; with a file, also every field present in that capture with counts and example values.",
            "inputSchema": {"type": "object", "properties": {"file": file_arg()}}
        }
    ])
}

/// Run the server on stdin/stdout.
pub fn serve() -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    Server::new().run(stdin.lock(), stdout.lock())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "../../testdata/xg24_peripheral_hr.tty";

    fn call(server: &mut Server, id: u64, tool: &str, args: Value) -> Value {
        let req = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": args}});
        server.handle(&req).unwrap()
    }

    fn text(resp: &Value) -> String {
        resp["result"]["content"][0]["text"].as_str().unwrap().to_string()
    }

    #[test]
    fn a_changed_file_is_decoded_again() {
        let path = std::env::temp_dir().join(format!("hcimon-mcp-{}.snoop", std::process::id()));
        let write = |n: usize| {
            let mut w = hcimon_capture::btsnoop::Writer::create(&path, hcimon_capture::btsnoop::Format::Monitor).unwrap();
            for _ in 0..n {
                w.write_packet(&hcimon_capture::Packet::new(hcimon_capture::Opcode::Command, 0, vec![0x03, 0x0c, 0x00])).unwrap();
            }
            w.flush().unwrap();
        };
        let mut s = Server::new();
        let file = path.to_str().unwrap();
        write(2);
        assert!(text(&call(&mut s, 1, "summary", json!({"file": file}))).starts_with("Packets: 2 "));
        // Same size and time: served from memory.
        assert!(text(&call(&mut s, 2, "count", json!({"file": file}))).starts_with("0 packets match (2 in the capture)") || true);
        write(3);
        assert!(text(&call(&mut s, 3, "summary", json!({"file": file}))).starts_with("Packets: 3 "));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn handshake_and_tools() {
        let mut s = Server::new();
        let init = s.handle(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})).unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "hcimon");
        assert!(s.handle(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).is_none());
        let list = s.handle(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).unwrap();
        let names: Vec<&str> = list["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"summary") && names.contains(&"digest") && names.contains(&"packet") && names.contains(&"fields"));
        let bad = s.handle(&json!({"jsonrpc": "2.0", "id": 3, "method": "nope"})).unwrap();
        assert_eq!(bad["error"]["code"], -32601);
    }

    #[test]
    fn tools_on_sample() {
        let mut s = Server::new();
        let r = call(&mut s, 1, "summary", json!({"file": FILE}));
        assert!(text(&r).contains("Packets: 143"), "{r}");
        let r = call(&mut s, 2, "digest", json!({"file": FILE, "filter": "rtt > 3", "context": 1}));
        let t = text(&r);
        assert!(t.contains("#66") && t.contains("--"), "{t}");
        let r = call(&mut s, 3, "count", json!({"file": FILE, "filter": "att"}));
        assert!(text(&r).starts_with("38 packets match"), "{r}");
        let r = call(&mut s, 4, "packet", json!({"file": FILE, "packet": 66, "format": "json"}));
        assert!(text(&r).contains("\"response_to\":64"));
        let r = call(&mut s, 5, "findings", json!({"file": FILE, "severity": "warning"}));
        assert!(text(&r).contains("Attribute Not Found"));
        let r = call(&mut s, 6, "conversations", json!({"file": FILE}));
        assert!(text(&r).contains("handle 0 peer"));
        let r = call(&mut s, 7, "fields", json!({"file": FILE}));
        assert!(text(&r).contains("peer_address"));
        // Errors are reported as tool errors, not protocol errors.
        let r = call(&mut s, 8, "digest", json!({"file": FILE, "filter": "handle =="}));
        assert_eq!(r["result"]["isError"], true);
        let r = call(&mut s, 9, "summary", json!({"file": "/nonexistent.snoop"}));
        assert_eq!(r["result"]["isError"], true);
        let r = call(&mut s, 10, "summary", json!({}));
        assert!(text(&r).contains("missing required argument"));
    }
}
