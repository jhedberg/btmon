# hcimon

Cross-platform Bluetooth HCI monitor in Rust (BlueZ btmon work-alike with a TUI).

- Workspace: `crates/hcimon-capture` (protocol framing, btsnoop/PacketLogger I/O),
  `crates/hcimon-decode` (stateful decoders → field tree; see `crates/hcimon-decode/DECODERS.md`
  before adding decoders), `crates/hcimon` (CLI, sources, plain output, ratatui UI).
- Build/test: `cargo build`, `cargo test --workspace`. Decode a capture to text:
  `cargo run -p hcimon-decode --example dump -- testdata/xg24_peripheral_hr.tty`.
- Generated tables: `crates/hcimon-decode/src/hci/ids.rs` (`tools/gen_hci_ids.py`, from the
  Core Spec text) and `crates/hcimon-decode/src/assigned/` (`tools/gen_assigned_numbers.py`).
  Never edit them by hand.
- Output wording follows BlueZ btmon; decoders never panic and report truncation in the tree.
- Machine interfaces: `-f digest|jsonl|summary`, `-Y` filters, `-X` context, `--fields`, and
  `--mcp` (stdio MCP server; tools in `crates/hcimon/src/mcp.rs`, primitives in `analysis.rs`).
- Commits: `area: Subject` (area = crate/module), explanatory body, trailer block last with
  `Assisted-by: Claude:<model-id>` before `Signed-off-by:`; no other AI mentions.
