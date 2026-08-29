//! Application state and event loop of the interactive UI.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use anyhow::Result;
use hcimon_decode::Timestamp;
use crossbeam_channel::{select, unbounded, Receiver};
use ratatui::crossterm::event::{self, Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEventKind};
use ratatui::crossterm::execute;
use ratatui::layout::Rect;
use ratatui::DefaultTerminal;

use super::conversations::{self, Conversation};
use super::filter::{Category, Filter, LAYERS};
use super::ui;
use super::widgets::{flatten_tree, TextInput};
use crate::session::{Entry, Ref, Session};
use hcimon_decode::LinkKind;
use crate::source::discovery::{self, ProbeCandidate, SerialCandidate};
use crate::source::{Event as SourceEvent, SourceId, SourceKind};
use crate::time::TimeMode;

const FRAME_INTERVAL: Duration = Duration::from_millis(33);
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(2);
const MESSAGE_TTL: Duration = Duration::from_secs(6);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    List,
    Details,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutMode {
    /// Details below the list.
    Bottom,
    /// Details to the right of the list.
    Right,
    /// Details hidden.
    Hidden,
}

impl LayoutMode {
    pub fn next(self) -> Self {
        match self {
            LayoutMode::Bottom => LayoutMode::Right,
            LayoutMode::Right => LayoutMode::Hidden,
            LayoutMode::Hidden => LayoutMode::Bottom,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceState {
    Running,
    Finished,
    Failed,
}

#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub packets: u64,
    pub state: SourceState,
    pub last_message: String,
}

/// Which popup is open.
#[derive(Debug, Clone)]
pub enum Popup {
    Help,
    Filter { cursor: usize },
    Sources { cursor: usize },
    AddSource(AddSource),
    Write(TextInput),
    Search(TextInput),
    Expr(TextInput),
    Conversations { cursor: usize, rows: Vec<Conversation> },
    Message { title: String, text: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddKind {
    Tty,
    Rtt,
    File,
    Kernel,
}

impl AddKind {
    pub const ALL: [AddKind; 4] = [AddKind::Tty, AddKind::Rtt, AddKind::File, AddKind::Kernel];

    pub fn name(self) -> &'static str {
        match self {
            AddKind::Tty => "Serial port (Zephyr monitor over UART)",
            AddKind::Rtt => "RTT channel via debug probe",
            AddKind::File => "Capture file (btsnoop / PacketLogger / raw stream)",
            AddKind::Kernel => "Linux kernel HCI monitor socket",
        }
    }
}

/// State of the "add source" dialog.
#[derive(Debug, Clone)]
pub struct AddSource {
    pub kind: AddKind,
    /// 0 = kind selector, then the fields of the chosen kind.
    pub field: usize,
    pub ports: Vec<SerialCandidate>,
    pub port_idx: usize,
    pub path: TextInput,
    pub baud: TextInput,
    pub probes: Vec<ProbeCandidate>,
    pub probe_idx: usize,
    pub chip: TextInput,
    pub channel: TextInput,
    /// Reset the target after attaching (RTT) so the capture starts at boot.
    pub reset: bool,
    pub error: Option<String>,
}

impl AddSource {
    pub fn new(default_baud: u32) -> Self {
        let ports = discovery::serial_ports();
        let probes = discovery::probes();
        AddSource {
            kind: AddKind::Tty,
            field: 0,
            ports,
            port_idx: 0,
            path: TextInput::default(),
            baud: TextInput::new(default_baud.to_string()),
            probes,
            probe_idx: 0,
            chip: TextInput::default(),
            channel: TextInput::new("btmonitor"),
            reset: false,
            error: None,
        }
    }

    /// Number of fields (including the kind selector) for the current kind.
    pub fn field_count(&self) -> usize {
        match self.kind {
            AddKind::Tty => 3,    // kind, port, baud
            AddKind::Rtt => 5,    // kind, probe, chip, channel, reset
            AddKind::File => 2,   // kind, path
            AddKind::Kernel => 1, // kind
        }
    }

    pub fn to_kind(&self) -> Result<SourceKind, String> {
        match self.kind {
            AddKind::Tty => {
                let path = if self.path.value.trim().is_empty() {
                    self.ports.get(self.port_idx).map(|p| p.path.clone()).ok_or("no serial port selected")?
                } else {
                    self.path.value.trim().to_string()
                };
                let baud = self.baud.value.trim().parse::<u32>().map_err(|_| "invalid baud rate")?;
                Ok(SourceKind::Tty { path, baud })
            }
            AddKind::Rtt => {
                let chip = self.chip.value.trim();
                if chip.is_empty() {
                    return Err("chip name is required (e.g. nRF52832_xxAA)".into());
                }
                let probe = self.probes.get(self.probe_idx).map(|p| p.selector.clone());
                let channel = if self.channel.value.trim().is_empty() { None } else { Some(self.channel.value.trim().to_string()) };
                Ok(SourceKind::Rtt { chip: chip.to_string(), probe, channel, reset: self.reset })
            }
            AddKind::File => {
                let path = self.path.value.trim();
                if path.is_empty() {
                    return Err("file path is required".into());
                }
                Ok(SourceKind::File { path: path.to_string() })
            }
            AddKind::Kernel => Ok(SourceKind::Kernel),
        }
    }
}

/// Screen regions from the last draw, for mouse handling.
#[derive(Debug, Clone, Copy, Default)]
pub struct Areas {
    pub list: Rect,
    pub details: Rect,
}

pub struct App {
    pub session: Session,
    pub entries: Vec<Entry>,
    pub visible: Vec<usize>,
    pub filter: Filter,
    pub selected: Option<usize>,
    pub list_offset: usize,
    pub follow: bool,
    pub paused: bool,
    pub focus: Focus,
    pub layout: LayoutMode,
    /// Share of the body given to the packet list, in percent.
    pub split: u16,
    pub time_mode: TimeMode,
    pub show_hex: bool,
    pub details_cursor: usize,
    pub details_offset: usize,
    pub collapsed: HashSet<Vec<usize>>,
    pub collapsed_for: Option<u64>,
    pub popup: Option<Popup>,
    pub search: String,
    pub message: Option<(Instant, String, bool)>,
    pub sources: HashMap<SourceId, SourceInfo>,
    pub areas: Areas,
    pub dropped: u64,
    pub filtered_out: u64,
    /// `(source, controller index, frame)` → session sequence number, for resolving links.
    frame_map: HashMap<(SourceId, u16, u64), u64>,
    known_ports: HashSet<String>,
    last_discovery: Instant,
    should_quit: bool,
    dirty: bool,
    default_baud: u32,
}

impl App {
    pub fn new(session: Session) -> Self {
        let time_mode = session.config.time_mode;
        let default_baud = 115_200;
        let known_ports: HashSet<String> = discovery::serial_ports().into_iter().map(|p| p.device).collect();
        // In the UI the index and priority options seed the interactive filter
        // instead of discarding packets for good.
        let mut session = session;
        let filter = Filter { index: session.config.index.take(), max_priority: session.config.priority.take(), ..Filter::default() };
        App {
            filter,
            session,
            entries: Vec::new(),
            visible: Vec::new(),
            selected: None,
            list_offset: 0,
            follow: true,
            paused: false,
            focus: Focus::List,
            layout: LayoutMode::Bottom,
            split: 55,
            time_mode,
            show_hex: false,
            details_cursor: 0,
            details_offset: 0,
            collapsed: HashSet::new(),
            collapsed_for: None,
            popup: None,
            search: String::new(),
            message: None,
            sources: HashMap::new(),
            areas: Areas::default(),
            dropped: 0,
            filtered_out: 0,
            frame_map: HashMap::new(),
            known_ports,
            last_discovery: Instant::now(),
            should_quit: false,
            dirty: true,
            default_baud,
        }
    }

    pub fn selected_entry(&self) -> Option<&Entry> {
        self.selected.and_then(|i| self.visible.get(i)).map(|&e| &self.entries[e])
    }

    pub fn set_message(&mut self, text: impl Into<String>, is_error: bool) {
        self.message = Some((Instant::now(), text.into(), is_error));
        self.dirty = true;
    }

    fn source_info_mut(&mut self, id: SourceId) -> &mut SourceInfo {
        self.sources.entry(id).or_insert_with(|| SourceInfo { packets: 0, state: SourceState::Running, last_message: String::new() })
    }

    // ----- packet store -----------------------------------------------------------------

    /// Position of the entry with sequence number `seq` in `entries`.
    fn entry_pos(&self, seq: u64) -> Option<usize> {
        self.entries.binary_search_by_key(&seq, |e| e.seq).ok()
    }

    fn push_entry(&mut self, mut entry: Entry) {
        self.source_info_mut(entry.source).packets += 1;
        if entry.decoded.frame > 0 {
            self.frame_map.insert((entry.source, entry.packet.index, entry.decoded.frame), entry.seq);
        }
        // Resolve request/response links to session numbers and tell the request too.
        for link in &entry.decoded.links {
            if link.kind != LinkKind::ResponseTo {
                continue;
            }
            let Some(&req_seq) = self.frame_map.get(&(entry.source, entry.packet.index, link.frame)) else { continue };
            entry.refs.push(Ref { kind: LinkKind::ResponseTo, seq: req_seq, elapsed_us: link.elapsed_us });
            if let Some(pos) = self.entry_pos(req_seq) {
                self.entries[pos].refs.push(Ref { kind: LinkKind::AnsweredBy, seq: entry.seq, elapsed_us: link.elapsed_us });
            }
        }
        let show = self.filter.matches(&entry);
        if !show {
            self.filtered_out += 1;
        }
        self.entries.push(entry);
        if self.entries.len() > self.session.config.max_packets {
            self.drop_oldest(self.session.config.max_packets / 10);
        }
        if show && !self.paused {
            self.visible.push(self.entries.len() - 1);
            if self.follow {
                self.selected = Some(self.visible.len() - 1);
            }
        }
        self.dirty = true;
    }

    fn drop_oldest(&mut self, n: usize) {
        let n = n.min(self.entries.len());
        for e in &self.entries[..n] {
            self.frame_map.remove(&(e.source, e.packet.index, e.decoded.frame));
        }
        self.entries.drain(..n);
        self.dropped += n as u64;
        self.visible.retain(|&i| i >= n);
        for i in &mut self.visible {
            *i -= n;
        }
        if let Some(sel) = self.selected {
            if sel >= self.visible.len() {
                self.selected = if self.visible.is_empty() { None } else { Some(self.visible.len() - 1) };
            }
        }
        // The selection index may now point at a different packet; that is acceptable
        // when the store overflows, following mode keeps the newest one anyway.
    }

    pub fn rebuild_visible(&mut self) {
        let keep_seq = self.selected_entry().map(|e| e.seq);
        self.visible = (0..self.entries.len()).filter(|&i| self.filter.matches(&self.entries[i])).collect();
        self.filtered_out = (self.entries.len() - self.visible.len()) as u64;
        self.selected = match keep_seq {
            Some(seq) => self.visible.iter().position(|&i| self.entries[i].seq >= seq).or_else(|| self.visible.len().checked_sub(1)),
            None => self.visible.len().checked_sub(1),
        };
        if self.follow {
            self.selected = self.visible.len().checked_sub(1);
        }
        self.dirty = true;
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.frame_map.clear();
        self.visible.clear();
        self.selected = None;
        self.list_offset = 0;
        self.filtered_out = 0;
        self.dirty = true;
    }

    // ----- navigation ---------------------------------------------------------------------

    fn move_selection(&mut self, delta: i64) {
        if self.visible.is_empty() {
            self.selected = None;
            return;
        }
        let cur = self.selected.unwrap_or(self.visible.len() - 1) as i64;
        let next = (cur + delta).clamp(0, self.visible.len() as i64 - 1) as usize;
        self.selected = Some(next);
        self.follow = next == self.visible.len() - 1 && delta > 0 && self.follow;
        if delta < 0 {
            self.follow = false;
        }
        self.dirty = true;
    }

    fn select_first(&mut self) {
        if !self.visible.is_empty() {
            self.selected = Some(0);
            self.follow = false;
            self.dirty = true;
        }
    }

    fn select_last(&mut self) {
        self.selected = self.visible.len().checked_sub(1);
        self.follow = true;
        self.dirty = true;
    }

    fn page(&self) -> i64 {
        (self.areas.list.height.saturating_sub(2)).max(1) as i64
    }

    /// Forget the expand/collapse state when a different packet is selected.
    pub fn reset_details(&mut self) {
        let seq = self.selected_entry().map(|e| e.seq);
        if seq != self.collapsed_for {
            self.collapsed.clear();
            self.collapsed_for = seq;
            self.details_cursor = 0;
            self.details_offset = 0;
        }
    }

    fn detail_rows(&self) -> usize {
        match self.selected_entry() {
            Some(e) => 1 + flatten_tree(&e.decoded.fields, &self.collapsed).len() + if self.show_hex { hex_lines(&e.packet.data) } else { 0 },
            None => 0,
        }
    }

    fn toggle_detail_node(&mut self) {
        let Some(e) = self.selected_entry() else { return };
        if self.details_cursor == 0 {
            // Headline row: toggle everything.
            let rows = flatten_tree(&e.decoded.fields, &HashSet::new());
            let all: Vec<Vec<usize>> = rows.iter().filter(|r| r.has_children).map(|r| r.path.clone()).collect();
            if self.collapsed.is_empty() {
                self.collapsed.extend(all);
            } else {
                self.collapsed.clear();
            }
        } else {
            let rows = flatten_tree(&e.decoded.fields, &self.collapsed);
            if let Some(row) = rows.get(self.details_cursor - 1) {
                if row.has_children {
                    let p = row.path.clone();
                    if !self.collapsed.remove(&p) {
                        self.collapsed.insert(p);
                    }
                }
            }
        }
        self.dirty = true;
    }

    /// Path of the tree node under the details cursor, if it can be collapsed
    /// (`expanded == true`) or expanded (`expanded == false`).
    fn cursor_node_path(&self, expanded: bool) -> Option<Vec<usize>> {
        let e = self.selected_entry()?;
        let rows = flatten_tree(&e.decoded.fields, &self.collapsed);
        let row = rows.get(self.details_cursor.checked_sub(1)?)?;
        if row.has_children && row.collapsed != expanded {
            Some(row.path.clone())
        } else {
            None
        }
    }

    /// Restrict the list to one connection handle, or lift that restriction if it is already in place.
    fn follow_handle(&mut self, handle: u16) {
        let expr = format!("handle == {handle}");
        if self.filter.expr.as_ref().map(|q| q.source() == expr).unwrap_or(false) {
            self.filter.expr = None;
            self.rebuild_visible();
            self.set_message("no longer following a connection", false);
            return;
        }
        if let Ok(q) = hcimon_decode::Query::parse(&expr) {
            self.filter.expr = Some(q);
            self.rebuild_visible();
            self.set_message(format!("following connection handle {handle} ({} packets); F again to stop", self.visible.len()), false);
        }
    }

    /// Follow the connection of the selected packet.
    fn follow_selected(&mut self) {
        let Some(e) = self.selected_entry() else { return };
        match conversations::handles_of(e).first() {
            Some(&h) => self.follow_handle(h),
            None => self.set_message("the selected packet is not tied to a connection", false),
        }
    }

    /// Jump to the packet the selected one is linked to (its request or its response).
    fn jump_to_linked(&mut self) {
        let Some(e) = self.selected_entry() else { return };
        let Some(r) = e.refs.first() else {
            self.set_message("no linked request/response for this packet", false);
            return;
        };
        let target = r.seq;
        match self.visible.iter().position(|&i| self.entries[i].seq == target) {
            Some(vi) => {
                self.selected = Some(vi);
                self.follow = false;
                self.dirty = true;
            }
            None if self.entry_pos(target).is_some() => self.set_message(format!("packet {target} is hidden by the current filter"), false),
            None => self.set_message(format!("packet {target} is no longer in memory"), false),
        }
    }

    // ----- search ----------------------------------------------------------------------------

    fn find_next(&mut self, forward: bool) {
        if self.search.is_empty() || self.visible.is_empty() {
            return;
        }
        let n = self.visible.len();
        let start = self.selected.unwrap_or(0);
        for step in 1..=n {
            let i = if forward { (start + step) % n } else { (start + n - step % n) % n };
            let e = &self.entries[self.visible[i]];
            if super::filter::text_matches(e, &self.search) {
                self.selected = Some(i);
                self.follow = false;
                self.dirty = true;
                return;
            }
        }
        self.set_message(format!("no match for \"{}\"", self.search), false);
    }

    // ----- sources ------------------------------------------------------------------------------

    fn add_source(&mut self, kind: SourceKind) {
        let label = kind.label();
        match self.session.add_source(kind) {
            Ok(id) => {
                self.source_info_mut(id);
                self.set_message(format!("added {label}"), false);
            }
            Err(e) => self.set_message(format!("{label}: {e:#}"), true),
        }
    }

    fn remove_source_at(&mut self, cursor: usize) {
        let ids: Vec<SourceId> = self.session.sources().iter().map(|s| s.id).collect();
        if let Some(&id) = ids.get(cursor) {
            let label = self.session.sources().iter().find(|s| s.id == id).map(|s| s.kind.label()).unwrap_or_default();
            self.session.remove_source(id);
            self.sources.remove(&id);
            self.set_message(format!("removed {label}"), false);
        }
    }

    fn poll_discovery(&mut self) {
        if self.last_discovery.elapsed() < DISCOVERY_INTERVAL {
            return;
        }
        self.last_discovery = Instant::now();
        let ports = discovery::serial_ports();
        let now: HashSet<String> = ports.iter().map(|p| p.device.clone()).collect();
        let new: Vec<&SerialCandidate> = ports.iter().filter(|p| !self.known_ports.contains(&p.device)).collect();
        if let Some(p) = new.first() {
            let more = if new.len() > 1 { format!(" (+{} more)", new.len() - 1) } else { String::new() };
            self.set_message(format!("new serial port {}{more} — press 'a' to add it", crate::source::short_path(&p.path)), false);
        }
        self.known_ports = now;
        if let Some(Popup::AddSource(add)) = &mut self.popup {
            if add.kind == AddKind::Tty {
                add.ports = ports;
                add.port_idx = add.port_idx.min(add.ports.len().saturating_sub(1));
                self.dirty = true;
            }
        }
    }

    // ----- source events --------------------------------------------------------------------------

    fn handle_source_event(&mut self, ev: SourceEvent) {
        match ev {
            SourceEvent::Packet { source, packet } => {
                if let Some(entry) = self.session.ingest(source, packet) {
                    self.push_entry(entry);
                }
            }
            SourceEvent::Status { source, message } => {
                // Messages name their source themselves.
                self.source_info_mut(source).last_message = message.clone();
                self.set_message(message, false);
            }
            SourceEvent::Error { source, message } => {
                let label = self.session.sources().iter().find(|s| s.id == source).map(|s| s.kind.label()).unwrap_or_default();
                let info = self.source_info_mut(source);
                info.state = SourceState::Failed;
                info.last_message = message.clone();
                self.set_message(format!("{label}: {message}"), true);
            }
            SourceEvent::Eof { source } => {
                let info = self.source_info_mut(source);
                if info.state == SourceState::Running {
                    info.state = SourceState::Finished;
                }
                self.dirty = true;
            }
        }
    }

    // ----- key handling -------------------------------------------------------------------------------

    fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press && key.kind != KeyEventKind::Repeat {
            return;
        }
        self.dirty = true;
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        if self.popup.is_some() {
            self.handle_popup_key(key);
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') | KeyCode::F(1) => self.popup = Some(Popup::Help),
            KeyCode::Char('/') => self.popup = Some(Popup::Search(TextInput::new(self.search.clone()))),
            KeyCode::Char('e') | KeyCode::Char(':') => {
                let current = self.filter.expr.as_ref().map(|q| q.source().to_string()).unwrap_or_default();
                self.popup = Some(Popup::Expr(TextInput::new(current)));
            }
            KeyCode::Char('n') => self.find_next(true),
            KeyCode::Char('N') => self.find_next(false),
            KeyCode::Char('m') => self.jump_to_linked(),
            KeyCode::Char('F') => self.follow_selected(),
            KeyCode::Char('C') => self.popup = Some(Popup::Conversations { cursor: 0, rows: conversations::collect(&self.entries) }),
            KeyCode::Char('f') => self.popup = Some(Popup::Filter { cursor: 0 }),
            KeyCode::Char('a') => self.popup = Some(Popup::AddSource(AddSource::new(self.default_baud))),
            KeyCode::Char('s') => self.popup = Some(Popup::Sources { cursor: 0 }),
            KeyCode::Char('w') => {
                let default = self.session.config.write.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| "capture.snoop".into());
                self.popup = Some(Popup::Write(TextInput::new(default)));
            }
            KeyCode::Char('c') => self.clear(),
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                if !self.paused {
                    self.rebuild_visible();
                }
            }
            KeyCode::Char('t') => self.time_mode = self.time_mode.next(),
            KeyCode::Char('l') => self.layout = self.layout.next(),
            KeyCode::Char('[') => self.split = self.split.saturating_sub(5).max(20),
            KeyCode::Char(']') => self.split = (self.split + 5).min(80),
            KeyCode::Char('x') => self.show_hex = !self.show_hex,
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::List => Focus::Details,
                    Focus::Details => Focus::List,
                };
                if self.layout == LayoutMode::Hidden {
                    self.layout = LayoutMode::Bottom;
                }
            }
            KeyCode::Esc => {
                if self.focus == Focus::Details {
                    self.focus = Focus::List;
                } else if !self.search.is_empty() {
                    self.search.clear();
                    self.set_message("search cleared", false);
                }
            }
            _ => match self.focus {
                Focus::List => self.handle_list_key(key),
                Focus::Details => self.handle_details_key(key),
            },
        }
    }

    fn handle_list_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-self.page()),
            KeyCode::PageDown => self.move_selection(self.page()),
            KeyCode::Home | KeyCode::Char('g') => self.select_first(),
            KeyCode::End | KeyCode::Char('G') => self.select_last(),
            KeyCode::Enter | KeyCode::Right => {
                if self.selected.is_some() {
                    self.focus = Focus::Details;
                    if self.layout == LayoutMode::Hidden {
                        self.layout = LayoutMode::Bottom;
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_details_key(&mut self, key: KeyEvent) {
        let rows = self.detail_rows();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.details_cursor = self.details_cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.details_cursor = (self.details_cursor + 1).min(rows.saturating_sub(1)),
            KeyCode::PageUp => self.details_cursor = self.details_cursor.saturating_sub(10),
            KeyCode::PageDown => self.details_cursor = (self.details_cursor + 10).min(rows.saturating_sub(1)),
            KeyCode::Home | KeyCode::Char('g') => self.details_cursor = 0,
            KeyCode::End | KeyCode::Char('G') => self.details_cursor = rows.saturating_sub(1),
            KeyCode::Enter | KeyCode::Char(' ') => self.toggle_detail_node(),
            KeyCode::Left => {
                // Collapse the node under the cursor, or go back to the list.
                match self.cursor_node_path(true) {
                    Some(path) => {
                        self.collapsed.insert(path);
                    }
                    None => self.focus = Focus::List,
                }
            }
            KeyCode::Right => {
                if let Some(path) = self.cursor_node_path(false) {
                    self.collapsed.remove(&path);
                }
            }
            _ => {}
        }
    }

    fn handle_popup_key(&mut self, key: KeyEvent) {
        let Some(popup) = self.popup.take() else { return };
        match popup {
            Popup::Help | Popup::Message { .. } => {
                // Any key closes.
            }
            Popup::Search(mut input) => match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    self.search = input.value.trim().to_string();
                    self.find_next(true);
                }
                KeyCode::Tab => {
                    // Apply the text as a filter instead of jumping to matches.
                    self.search = input.value.trim().to_string();
                    self.filter.text = self.search.clone();
                    self.rebuild_visible();
                }
                _ => {
                    input.handle(key);
                    self.popup = Some(Popup::Search(input));
                }
            },
            Popup::Expr(mut input) => match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    let text = input.value.trim().to_string();
                    if text.is_empty() {
                        self.filter.expr = None;
                        self.rebuild_visible();
                    } else {
                        match hcimon_decode::Query::parse(&text) {
                            Ok(q) => {
                                self.filter.expr = Some(q);
                                self.rebuild_visible();
                                self.set_message(format!("filter: {text} ({} of {} shown)", self.visible.len(), self.entries.len()), false);
                            }
                            Err(e) => {
                                self.set_message(format!("filter error: {e}"), true);
                                self.popup = Some(Popup::Expr(input));
                            }
                        }
                    }
                }
                _ => {
                    input.handle(key);
                    self.popup = Some(Popup::Expr(input));
                }
            },
            Popup::Write(mut input) => match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    let path = input.value.trim().to_string();
                    match self.session.start_writing(&path, &self.entries) {
                        Ok(n) => self.set_message(format!("writing to {path} ({n} packets so far)"), false),
                        Err(e) => self.set_message(format!("{path}: {e:#}"), true),
                    }
                }
                _ => {
                    input.handle(key);
                    self.popup = Some(Popup::Write(input));
                }
            },
            Popup::Filter { mut cursor } => {
                let n_items = Category::ALL.len() + LAYERS.len() + 3;
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {}
                    KeyCode::Up | KeyCode::Char('k') => {
                        cursor = cursor.saturating_sub(1);
                        self.popup = Some(Popup::Filter { cursor });
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        cursor = (cursor + 1).min(n_items - 1);
                        self.popup = Some(Popup::Filter { cursor });
                    }
                    KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right => {
                        self.toggle_filter_item(cursor, key.code);
                        self.popup = Some(Popup::Filter { cursor });
                    }
                    KeyCode::Char('r') => {
                        self.filter = Filter::default();
                        self.rebuild_visible();
                        self.popup = Some(Popup::Filter { cursor });
                    }
                    KeyCode::Char(c) => {
                        if let Some(cat) = Category::ALL.iter().find(|x| x.key() == c) {
                            self.filter.toggle_category(*cat);
                            self.rebuild_visible();
                        }
                        self.popup = Some(Popup::Filter { cursor });
                    }
                    _ => self.popup = Some(Popup::Filter { cursor }),
                }
            }
            Popup::Conversations { mut cursor, rows } => match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('C') => {}
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    self.popup = Some(Popup::Conversations { cursor, rows });
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    cursor = (cursor + 1).min(rows.len().saturating_sub(1));
                    self.popup = Some(Popup::Conversations { cursor, rows });
                }
                KeyCode::Enter | KeyCode::Char('F') => {
                    if let Some(c) = rows.get(cursor) {
                        self.follow_handle(c.handle);
                    }
                }
                KeyCode::Char('g') => {
                    // Go to the first packet of the conversation.
                    if let Some(c) = rows.get(cursor) {
                        let target = c.first;
                        if let Some(vi) = self.visible.iter().position(|&i| self.entries[i].seq == target) {
                            self.selected = Some(vi);
                            self.follow = false;
                        }
                    }
                }
                _ => self.popup = Some(Popup::Conversations { cursor, rows }),
            },
            Popup::Sources { mut cursor } => {
                let n = self.session.sources().len();
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('s') => {}
                    KeyCode::Up | KeyCode::Char('k') => {
                        cursor = cursor.saturating_sub(1);
                        self.popup = Some(Popup::Sources { cursor });
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        cursor = (cursor + 1).min(n.saturating_sub(1));
                        self.popup = Some(Popup::Sources { cursor });
                    }
                    KeyCode::Char('a') => self.popup = Some(Popup::AddSource(AddSource::new(self.default_baud))),
                    KeyCode::Char('d') | KeyCode::Delete => {
                        self.remove_source_at(cursor);
                        let n = self.session.sources().len();
                        self.popup = Some(Popup::Sources { cursor: cursor.min(n.saturating_sub(1)) });
                    }
                    KeyCode::Char('o') | KeyCode::Enter => {
                        // Filter the list to this source (toggle).
                        let ids: Vec<SourceId> = self.session.sources().iter().map(|s| s.id).collect();
                        if let Some(&id) = ids.get(cursor) {
                            self.filter.source = if self.filter.source == Some(id) { None } else { Some(id) };
                            self.rebuild_visible();
                        }
                        self.popup = Some(Popup::Sources { cursor });
                    }
                    _ => self.popup = Some(Popup::Sources { cursor }),
                }
            }
            Popup::AddSource(mut add) => {
                match key.code {
                    KeyCode::Esc => {}
                    KeyCode::Enter => match add.to_kind() {
                        Ok(kind) => self.add_source(kind),
                        Err(e) => {
                            add.error = Some(e);
                            self.popup = Some(Popup::AddSource(add));
                        }
                    },
                    KeyCode::Tab | KeyCode::Down => {
                        add.field = (add.field + 1) % add.field_count();
                        self.popup = Some(Popup::AddSource(add));
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        add.field = (add.field + add.field_count() - 1) % add.field_count();
                        self.popup = Some(Popup::AddSource(add));
                    }
                    _ => {
                        add_source_field_key(&mut add, key);
                        self.popup = Some(Popup::AddSource(add));
                    }
                }
            }
        }
        self.dirty = true;
    }

    fn toggle_filter_item(&mut self, cursor: usize, code: KeyCode) {
        let ncat = Category::ALL.len();
        let nlay = LAYERS.len();
        if cursor < ncat {
            self.filter.toggle_category(Category::ALL[cursor]);
        } else if cursor < ncat + nlay {
            self.filter.toggle_layer(LAYERS[cursor - ncat]);
        } else {
            match cursor - ncat - nlay {
                0 => {
                    // Controller index: cycle through the indexes seen.
                    let mut seen: Vec<u16> = self.entries.iter().map(|e| e.packet.index).filter(|&i| i != hcimon_capture::INDEX_NONE).collect();
                    seen.sort_unstable();
                    seen.dedup();
                    self.filter.index = cycle_option(self.filter.index, &seen, code == KeyCode::Left);
                }
                1 => {
                    let ids: Vec<SourceId> = self.session.sources().iter().map(|s| s.id).collect();
                    self.filter.source = cycle_option(self.filter.source, &ids, code == KeyCode::Left);
                }
                _ => {
                    let levels: Vec<u8> = (0..=7).collect();
                    self.filter.max_priority = cycle_option(self.filter.max_priority, &levels, code == KeyCode::Left);
                }
            }
        }
        self.rebuild_visible();
    }

    fn handle_mouse(&mut self, kind: MouseEventKind, column: u16, row: u16) {
        if self.popup.is_some() {
            return;
        }
        let in_list = self.areas.list.contains((column, row).into());
        let in_details = self.areas.details.contains((column, row).into());
        match kind {
            MouseEventKind::ScrollUp => {
                if in_details {
                    self.details_cursor = self.details_cursor.saturating_sub(3);
                } else {
                    self.move_selection(-3);
                }
            }
            MouseEventKind::ScrollDown => {
                if in_details {
                    let rows = self.detail_rows();
                    self.details_cursor = (self.details_cursor + 3).min(rows.saturating_sub(1));
                } else {
                    self.move_selection(3);
                }
            }
            MouseEventKind::Down(_) => {
                if in_list {
                    let line = row.saturating_sub(self.areas.list.y + 1) as usize;
                    let idx = self.list_offset + line;
                    if idx < self.visible.len() {
                        self.selected = Some(idx);
                        self.follow = idx == self.visible.len() - 1;
                        self.focus = Focus::List;
                    }
                } else if in_details {
                    self.focus = Focus::Details;
                    let line = row.saturating_sub(self.areas.details.y + 1) as usize;
                    let idx = self.details_offset + line;
                    if idx < self.detail_rows() {
                        self.details_cursor = idx;
                    }
                }
            }
            _ => return,
        }
        self.dirty = true;
    }

    fn handle_term_event(&mut self, ev: TermEvent) {
        match ev {
            TermEvent::Key(k) => self.handle_key(k),
            TermEvent::Mouse(m) => self.handle_mouse(m.kind, m.column, m.row),
            TermEvent::Resize(_, _) => self.dirty = true,
            _ => {}
        }
    }

    fn tick(&mut self) {
        if let Some((t, _, _)) = &self.message {
            if t.elapsed() > MESSAGE_TTL {
                self.message = None;
                self.dirty = true;
            }
        }
        self.poll_discovery();
        // Sources that stopped silently.
        let ids: Vec<SourceId> = self.session.sources().iter().filter(|s| s.is_finished()).map(|s| s.id).collect();
        for id in ids {
            let info = self.source_info_mut(id);
            if info.state == SourceState::Running {
                info.state = SourceState::Finished;
                self.dirty = true;
            }
        }
    }
}

fn add_source_field_key(add: &mut AddSource, key: KeyEvent) {
    match (add.kind, add.field) {
        (_, 0) => {
            // Kind selector.
            let i = AddKind::ALL.iter().position(|k| *k == add.kind).unwrap_or(0);
            match key.code {
                KeyCode::Left | KeyCode::Char('h') => add.kind = AddKind::ALL[(i + AddKind::ALL.len() - 1) % AddKind::ALL.len()],
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Char(' ') => add.kind = AddKind::ALL[(i + 1) % AddKind::ALL.len()],
                _ => {}
            }
            add.error = None;
        }
        (AddKind::Tty, 1) => match key.code {
            KeyCode::Left => add.port_idx = add.port_idx.saturating_sub(1),
            KeyCode::Right => add.port_idx = (add.port_idx + 1).min(add.ports.len().saturating_sub(1)),
            _ => {
                add.path.handle(key);
            }
        },
        (AddKind::Tty, 2) => {
            add.baud.handle(key);
        }
        (AddKind::Rtt, 1) => match key.code {
            KeyCode::Left => add.probe_idx = add.probe_idx.saturating_sub(1),
            KeyCode::Right | KeyCode::Char(' ') => add.probe_idx = (add.probe_idx + 1).min(add.probes.len().saturating_sub(1)),
            _ => {}
        },
        (AddKind::Rtt, 2) => {
            add.chip.handle(key);
        }
        (AddKind::Rtt, 3) => {
            add.channel.handle(key);
        }
        (AddKind::Rtt, 4) => {
            if matches!(key.code, KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')) {
                add.reset = !add.reset;
            }
        }
        (AddKind::File, 1) => {
            add.path.handle(key);
        }
        _ => {}
    }
}

fn cycle_option<T: Copy + PartialEq>(current: Option<T>, values: &[T], backwards: bool) -> Option<T> {
    if values.is_empty() {
        return None;
    }
    let pos = current.and_then(|c| values.iter().position(|v| *v == c));
    match (pos, backwards) {
        (None, false) => Some(values[0]),
        (None, true) => Some(values[values.len() - 1]),
        (Some(p), false) => {
            if p + 1 < values.len() {
                Some(values[p + 1])
            } else {
                None
            }
        }
        (Some(p), true) => {
            if p == 0 {
                None
            } else {
                Some(values[p - 1])
            }
        }
    }
}

/// Number of lines a hex dump of `data` takes (16 bytes per line).
pub fn hex_lines(data: &[u8]) -> usize {
    data.len().div_ceil(16)
}

/// Run the interactive UI until the user quits.
pub fn run(session: Session, startup_errors: Vec<String>) -> Result<()> {
    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), event::EnableMouseCapture);
    let result = main_loop(&mut terminal, session, startup_errors);
    let _ = execute!(std::io::stdout(), event::DisableMouseCapture);
    ratatui::restore();
    result
}

fn spawn_input_thread(stop: Receiver<()>) -> Receiver<TermEvent> {
    let (tx, rx) = unbounded();
    std::thread::Builder::new()
        .name("input".into())
        .spawn(move || loop {
            if stop.try_recv().is_ok() {
                break;
            }
            match event::poll(Duration::from_millis(100)) {
                Ok(true) => match event::read() {
                    Ok(ev) => {
                        if tx.send(ev).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                Ok(false) => {}
                Err(_) => break,
            }
        })
        .expect("failed to spawn input thread");
    rx
}

fn main_loop(terminal: &mut DefaultTerminal, session: Session, startup_errors: Vec<String>) -> Result<()> {
    let (stop_tx, stop_rx) = unbounded::<()>();
    let term_rx = spawn_input_thread(stop_rx);
    let source_rx = session.receiver().clone();
    let mut app = App::new(session);
    for s in app.session.sources() {
        app.sources.insert(s.id, SourceInfo { packets: 0, state: SourceState::Running, last_message: String::new() });
    }
    if !startup_errors.is_empty() {
        app.popup = Some(Popup::Message { title: "Could not open all sources".into(), text: startup_errors.join("\n") });
    } else if app.session.sources().is_empty() {
        app.popup = Some(Popup::AddSource(AddSource::new(app.default_baud)));
    }

    let mut last_draw = Instant::now() - FRAME_INTERVAL;
    while !app.should_quit {
        if app.dirty && last_draw.elapsed() >= FRAME_INTERVAL {
            terminal.draw(|frame| ui::draw(frame, &mut app))?;
            app.dirty = false;
            last_draw = Instant::now();
        }
        let wait = if app.dirty { FRAME_INTERVAL.saturating_sub(last_draw.elapsed()) } else { Duration::from_millis(100) };
        select! {
            recv(term_rx) -> ev => {
                if let Ok(ev) = ev {
                    app.handle_term_event(ev);
                }
            }
            recv(source_rx) -> ev => {
                if let Ok(ev) = ev {
                    app.handle_source_event(ev);
                    // Batch whatever else is already queued before redrawing.
                    for _ in 0..2000 {
                        match source_rx.try_recv() {
                            Ok(ev) => app.handle_source_event(ev),
                            Err(_) => break,
                        }
                    }
                }
            }
            default(wait) => {}
        }
        app.tick();
    }
    let _ = stop_tx.send(());
    app.session.flush_writer();
    Ok(())
}

impl App {
    /// Timestamp of the packet before the selected one (for delta display).
    pub fn prev_ts(&self, visible_idx: usize) -> Option<Timestamp> {
        visible_idx.checked_sub(1).and_then(|i| self.visible.get(i)).and_then(|&e| self.entries[e].packet.ts)
    }
}
