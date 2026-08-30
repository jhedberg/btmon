//! Rendering of the interactive UI.

use hcimon_decode::{Decoded, Opcode, Style as NodeStyle};
use hcimon_capture::INDEX_NONE;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Sparkline, Wrap};
use ratatui::Frame;

use super::app::{AddKind, App, Focus, LayoutMode, Popup, SourceState};
use super::filter::{Category, LAYERS};
use super::widgets::{centered_rect, flatten_tree, TextInput};
use crate::source::short_path;
use crate::terminal::TermLine;
use crate::time::{format_delta, format_time, TimeMode};

/// btmon's colour for a packet.
pub fn packet_color(d: &Decoded) -> Style {
    if d.unknown {
        return Style::default().fg(Color::Black).bg(Color::White);
    }
    let c = match d.opcode {
        Opcode::NewIndex | Opcode::OpenIndex | Opcode::IndexInfo => Color::Green,
        Opcode::DelIndex | Opcode::CloseIndex => Color::Red,
        Opcode::Command => Color::Blue,
        Opcode::Event => Color::Magenta,
        Opcode::AclTx | Opcode::AclRx => Color::Cyan,
        Opcode::ScoTx | Opcode::ScoRx | Opcode::IsoTx | Opcode::IsoRx | Opcode::VendorDiag => Color::Yellow,
        Opcode::CtrlOpen => Color::LightGreen,
        Opcode::CtrlClose => Color::LightRed,
        Opcode::CtrlCommand => Color::LightBlue,
        Opcode::CtrlEvent => Color::LightMagenta,
        Opcode::SystemNote | Opcode::UserLogging | Opcode::Unknown(_) => Color::Reset,
    };
    let s = Style::default().fg(c);
    if matches!(d.opcode, Opcode::CtrlOpen | Opcode::CtrlClose | Opcode::CtrlCommand | Opcode::CtrlEvent) {
        s.add_modifier(Modifier::BOLD)
    } else {
        s
    }
}

fn node_style(style: NodeStyle) -> Style {
    match style {
        NodeStyle::Normal => Style::default(),
        NodeStyle::Unknown => Style::default().fg(Color::Black).bg(Color::White),
        NodeStyle::Error => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        NodeStyle::Hex => Style::default().fg(Color::DarkGray),
        NodeStyle::Heading => Style::default().add_modifier(Modifier::BOLD),
    }
}

pub fn draw(frame: &mut Frame, app: &mut App) {
    app.reset_details();
    let area = frame.area();
    let [header, body, status] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1), Constraint::Length(1)]).areas(area);

    draw_header(frame, app, header);

    // The shell pane takes the bottom of the body when shown.
    let (body, shell_area) = if app.shell_visible {
        let h = (body.height * 35 / 100).max(5).min(body.height.saturating_sub(4)).max(1);
        let [b, s] = Layout::vertical([Constraint::Fill(1), Constraint::Length(h)]).areas(body);
        (b, s)
    } else {
        (body, Rect::default())
    };
    app.areas.shell = shell_area;

    let (list_area, details_area) = match app.layout {
        LayoutMode::Hidden => (body, Rect::default()),
        LayoutMode::Bottom => {
            let [l, d] = Layout::vertical([Constraint::Percentage(app.split), Constraint::Percentage(100 - app.split)]).areas(body);
            (l, d)
        }
        LayoutMode::Right => {
            let [l, d] = Layout::horizontal([Constraint::Percentage(app.split), Constraint::Percentage(100 - app.split)]).areas(body);
            (l, d)
        }
    };
    app.areas.list = list_area;
    app.areas.details = details_area;

    draw_list(frame, app, list_area);
    if app.layout != LayoutMode::Hidden {
        draw_details(frame, app, details_area);
    }
    if app.shell_visible {
        draw_shell(frame, app, shell_area);
    }
    draw_status(frame, app, status);

    if let Some(popup) = app.popup.clone() {
        draw_popup(frame, app, &popup, area);
    }
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![Span::styled(" hcimon ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Black).bg(Color::Cyan)), Span::raw(" ")];
    let sources = app.session.sources();
    if sources.is_empty() {
        spans.push(Span::styled("no sources", Style::default().fg(Color::DarkGray)));
    }
    for (i, s) in sources.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        let (dot, color) = match app.sources.get(&s.id).map(|i| i.state) {
            Some(SourceState::Running) | None => ("●", Color::Green),
            Some(SourceState::Finished) => ("○", Color::DarkGray),
            Some(SourceState::Failed) => ("✖", Color::Red),
        };
        let count = app.sources.get(&s.id).map(|i| i.packets).unwrap_or(0);
        spans.push(Span::styled(dot, Style::default().fg(color)));
        spans.push(Span::raw(format!(" {} ({count})", s.kind.label())));
    }
    let mut right = format!("{} pkts", app.entries.len());
    if app.filtered_out > 0 {
        right.push_str(&format!(" · {} hidden", app.filtered_out));
    }
    if app.dropped > 0 {
        right.push_str(&format!(" · {} dropped", app.dropped));
    }
    let (errs, warns, _) = app.expert_counts();
    if errs > 0 || warns > 0 {
        right.push_str(&format!(" · {errs} err {warns} warn (!)"));
    }
    let rate = app.live_rate();
    if rate > 0 {
        right.push_str(&format!(" · {rate} pkt/s"));
    }
    if app.paused {
        right.push_str(" · PAUSED");
    } else if app.follow {
        right.push_str(" · follow");
    }
    right.push_str(&format!(" · time:{}", app.time_mode.name()));
    right.push(' ');
    let left_len: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let pad = (area.width as usize).saturating_sub(left_len + right.chars().count());
    spans.push(Span::raw(" ".repeat(pad)));
    spans.push(Span::styled(right, Style::default().fg(Color::DarkGray)));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_list(frame: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.focus == Focus::List;
    let title = if app.filter.is_active() { format!(" Packets [{}] ", app.filter.describe()) } else { " Packets ".to_string() };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(if focused { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) });
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let height = inner.height as usize;
    if height == 0 || inner.width == 0 {
        return;
    }
    let total = app.visible.len();
    // Keep the selection within the window.
    if let Some(sel) = app.selected {
        if sel < app.list_offset {
            app.list_offset = sel;
        } else if sel >= app.list_offset + height {
            app.list_offset = sel + 1 - height;
        }
    }
    if app.list_offset + height > total {
        app.list_offset = total.saturating_sub(height);
    }
    let multi_source = app.session.sources().len() > 1;
    let first_ts = app.session.first_ts;
    let width = inner.width as usize;

    let mut items = Vec::with_capacity(height);
    let end = (app.list_offset + height).min(total);
    for vi in app.list_offset..end {
        let e = &app.entries[app.visible[vi]];
        let d = &e.decoded;
        let mut spans = Vec::with_capacity(6);
        spans.push(Span::styled(format!("{:>6} ", e.seq), Style::default().fg(Color::DarkGray)));
        let ts = e.packet.ts.and_then(|t| format_time(t, first_ts, app.time_mode)).unwrap_or_default();
        if app.time_mode != TimeMode::None {
            spans.push(Span::styled(format!("{ts:>12} "), Style::default().fg(Color::Yellow)));
        }
        if multi_source {
            let label = app.session.sources().iter().find(|s| s.id == e.source).map(|s| short_label(&s.kind.label())).unwrap_or_default();
            spans.push(Span::styled(format!("{label:<8} "), Style::default().fg(Color::DarkGray)));
        }
        if e.packet.index != INDEX_NONE {
            spans.push(Span::styled(format!("hci{} ", e.packet.index), Style::default().fg(Color::DarkGray)));
        } else {
            spans.push(Span::raw("     "));
        }
        let style = packet_color(d);
        let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
        let mut head = d.headline();
        let room = width.saturating_sub(used);
        if head.chars().count() > room && room > 1 {
            head = head.chars().take(room - 1).collect::<String>() + "…";
        }
        spans.push(Span::styled(head, style));
        items.push(ListItem::new(Line::from(spans)));
    }
    let mut state = ListState::default();
    state.select(app.selected.map(|s| s.saturating_sub(app.list_offset)));
    let list = List::new(items).highlight_style(if focused {
        Style::default().bg(Color::Rgb(40, 40, 60)).add_modifier(Modifier::BOLD)
    } else {
        Style::default().bg(Color::Rgb(30, 30, 40))
    });
    frame.render_stateful_widget(list, inner, &mut state);

    if total == 0 {
        let msg = if app.entries.is_empty() && app.session.sources().is_empty() {
            "No sources. Press 'a' to add a serial port, RTT channel or capture file."
        } else if app.entries.is_empty() {
            "Waiting for packets…"
        } else {
            "No packets match the current filter (press 'f' to change it)."
        };
        let p = Paragraph::new(msg).style(Style::default().fg(Color::DarkGray)).wrap(Wrap { trim: true });
        frame.render_widget(p, centered_rect(inner, msg.len().min(inner.width as usize) as u16, 2));
    }
}

fn short_label(label: &str) -> String {
    truncate(label, 8)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n.saturating_sub(1)).collect::<String>() + "…"
    }
}

fn draw_details(frame: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.focus == Focus::Details;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Details ")
        .border_style(if focused { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) });
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 {
        return;
    }

    let Some(sel) = app.selected else {
        frame.render_widget(Paragraph::new("Select a packet to see its fields.").style(Style::default().fg(Color::DarkGray)), inner);
        return;
    };
    let prev_ts = app.prev_ts(sel);
    let e = &app.entries[app.visible[sel]];
    let d = &e.decoded;

    let mut lines: Vec<Line> = Vec::new();
    // Headline with trailer.
    let mut trailer = String::new();
    if d.frame > 0 {
        trailer.push_str(&format!(" #{}", d.frame));
    }
    if e.packet.index != INDEX_NONE {
        trailer.push_str(&format!(" [hci{}]", e.packet.index));
    }
    if let Some(ts) = e.packet.ts {
        if let Some(t) = format_time(ts, app.session.first_ts, if app.time_mode == TimeMode::None { TimeMode::Offset } else { app.time_mode }) {
            trailer.push(' ');
            trailer.push_str(&t);
        }
        let delta = format_delta(ts, prev_ts);
        if !delta.is_empty() {
            trailer.push_str(&format!(" ({delta})"));
        }
    }
    lines.push(Line::from(vec![Span::styled(d.headline(), packet_color(d).add_modifier(Modifier::BOLD)), Span::styled(trailer, Style::default().fg(Color::Yellow))]));
    for f in &e.findings {
        let color = match f.severity {
            hcimon_decode::Severity::Error => Color::Red,
            hcimon_decode::Severity::Warning => Color::Yellow,
            hcimon_decode::Severity::Note => Color::Cyan,
        };
        lines.push(Line::from(Span::styled(format!("  ⚠ {}", f.text), Style::default().fg(color))));
    }
    for r in &e.refs {
        let arrow = if r.kind.is_back_reference() { "↩" } else { "↪" };
        let what = r.what();
        let rtt = r.elapsed_text();
        let text = if rtt.is_empty() { format!("  {arrow} {what} packet {}  (m: jump)", r.seq) } else { format!("  {arrow} {what} packet {}, {rtt}  (m: jump)", r.seq) };
        lines.push(Line::from(Span::styled(text, Style::default().fg(Color::Green))));
    }

    let rows = flatten_tree(&d.fields, &app.collapsed);
    for row in &rows {
        let marker = if row.has_children {
            if row.collapsed {
                "▸ "
            } else {
                "▾ "
            }
        } else {
            "  "
        };
        let indent = " ".repeat(2 + row.depth * 2);
        lines.push(Line::from(vec![Span::raw(indent), Span::styled(marker, Style::default().fg(Color::DarkGray)), Span::styled(row.node.text.clone(), node_style(row.node.style))]));
    }
    if app.show_hex {
        lines.push(Line::from(Span::styled("  Raw packet:", Style::default().add_modifier(Modifier::BOLD))));
        for chunk in e.packet.data.chunks(16) {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            let ascii: String = chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
            lines.push(Line::from(Span::styled(format!("    {:<47}  {}", hex.join(" "), ascii), Style::default().fg(Color::DarkGray))));
        }
    }

    let total = lines.len();
    let height = inner.height as usize;
    if app.details_cursor >= total {
        app.details_cursor = total.saturating_sub(1);
    }
    if app.details_cursor < app.details_offset {
        app.details_offset = app.details_cursor;
    } else if app.details_cursor >= app.details_offset + height {
        app.details_offset = app.details_cursor + 1 - height;
    }
    if app.details_offset + height > total {
        app.details_offset = total.saturating_sub(height);
    }
    let visible: Vec<Line> = lines.into_iter().skip(app.details_offset).take(height).collect();
    let items: Vec<ListItem> = visible.into_iter().map(ListItem::new).collect();
    let mut state = ListState::default();
    if focused {
        state.select(Some(app.details_cursor.saturating_sub(app.details_offset)));
    }
    let list = List::new(items).highlight_style(Style::default().bg(Color::Rgb(40, 40, 60)));
    frame.render_stateful_widget(list, inner, &mut state);
}

/// The target's shell / console (RTT terminal channel) of the selected source.
fn draw_shell(frame: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.focus == Focus::Shell;
    let label = app
        .shell_source
        .and_then(|id| app.session.sources().iter().find(|s| s.id == id).map(|s| s.kind.label()))
        .unwrap_or_else(|| "no source".to_string());
    let hint = if focused { "keys go to the target · Esc: back · PgUp/PgDn: history" } else { "Tab or click: type here · T: hide" };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Shell: {label} · {hint} "))
        .border_style(if focused { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) });
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let dim = Style::default().fg(Color::DarkGray);
    let Some(term) = app.shell_source.and_then(|id| app.terminals.get_mut(&id)) else {
        let text = if app.shell_source.is_some() {
            " no output yet: Tab here and press Enter for a prompt"
        } else {
            " no source with a shell channel — add an RTT source (a) whose Zephyr shell runs over RTT (CONFIG_SHELL_BACKEND_RTT=y)"
        };
        frame.render_widget(Paragraph::new(Span::styled(text, dim)).wrap(Wrap { trim: false }), inner);
        return;
    };
    let height = inner.height as usize;
    term.set_size(inner.width as usize, height);
    let total = term.lines().len();
    let scroll = app.shell_scroll.min(total.saturating_sub(height));
    let end = total - scroll;
    let start = end.saturating_sub(height);
    let lines: Vec<Line<'static>> = term.lines().iter().skip(start).take(end - start).map(|l| term_line(l, inner.width as usize)).collect();
    let (cursor_row, cursor_col) = term.cursor();
    app.shell_scroll = scroll;
    frame.render_widget(Paragraph::new(lines), inner);
    if focused && scroll == 0 && cursor_row >= start {
        let x = inner.x + (cursor_col as u16).min(inner.width.saturating_sub(1));
        let y = inner.y + (cursor_row - start) as u16;
        frame.set_cursor_position((x, y));
    }
}

fn term_line(line: &TermLine, width: usize) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut text = String::new();
    let mut style = None;
    for cell in line.cells.iter().take(width) {
        if style != Some(cell.style) {
            if let Some(s) = style {
                spans.push(Span::styled(std::mem::take(&mut text), term_style(s)));
            }
            style = Some(cell.style);
        }
        text.push(cell.ch);
    }
    if let Some(s) = style {
        spans.push(Span::styled(text, term_style(s)));
    }
    Line::from(spans)
}

fn term_style(s: crate::terminal::Style) -> Style {
    const PALETTE: [Color; 16] = [
        Color::Black,
        Color::Red,
        Color::Green,
        Color::Yellow,
        Color::Blue,
        Color::Magenta,
        Color::Cyan,
        Color::Gray,
        Color::DarkGray,
        Color::LightRed,
        Color::LightGreen,
        Color::LightYellow,
        Color::LightBlue,
        Color::LightMagenta,
        Color::LightCyan,
        Color::White,
    ];
    let mut style = Style::default();
    if let Some(fg) = s.fg {
        style = style.fg(PALETTE[(fg as usize) % 16]);
    }
    if s.bold {
        style = style.add_modifier(Modifier::BOLD);
    }
    style
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let line = match &app.message {
        Some((_, text, is_error)) => {
            let style = if *is_error { Style::default().fg(Color::Red).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Yellow) };
            Line::from(Span::styled(format!(" {text}"), style))
        }
        None => {
            let keys = [
                ("q", "quit"),
                ("?", "help"),
                ("/", "search"),
                ("e", "expr"),
                ("m", "linked"),
                ("F", "follow"),
                ("C", "conns"),
                ("!", "expert"),
                ("S", "stats"),
                ("f", "filter"),
                ("a", "add source"),
                ("s", "sources"),
                ("w", "write"),
                ("space", "pause"),
                ("t", "time"),
                ("l", "layout"),
                ("x", "hex"),
                ("T", "shell"),
                ("Tab", "focus"),
            ];
            let mut spans = Vec::new();
            for (k, v) in keys {
                spans.push(Span::styled(format!(" {k}"), Style::default().fg(Color::Black).bg(Color::Gray)));
                spans.push(Span::raw(format!(" {v} ")));
            }
            if !app.search.is_empty() {
                spans.push(Span::styled(format!(" search:\"{}\" (n/N)", app.search), Style::default().fg(Color::Yellow)));
            }
            Line::from(spans)
        }
    };
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_popup(frame: &mut Frame, app: &App, popup: &Popup, area: Rect) {
    match popup {
        Popup::Help => {
            let text = HELP_TEXT;
            let h = (text.lines().count() + 2) as u16;
            let w = (text.lines().map(|l| l.chars().count()).max().unwrap_or(40) + 4) as u16;
            let rect = centered_rect(area, w, h);
            frame.render_widget(Clear, rect);
            frame.render_widget(Paragraph::new(text).block(Block::bordered().title(" Keys (any key to close) ")), rect);
        }
        Popup::Message { title, text } => {
            let h = (text.lines().count() + 3) as u16;
            let w = (text.lines().map(|l| l.chars().count()).max().unwrap_or(40).min(area.width as usize - 4) + 4) as u16;
            let rect = centered_rect(area, w, h);
            frame.render_widget(Clear, rect);
            frame.render_widget(
                Paragraph::new(text.as_str()).wrap(Wrap { trim: false }).block(Block::bordered().title(format!(" {title} ")).border_style(Style::default().fg(Color::Red))),
                rect,
            );
        }
        Popup::Search(input) => draw_input(frame, area, " Search (Enter: find next · Tab: apply as filter · Esc: cancel) ", input),
        Popup::Write(input) => draw_input(frame, area, " Write btsnoop file ", input),
        Popup::Expr(input) => draw_input(frame, area, " Filter expression — e.g. att && handle == 0x1c · status != Success · rssi < -70 · !log  (empty clears) ", input),
        Popup::Filter { cursor } => draw_filter(frame, app, area, *cursor),
        Popup::Sources { cursor } => draw_sources(frame, app, area, *cursor),
        Popup::Conversations { cursor, rows } => draw_conversations(frame, app, area, *cursor, rows),
        Popup::Expert { cursor } => draw_expert(frame, app, area, *cursor),
        Popup::Stats(stats) => draw_stats(frame, area, stats),
        Popup::AddSource(add) => draw_add_source(frame, area, add),
    }
}

fn draw_input(frame: &mut Frame, area: Rect, title: &str, input: &TextInput) {
    let rect = centered_rect(area, (area.width * 3 / 4).clamp(30, 90), 3);
    frame.render_widget(Clear, rect);
    let block = Block::bordered().title(title);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    frame.render_widget(Paragraph::new(input.value.as_str()), inner);
    let x = inner.x + input.cursor.min(inner.width.saturating_sub(1) as usize) as u16;
    frame.set_cursor_position((x, inner.y));
}

fn draw_filter(frame: &mut Frame, app: &App, area: Rect, cursor: usize) {
    let mut lines: Vec<Line> = Vec::new();
    let mut row = 0usize;
    let mark = |on: bool| if on { "[x]" } else { "[ ]" };
    lines.push(Line::from(Span::styled("Packet types (space/letter toggles)", Style::default().add_modifier(Modifier::BOLD))));
    for c in Category::ALL {
        let style = if row == cursor { Style::default().bg(Color::Rgb(40, 40, 60)) } else { Style::default() };
        lines.push(Line::from(Span::styled(format!(" {} {} ({})", mark(app.filter.has_category(c)), c.name(), c.key()), style)));
        row += 1;
    }
    lines.push(Line::from(Span::styled("Require protocol layer (any of the checked)", Style::default().add_modifier(Modifier::BOLD))));
    for l in LAYERS {
        let style = if row == cursor { Style::default().bg(Color::Rgb(40, 40, 60)) } else { Style::default() };
        lines.push(Line::from(Span::styled(format!(" {} {}", mark(app.filter.layers.contains(&l)), l.name()), style)));
        row += 1;
    }
    lines.push(Line::from(Span::styled("Other (←/→ cycle)", Style::default().add_modifier(Modifier::BOLD))));
    let others = [
        format!(" Controller index: {}", app.filter.index.map(|i| format!("hci{i}")).unwrap_or_else(|| "any".into())),
        format!(
            " Source: {}",
            app.filter.source.and_then(|id| app.session.sources().iter().find(|s| s.id == id).map(|s| s.kind.label())).unwrap_or_else(|| "any".into())
        ),
        format!(" Max log priority: {}", app.filter.max_priority.map(|p| p.to_string()).unwrap_or_else(|| "any".into())),
    ];
    for o in others {
        let style = if row == cursor { Style::default().bg(Color::Rgb(40, 40, 60)) } else { Style::default() };
        lines.push(Line::from(Span::styled(o, style)));
        row += 1;
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(" r: reset all   /: text search filter   Esc: close", Style::default().fg(Color::DarkGray))));
    let h = (lines.len() + 2) as u16;
    let rect = centered_rect(area, 60, h);
    frame.render_widget(Clear, rect);
    frame.render_widget(Paragraph::new(lines).block(Block::bordered().title(" Filter ")), rect);
}

fn draw_sources(frame: &mut Frame, app: &App, area: Rect, cursor: usize) {
    let mut lines: Vec<Line> = Vec::new();
    if app.session.sources().is_empty() {
        lines.push(Line::from(Span::styled(" (no sources)", Style::default().fg(Color::DarkGray))));
    }
    for (i, s) in app.session.sources().iter().enumerate() {
        let info = app.sources.get(&s.id);
        let (state, color) = match info.map(|i| i.state) {
            Some(SourceState::Running) | None => ("running", Color::Green),
            Some(SourceState::Finished) => ("finished", Color::DarkGray),
            Some(SourceState::Failed) => ("failed", Color::Red),
        };
        let count = info.map(|i| i.packets).unwrap_or(0);
        let msg = info.map(|i| i.last_message.clone()).unwrap_or_default();
        let filtered = if app.filter.source == Some(s.id) { " (filter)" } else { "" };
        let style = if i == cursor { Style::default().bg(Color::Rgb(40, 40, 60)) } else { Style::default() };
        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", s.id), style.fg(Color::DarkGray)),
            Span::styled(format!("{:<30} ", truncate(&s.kind.label(), 30)), style),
            Span::styled(format!("{state:<9}"), style.fg(color)),
            Span::styled(format!("{count:>8} pkts{filtered}"), style),
        ]));
        if !msg.is_empty() {
            lines.push(Line::from(Span::styled(format!("      {msg}"), Style::default().fg(Color::DarkGray))));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(" a: add   d: remove   Enter: filter list to source   Esc: close", Style::default().fg(Color::DarkGray))));
    let h = (lines.len() + 2) as u16;
    let rect = centered_rect(area, 78, h);
    frame.render_widget(Clear, rect);
    frame.render_widget(Paragraph::new(lines).block(Block::bordered().title(" Sources ")), rect);
}

fn draw_conversations(frame: &mut Frame, app: &App, area: Rect, cursor: usize, rows: &[crate::conversations::Conversation]) {
    let multi = app.session.sources().len() > 1;
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        format!(" {:<6} {:<24} {:>6} {:>6} {:>9} {:>8} {:>8}  {}", "Handle", "Peer", "TX", "RX", "Bytes", "First", "Last", "State"),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    if rows.is_empty() {
        lines.push(Line::from(Span::styled(" (no connections seen yet)", Style::default().fg(Color::DarkGray))));
    }
    for (i, c) in rows.iter().enumerate() {
        let style = if i == cursor { Style::default().bg(Color::Rgb(40, 40, 60)) } else { Style::default() };
        let mut handle = format!("{}", c.handle);
        if multi {
            handle = format!("{}/{}", c.source, handle);
        }
        let peer = truncate(if c.peer.is_empty() { "?" } else { &c.peer }, 24);
        let state = if c.open { "open" } else { "closed" };
        lines.push(Line::from(vec![
            Span::styled(format!(" {handle:<6} {peer:<24} {:>6} {:>6} {:>9} {:>8} {:>8}  ", c.tx, c.rx, c.bytes, c.first, c.last), style),
            Span::styled(state, style.fg(if c.open { Color::Green } else { Color::DarkGray })),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(" Enter/F: follow this connection (filter)   g: go to first packet   Esc: close", Style::default().fg(Color::DarkGray))));
    let h = (lines.len() + 2) as u16;
    let rect = centered_rect(area, 92, h);
    frame.render_widget(Clear, rect);
    frame.render_widget(Paragraph::new(lines).block(Block::bordered().title(" Conversations ")), rect);
}

fn draw_stats(frame: &mut Frame, area: Rect, s: &crate::stats::Stats) {
    use crate::stats::span_text;
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::DarkGray);
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(format!(" {} packets", s.total), bold),
        Span::styled(format!("  over {}", span_text(s.span_us)), dim),
        Span::styled(format!("   {} errors, {} warnings, {} notes", s.findings.0, s.findings.1, s.findings.2), dim),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(" By type", bold)));
    for (name, n, bytes) in &s.kinds {
        lines.push(Line::from(format!("   {name:<16} {n:>7}   {bytes:>9} B")));
    }
    if !s.layers.is_empty() {
        lines.push(Line::from(Span::styled(" Protocols", bold)));
        let l: Vec<String> = s.layers.iter().map(|(n, c)| format!("{n} {c}")).collect();
        lines.push(Line::from(format!("   {}", l.join("  ·  "))));
    }
    if s.answered > 0 {
        lines.push(Line::from(Span::styled(" Request/response", bold)));
        lines.push(Line::from(format!("   {} answered   avg {:.3} ms   max {:.3} ms", s.answered, s.avg_rtt_ms, s.max_rtt_ms)));
    }
    let cols = [("Commands", &s.top_commands), ("Events", &s.top_events), ("ATT", &s.top_att)];
    let rows = cols.iter().map(|(_, v)| v.len()).max().unwrap_or(0);
    if rows > 0 {
        lines.push(Line::from(Span::styled(format!(" {:<38}{:<38}{}", "Top commands", "Top events", "Top ATT"), bold)));
        for i in 0..rows {
            let cell = |v: &Vec<(String, u64)>| v.get(i).map(|(n, c)| format!("{:>5} {}", c, truncate(n, 30))).unwrap_or_default();
            lines.push(Line::from(format!(" {:<38}{:<38}{}", cell(cols[0].1), cell(cols[1].1), cell(cols[2].1))));
        }
    }
    lines.push(Line::from(""));
    let max = s.rate.iter().copied().max().unwrap_or(0);
    lines.push(Line::from(Span::styled(
        format!(" Packets over time ({} per bar, peak {} per bar)", span_text(s.bucket_us), max),
        bold,
    )));
    let spark_h = 4u16;
    let h = (lines.len() as u16 + spark_h + 3).min(area.height);
    let rect = centered_rect(area, area.width.saturating_sub(6).min(118), h);
    frame.render_widget(Clear, rect);
    let block = Block::bordered().title(" Statistics (any key to close) ");
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let [text_area, spark_area] = Layout::vertical([Constraint::Length(lines.len() as u16), Constraint::Length(spark_h)]).areas(inner);
    frame.render_widget(Paragraph::new(lines), text_area);
    let spark = Sparkline::default().data(&s.rate).style(Style::default().fg(Color::Cyan));
    frame.render_widget(spark, Rect { x: spark_area.x + 3, width: spark_area.width.saturating_sub(4), ..spark_area });
}

fn draw_expert(frame: &mut Frame, app: &App, area: Rect, cursor: usize) {
    let height = (area.height.saturating_sub(6)).clamp(6, 30) as usize;
    let total = app.experts.len();
    let offset = cursor.saturating_sub(height - 1).min(total.saturating_sub(height));
    let mut lines: Vec<Line> = Vec::new();
    let (errs, warns, notes) = app.expert_counts();
    lines.push(Line::from(vec![
        Span::styled(format!(" {errs} errors"), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  {warns} warnings"), Style::default().fg(Color::Yellow)),
        Span::styled(format!("  {notes} notes"), Style::default().fg(Color::Cyan)),
    ]));
    if total == 0 {
        lines.push(Line::from(Span::styled(" nothing to report", Style::default().fg(Color::DarkGray))));
    }
    for (i, (seq, severity)) in app.experts.iter().enumerate().skip(offset).take(height) {
        let style = if i == cursor { Style::default().bg(Color::Rgb(40, 40, 60)) } else { Style::default() };
        let color = match severity {
            hcimon_decode::Severity::Error => Color::Red,
            hcimon_decode::Severity::Warning => Color::Yellow,
            hcimon_decode::Severity::Note => Color::Cyan,
        };
        let text = app
            .entries
            .binary_search_by_key(seq, |e| e.seq)
            .ok()
            .and_then(|p| app.entries[p].findings.first().map(|f| f.text.clone()))
            .unwrap_or_default();
        lines.push(Line::from(vec![
            Span::styled(format!(" {seq:>6} "), style.fg(Color::DarkGray)),
            Span::styled(format!("{:<7} ", severity.name()), style.fg(color)),
            Span::styled(truncate(&text, (area.width as usize).saturating_sub(24)), style),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(" Enter: go to packet   f: filter to findings   Esc: close", Style::default().fg(Color::DarkGray))));
    let h = (lines.len() + 2) as u16;
    let rect = centered_rect(area, area.width.saturating_sub(6).min(120), h);
    frame.render_widget(Clear, rect);
    frame.render_widget(Paragraph::new(lines).block(Block::bordered().title(" Expert info ")), rect);
}

fn draw_add_source(frame: &mut Frame, area: Rect, add: &super::app::AddSource) {
    let hl = |active: bool| if active { Style::default().bg(Color::Rgb(40, 40, 60)) } else { Style::default() };
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(" Type:    ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(format!("◂ {} ▸", add.kind.name()), hl(add.field == 0)),
    ]));
    lines.push(Line::from(""));
    match add.kind {
        AddKind::Tty => {
            let port = add.ports.get(add.port_idx);
            let port_text = match port {
                Some(p) => format!("◂ {} ▸  {}", short_path(&p.path), p.description),
                None => "(no serial ports found)".to_string(),
            };
            lines.push(Line::from(vec![Span::styled(" Port:    ", Style::default().add_modifier(Modifier::BOLD)), Span::styled(port_text, hl(add.field == 1))]));
            lines.push(Line::from(vec![
                Span::raw("          or type a path: "),
                Span::styled(if add.path.value.is_empty() { "—".to_string() } else { add.path.value.clone() }, hl(add.field == 1)),
            ]));
            lines.push(Line::from(vec![Span::styled(" Baud:    ", Style::default().add_modifier(Modifier::BOLD)), Span::styled(add.baud.value.clone(), hl(add.field == 2))]));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(" Zephyr: CONFIG_BT_DEBUG_MONITOR_UART=y (the monitor stream replaces the console UART)", Style::default().fg(Color::DarkGray))));
        }
        AddKind::Rtt => {
            let probe_text = match add.probes.get(add.probe_idx) {
                Some(p) => format!("◂ {} ▸  {}", p.name, p.serial.as_deref().unwrap_or("")),
                None => "(no debug probes found)".to_string(),
            };
            lines.push(Line::from(vec![Span::styled(" Probe:   ", Style::default().add_modifier(Modifier::BOLD)), Span::styled(probe_text, hl(add.field == 1))]));
            lines.push(Line::from(vec![
                Span::styled(" Chip:    ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(if add.chip.value.is_empty() { "e.g. nRF52832_xxAA".to_string() } else { add.chip.value.clone() }, hl(add.field == 2)),
            ]));
            lines.push(Line::from(vec![Span::styled(" Channel: ", Style::default().add_modifier(Modifier::BOLD)), Span::styled(add.channel.value.clone(), hl(add.field == 3))]));
            lines.push(Line::from(vec![
                Span::styled(" Reset:   ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(if add.reset { "[x] reset the target after attaching (capture from boot)" } else { "[ ] reset the target after attaching (capture from boot)" }, hl(add.field == 4)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(" Zephyr: CONFIG_USE_SEGGER_RTT=y + CONFIG_BT_DEBUG_MONITOR_RTT=y; chip names as in `probe-rs chip list`.", Style::default().fg(Color::DarkGray))));
            lines.push(Line::from(Span::styled(" A shell over RTT (CONFIG_SHELL_BACKEND_RTT=y) shows up in the shell pane (T).", Style::default().fg(Color::DarkGray))));
        }
        AddKind::File => {
            lines.push(Line::from(vec![Span::styled(" Path:    ", Style::default().add_modifier(Modifier::BOLD)), Span::styled(add.path.value.clone(), hl(add.field == 1))]));
        }
        AddKind::Kernel => {
            lines.push(Line::from(Span::styled(" Reads HCI_CHANNEL_MONITOR like BlueZ btmon (needs CAP_NET_RAW).", Style::default().fg(Color::DarkGray))));
        }
    }
    lines.push(Line::from(""));
    if let Some(err) = &add.error {
        lines.push(Line::from(Span::styled(format!(" {err}"), Style::default().fg(Color::Red))));
    }
    lines.push(Line::from(Span::styled(" Tab/↑↓: next field   ←/→: change selection   Enter: add   Esc: cancel", Style::default().fg(Color::DarkGray))));
    let h = (lines.len() + 2) as u16;
    let rect = centered_rect(area, 88, h);
    frame.render_widget(Clear, rect);
    let block = Block::bordered().title(" Add source ");
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    frame.render_widget(Paragraph::new(lines), inner);
    // Place the terminal cursor in the active text field.
    let (line_idx, input): (Option<usize>, Option<&TextInput>) = match (add.kind, add.field) {
        (AddKind::Tty, 1) => (Some(3), Some(&add.path)),
        (AddKind::Tty, 2) => (Some(4), Some(&add.baud)),
        (AddKind::Rtt, 2) => (Some(3), Some(&add.chip)),
        (AddKind::Rtt, 3) => (Some(4), Some(&add.channel)),
        (AddKind::File, 1) => (Some(2), Some(&add.path)),
        _ => (None, None),
    };
    if let (Some(li), Some(input)) = (line_idx, input) {
        let prefix = match (add.kind, add.field) {
            (AddKind::Tty, 1) => 26,
            _ => 10,
        };
        let x = inner.x + prefix + input.cursor as u16;
        frame.set_cursor_position((x.min(inner.right().saturating_sub(1)), inner.y + li as u16));
    }
}

const HELP_TEXT: &str = "\
Navigation
  ↑/↓ j/k        select packet          PgUp/PgDn   page
  Home/End g/G   first / last (End resumes following new packets)
  Enter/→        open details           Tab         cycle list / details / shell
  ←              collapse / back        Enter/space toggle node in details
  m              jump to the linked request / response (round-trip time in details)
  F              follow the selected packet's connection (again to stop)
  C              conversations: every connection handle with peer, counts, state
  !              expert info: errors, non-success statuses, rejects, disconnects
  S              statistics: packets by type, top commands/events/ATT, rates, RTT

Display
  t              cycle time display: offset, wall time, date, none
  l              cycle layout: details bottom / right / hidden
  [ / ]          shrink / grow the packet list pane
  x              show raw packet bytes  space       pause the list
  c              clear captured packets

Filtering
  /              search headline and fields (n/N next/previous)
                 Tab in the search box applies the text as a filter
  e or :         filter expression: att && handle == 0x1c, status != Success,
                 opcode == 'LE Set Scan Enable', rssi < -70, !log, error, ...
  f              filter dialog: packet types, protocol layers, index, source

Sources
  a              add a serial port, RTT channel, file or kernel socket
  s              list sources, remove one, filter by source
  w              write everything captured to a btsnoop file

Shell (Zephyr's shell or console over the RTT terminal channel)
  T              show / hide the shell pane (it opens by itself on the first output)
  Tab or click   move the keyboard into the shell; Esc gives it back to the packet list
  PgUp/PgDn      scroll the shell's history (the mouse wheel works too)

Mouse: scroll and click in both panes.";
