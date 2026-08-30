//! A small terminal emulator for the RTT terminal channel, which carries
//! Zephyr's shell and console: enough of VT100 for a line-oriented shell —
//! carriage return, backspace, erase in line, cursor left/right, save/restore
//! cursor and SGR colours.  Output is kept as styled lines for the UI and
//! handed out as plain text lines for the plain printer.

use std::collections::VecDeque;

/// Colour (0–15, the classic palette) and weight of a cell.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Style {
    pub fg: Option<u8>,
    pub bold: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub style: Style,
}

const BLANK: Cell = Cell { ch: ' ', style: Style { fg: None, bold: false } };

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TermLine {
    pub cells: Vec<Cell>,
}

impl TermLine {
    /// The line as plain text, without trailing blanks.
    pub fn text(&self) -> String {
        let s: String = self.cells.iter().map(|c| c.ch).collect();
        s.trim_end().to_string()
    }
}

enum Esc {
    None,
    Esc,
    Csi(Vec<u8>),
    Osc,
    OscEsc,
    /// Charset designation (`ESC ( B`): one more byte to swallow.
    Charset,
}

/// A grid of lines with a cursor: the last `rows` lines are the screen the
/// cursor can move on, everything before is scrollback.
pub struct Terminal {
    lines: VecDeque<TermLine>,
    scrollback: usize,
    cols: usize,
    rows: usize,
    /// Cursor position: index into `lines`, and column.
    row: usize,
    col: usize,
    /// The last column was written; the next character wraps first.
    pending_wrap: bool,
    saved: Option<(usize, usize)>,
    style: Style,
    /// Bytes of an incomplete UTF-8 sequence, waiting for the rest.
    pending: Vec<u8>,
    esc: Esc,
    record_completed: bool,
    completed: Vec<String>,
}

impl Terminal {
    /// A terminal keeping at most `scrollback` lines, 80 columns by 24 rows
    /// until [`Terminal::set_size`] says otherwise.
    pub fn new(scrollback: usize) -> Self {
        let mut lines = VecDeque::new();
        lines.push_back(TermLine::default());
        Terminal {
            lines,
            scrollback: scrollback.max(2),
            cols: 80,
            rows: 24,
            row: 0,
            col: 0,
            pending_wrap: false,
            saved: None,
            style: Style::default(),
            pending: Vec::new(),
            esc: Esc::None,
            record_completed: false,
            completed: Vec::new(),
        }
    }

    pub fn with_size(mut self, cols: usize, rows: usize) -> Self {
        self.set_size(cols, rows);
        self
    }

    /// Keep the text of every finished line for [`Terminal::take_completed`].
    pub fn recording_completed(mut self) -> Self {
        self.record_completed = true;
        self
    }

    /// Size of the screen; output written from now on wraps at `cols`.
    pub fn set_size(&mut self, cols: usize, rows: usize) {
        self.cols = cols.max(1);
        self.rows = rows.max(1);
        self.col = self.col.min(self.cols - 1);
    }

    pub fn lines(&self) -> &VecDeque<TermLine> {
        &self.lines
    }

    /// `(line, column)` of the cursor.
    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    /// Whether nothing has been written yet.
    pub fn is_empty(&self) -> bool {
        self.lines.len() == 1 && self.lines[0].cells.is_empty()
    }

    /// Lines finished since the last call (only when recording).
    pub fn take_completed(&mut self) -> Vec<String> {
        std::mem::take(&mut self.completed)
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
        let buf = std::mem::take(&mut self.pending);
        let mut rest: &[u8] = &buf;
        while !rest.is_empty() {
            match std::str::from_utf8(rest) {
                Ok(s) => {
                    for c in s.chars() {
                        self.put_char(c);
                    }
                    rest = &[];
                }
                Err(e) => {
                    let (valid, tail) = rest.split_at(e.valid_up_to());
                    for c in std::str::from_utf8(valid).unwrap_or_default().chars() {
                        self.put_char(c);
                    }
                    match e.error_len() {
                        Some(n) => {
                            self.put_char('\u{FFFD}');
                            rest = &tail[n..];
                        }
                        None => {
                            // Incomplete sequence at the end: wait for the rest.
                            self.pending = tail.to_vec();
                            rest = &[];
                        }
                    }
                }
            }
        }
    }

    fn put_char(&mut self, c: char) {
        match std::mem::replace(&mut self.esc, Esc::None) {
            Esc::None => match c {
                '\x1b' => self.esc = Esc::Esc,
                '\r' => {
                    self.col = 0;
                    self.pending_wrap = false;
                }
                '\n' => self.line_feed(),
                '\x08' => {
                    self.col = self.col.saturating_sub(1);
                    self.pending_wrap = false;
                }
                '\t' => {
                    self.col = ((self.col / 8 + 1) * 8).min(self.cols - 1);
                    self.pending_wrap = false;
                }
                c if (c as u32) < 0x20 || c == '\x7f' => {}
                c => self.write(c),
            },
            Esc::Esc => match c {
                '[' => self.esc = Esc::Csi(Vec::new()),
                ']' => self.esc = Esc::Osc,
                '7' => self.saved = Some((self.row, self.col)),
                '8' => self.restore_cursor(),
                'c' => self.reset(),
                '(' | ')' | '*' | '+' => self.esc = Esc::Charset,
                _ => {}
            },
            Esc::Csi(mut params) => {
                let code = c as u32;
                if (0x20..0x40).contains(&code) {
                    if params.len() < 32 {
                        params.push(c as u8);
                    }
                    self.esc = Esc::Csi(params);
                } else if (0x40..0x7f).contains(&code) {
                    self.csi(&params, c);
                }
                // Anything else aborts the sequence.
            }
            Esc::Osc => {
                self.esc = match c {
                    '\x07' => Esc::None,
                    '\x1b' => Esc::OscEsc,
                    _ => Esc::Osc,
                }
            }
            // The character after ESC (normally the '\\' of ST) ends the string.
            Esc::OscEsc => {}
            Esc::Charset => {}
        }
    }

    /// Index of the first line of the screen.
    fn screen_top(&self) -> usize {
        self.lines.len().saturating_sub(self.rows)
    }

    fn line_mut(&mut self) -> &mut TermLine {
        let row = self.row;
        &mut self.lines[row]
    }

    fn write(&mut self, c: char) {
        if self.pending_wrap {
            self.line_feed();
        }
        let cell = Cell { ch: c, style: self.style };
        let col = self.col;
        let line = self.line_mut();
        if line.cells.len() < col {
            line.cells.resize(col, BLANK);
        }
        if col < line.cells.len() {
            line.cells[col] = cell;
        } else {
            line.cells.push(cell);
        }
        if col + 1 >= self.cols {
            self.pending_wrap = true;
        } else {
            self.col += 1;
        }
    }

    /// Move down one line, adding a line at the bottom when the cursor is on
    /// the last one.  Like a tty with ONLCR, this also returns to column 0.
    fn line_feed(&mut self) {
        if self.row + 1 == self.lines.len() {
            if self.record_completed && self.completed.len() < 10_000 {
                let text = self.line_mut().text();
                self.completed.push(text);
            }
            self.lines.push_back(TermLine::default());
            self.row += 1;
            while self.lines.len() > self.scrollback {
                self.lines.pop_front();
                self.row = self.row.saturating_sub(1);
                if let Some(s) = &mut self.saved {
                    s.0 = s.0.saturating_sub(1);
                }
            }
        } else {
            self.row += 1;
        }
        self.col = 0;
        self.pending_wrap = false;
    }

    /// Move the cursor to `row`, adding blank lines when it points below the
    /// last one (but never beyond the screen).
    fn goto_row(&mut self, row: usize) {
        let bottom = self.screen_top() + self.rows - 1;
        let row = row.min(bottom);
        while self.lines.len() <= row {
            self.lines.push_back(TermLine::default());
        }
        self.row = row.min(self.lines.len() - 1);
        self.pending_wrap = false;
    }

    fn restore_cursor(&mut self) {
        if let Some((row, col)) = self.saved {
            self.goto_row(row.min(self.lines.len() - 1));
            self.col = col.min(self.cols - 1);
        }
    }

    fn reset(&mut self) {
        self.lines.clear();
        self.lines.push_back(TermLine::default());
        self.row = 0;
        self.col = 0;
        self.pending_wrap = false;
        self.saved = None;
        self.style = Style::default();
    }

    fn csi(&mut self, params: &[u8], final_byte: char) {
        if params.first() == Some(&b'?') {
            // Private modes (cursor visibility, bracketed paste, ...).
            return;
        }
        let nums: Vec<usize> = params
            .split(|b| *b == b';')
            .map(|p| std::str::from_utf8(p).ok().and_then(|s| s.parse().ok()).unwrap_or(0))
            .collect();
        let n = |i: usize| nums.get(i).copied().unwrap_or(0);
        let n1 = |i: usize| n(i).max(1);
        let col = self.col;
        match final_byte {
            'K' => {
                let line = self.line_mut();
                match n(0) {
                    0 => line.cells.truncate(col),
                    1 => {
                        for cell in line.cells.iter_mut().take(col + 1) {
                            *cell = BLANK;
                        }
                    }
                    2 => line.cells.clear(),
                    _ => {}
                }
            }
            'J' => match n(0) {
                0 => {
                    self.line_mut().cells.truncate(col);
                    let row = self.row;
                    self.lines.truncate(row + 1);
                }
                1 => {
                    let top = self.screen_top();
                    for r in top..self.row {
                        self.lines[r].cells.clear();
                    }
                    for cell in self.line_mut().cells.iter_mut().take(col + 1) {
                        *cell = BLANK;
                    }
                }
                2 | 3 => {
                    let top = self.screen_top();
                    for r in top..self.lines.len() {
                        self.lines[r].cells.clear();
                    }
                }
                _ => {}
            },
            'A' => {
                let top = self.screen_top();
                let row = self.row.saturating_sub(n1(0)).max(top);
                self.goto_row(row);
            }
            'B' => self.goto_row(self.row + n1(0)),
            'C' => {
                self.col = (self.col + n1(0)).min(self.cols - 1);
                self.pending_wrap = false;
            }
            'D' => {
                self.col = self.col.saturating_sub(n1(0));
                self.pending_wrap = false;
            }
            'G' | '`' => {
                self.col = (n1(0) - 1).min(self.cols - 1);
                self.pending_wrap = false;
            }
            'H' | 'f' => {
                let top = self.screen_top();
                self.goto_row(top + n1(0) - 1);
                self.col = (n1(1) - 1).min(self.cols - 1);
            }
            'd' => {
                let top = self.screen_top();
                self.goto_row(top + n1(0) - 1);
            }
            'P' => {
                let line = self.line_mut();
                let end = (col + n1(0)).min(line.cells.len());
                if col < end {
                    line.cells.drain(col..end);
                }
            }
            '@' => {
                let line = self.line_mut();
                if col <= line.cells.len() {
                    for _ in 0..n1(0) {
                        line.cells.insert(col, BLANK);
                    }
                }
            }
            'X' => {
                let line = self.line_mut();
                for cell in line.cells.iter_mut().skip(col).take(n1(0)) {
                    *cell = BLANK;
                }
            }
            's' => self.saved = Some((self.row, self.col)),
            'u' => self.restore_cursor(),
            'm' => self.sgr(&nums),
            _ => {}
        }
    }

    fn sgr(&mut self, nums: &[usize]) {
        let mut i = 0;
        while i < nums.len() {
            match nums[i] {
                0 => self.style = Style::default(),
                1 => self.style.bold = true,
                22 => self.style.bold = false,
                30..=37 => self.style.fg = Some((nums[i] - 30) as u8),
                90..=97 => self.style.fg = Some((nums[i] - 90 + 8) as u8),
                39 => self.style.fg = None,
                38 | 48 => {
                    // Extended colour: 5;n (256 colours) or 2;r;g;b.
                    let skip = match nums.get(i + 1) {
                        Some(5) => 2,
                        Some(2) => 4,
                        _ => 0,
                    };
                    if nums[i] == 38 && skip == 2 {
                        if let Some(&c) = nums.get(i + 2) {
                            if c < 16 {
                                self.style.fg = Some(c as u8);
                            }
                        }
                    }
                    i += skip;
                }
                _ => {}
            }
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(t: &Terminal) -> Vec<String> {
        t.lines().iter().map(|l| l.text()).collect()
    }

    #[test]
    fn lines_and_cursor() {
        let mut t = Terminal::new(10).recording_completed();
        t.feed(b"hello\r\nworld");
        assert_eq!(texts(&t), vec!["hello", "world"]);
        assert_eq!(t.cursor(), (1, 5));
        assert_eq!(t.take_completed(), vec!["hello"]);
        assert!(t.take_completed().is_empty());
    }

    #[test]
    fn scrollback_is_bounded() {
        let mut t = Terminal::new(3);
        t.feed(b"1\n2\n3\n4\n5");
        assert_eq!(texts(&t), vec!["3", "4", "5"]);
    }

    #[test]
    fn zephyr_shell_line_editing() {
        let mut t = Terminal::new(10);
        // Backspace then erase to end of line, as the shell does on backspace.
        t.feed(b"uart:~$ bt inix\x08\x1b[K");
        assert_eq!(texts(&t), vec!["uart:~$ bt ini"]);
        // Redraw of the whole line after completion.
        t.feed(b"\r\x1b[Kuart:~$ bt init");
        assert_eq!(texts(&t), vec!["uart:~$ bt init"]);
        // Cursor left and overwrite.
        t.feed(b"\x1b[4DX");
        assert_eq!(texts(&t), vec!["uart:~$ bt Xnit"]);
        assert_eq!(t.cursor().1, 12);
        // Cursor right past the end pads with blanks.
        t.feed(b"\x1b[5C!");
        assert_eq!(texts(&t), vec!["uart:~$ bt Xnit  !"]);
        // Save / restore the cursor column.
        t.feed(b"\x1b[s\rA\x1b[u?");
        assert_eq!(texts(&t), vec!["Aart:~$ bt Xnit  !?"]);
    }

    #[test]
    fn colours_and_attributes() {
        let mut t = Terminal::new(10);
        t.feed(b"\x1b[1;32muart:~$ \x1b[0mcmd \x1b[91m!\x1b[m.");
        let line = &t.lines()[0];
        assert_eq!(line.text(), "uart:~$ cmd !.");
        assert_eq!(line.cells[0].style, Style { fg: Some(2), bold: true });
        assert_eq!(line.cells[8].style, Style::default());
        assert_eq!(line.cells[12].style, Style { fg: Some(9), bold: false });
        assert_eq!(line.cells[13].style, Style::default());
        // Extended colour sequences are consumed as a whole.
        t.feed(b"\x1b[38;5;3mx\x1b[38;2;1;2;3my");
        assert_eq!(t.lines()[0].cells[14].style.fg, Some(3));
        assert_eq!(t.lines()[0].cells[15].style.fg, Some(3));
    }

    #[test]
    fn clear_screen_and_ignored_sequences() {
        let mut t = Terminal::new(10);
        t.feed(b"one\r\ntwo\x1b[2J\x1b[H");
        // The screen is blanked, not removed, and the cursor goes home.
        assert_eq!(texts(&t), vec!["", ""]);
        assert_eq!(t.cursor(), (0, 0));
        t.feed(b"\x1b[?25la\x1b]0;title\x07b\x1b]0;t2\x1b\\c\x1b[Ad\x07\x1b(Be");
        assert_eq!(texts(&t), vec!["abcde", ""]);
    }

    #[test]
    fn wraps_at_the_width_with_a_pending_wrap() {
        let mut t = Terminal::new(10).with_size(10, 5);
        t.feed(b"abcdefghijkl");
        assert_eq!(texts(&t), vec!["abcdefghij", "kl"]);
        assert_eq!(t.cursor(), (1, 2));
        // Exactly filling a line does not open a blank one before CR LF.
        let mut t = Terminal::new(10).with_size(10, 5);
        t.feed(b"0123456789\r\nX");
        assert_eq!(texts(&t), vec!["0123456789", "X"]);
        assert_eq!(t.cursor(), (1, 1));
    }

    #[test]
    fn shell_repaints_a_wrapped_command_line_around_a_message() {
        // Zephyr's shell, when output arrives while a command is being typed:
        // move to the start of the command (left, then up over the wrapped
        // part), erase to the end of the screen, print the message, then the
        // prompt and the command again.
        let mut t = Terminal::new(50).with_size(10, 5);
        t.feed(b"rtt:~$ bt scan on");
        assert_eq!(texts(&t), vec!["rtt:~$ bt", "scan on"]);
        assert_eq!(t.lines()[0].cells.len(), 10);
        assert_eq!(t.cursor(), (1, 7));
        t.feed(b"\x1b[7D\x1b[1A\x1b[J[DEVICE]\r\nrtt:~$ bt scan on");
        assert_eq!(texts(&t), vec!["[DEVICE]", "rtt:~$ bt", "scan on"]);
        assert_eq!(t.cursor(), (2, 7));
        // Cursor down past the last line adds lines, but not beyond the screen.
        t.feed(b"\x1b[9B");
        assert_eq!(t.lines().len(), 5);
        assert_eq!(t.cursor().0, 4);
    }

    #[test]
    fn utf8_split_across_reads() {
        let mut t = Terminal::new(10);
        t.feed(b"caf\xc3");
        assert_eq!(texts(&t), vec!["caf"]);
        t.feed(b"\xa9!");
        assert_eq!(texts(&t), vec!["café!"]);
        t.feed(b"\xff-");
        assert_eq!(texts(&t), vec!["café!\u{FFFD}-"]);
    }

    #[test]
    fn tabs_delete_and_insert() {
        let mut t = Terminal::new(10);
        t.feed(b"ab\tc");
        assert_eq!(texts(&t), vec!["ab      c"]);
        t.feed(b"\r\x1b[2P");
        assert_eq!(texts(&t), vec!["      c"]);
        t.feed(b"\x1b[2@xy");
        assert_eq!(texts(&t), vec!["xy      c"]);
        t.feed(b"\x1b[3X");
        assert_eq!(texts(&t), vec!["xy      c"]);
        t.feed(b"\r\x1b[9X");
        assert_eq!(texts(&t), vec![""]);
    }
}
