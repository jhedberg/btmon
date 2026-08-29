//! The field tree that decoders produce and renderers consume.
//!
//! Decoders never print; they append [`Node`]s to an [`Out`] builder.  A text
//! renderer flattens the tree into btmon-style indented lines, while an
//! interactive UI can show it as a collapsible tree.

use std::fmt;

/// Presentation hint for a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Style {
    #[default]
    Normal,
    /// A value that the decoder did not recognise (btmon shows these with a white background).
    Unknown,
    /// A decoding problem: truncated data, malformed lengths, ...
    Error,
    /// Raw bytes (hex dumps).
    Hex,
    /// A section heading such as a protocol layer name.
    Heading,
}

/// One line of decoded output with optional children.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Node {
    pub text: String,
    pub style: Style,
    pub children: Vec<Node>,
}

impl Node {
    pub fn new(text: impl Into<String>) -> Self {
        Node { text: text.into(), style: Style::Normal, children: Vec::new() }
    }

    pub fn styled(text: impl Into<String>, style: Style) -> Self {
        Node { text: text.into(), style, children: Vec::new() }
    }

    /// Total number of nodes in this subtree, including this one.
    pub fn count(&self) -> usize {
        1 + self.children.iter().map(Node::count).sum::<usize>()
    }

    /// Visit every node depth-first with its depth.
    pub fn walk<'a>(&'a self, depth: usize, f: &mut impl FnMut(usize, &'a Node)) {
        f(depth, self);
        for c in &self.children {
            c.walk(depth + 1, f);
        }
    }
}

/// Builder used by decoders to append nodes at the current nesting level.
#[derive(Debug, Default)]
pub struct Out {
    roots: Vec<Node>,
    /// Indices from the root to the node whose children are being appended.
    path: Vec<usize>,
}

impl Out {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume the builder and return the root nodes.
    pub fn finish(self) -> Vec<Node> {
        self.roots
    }

    pub fn roots(&self) -> &[Node] {
        &self.roots
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    fn current_children(&mut self) -> &mut Vec<Node> {
        let mut children = &mut self.roots;
        for &i in &self.path {
            children = &mut children[i].children;
        }
        children
    }

    /// Append a node at the current level.
    pub fn push(&mut self, node: Node) -> &mut Self {
        self.current_children().push(node);
        self
    }

    /// Append a plain line.
    pub fn line(&mut self, text: impl Into<String>) -> &mut Self {
        self.push(Node::new(text))
    }

    /// Append a formatted line; usually invoked through [`field!`](crate::field).
    pub fn field(&mut self, args: fmt::Arguments<'_>) -> &mut Self {
        self.push(Node::new(args.to_string()))
    }

    /// Append a styled line.
    pub fn styled(&mut self, style: Style, text: impl Into<String>) -> &mut Self {
        self.push(Node::styled(text, style))
    }

    /// Append a line flagged as unknown/unrecognised.
    pub fn unknown(&mut self, text: impl Into<String>) -> &mut Self {
        self.styled(Style::Unknown, text)
    }

    /// Append an error line.
    pub fn error(&mut self, text: impl Into<String>) -> &mut Self {
        self.styled(Style::Error, text)
    }

    /// Append a hex dump of `data` (16 bytes per line, btmon style).
    pub fn hex(&mut self, data: &[u8]) -> &mut Self {
        for chunk in data.chunks(16) {
            let mut s = String::with_capacity(16 * 3 + 20);
            for (i, b) in chunk.iter().enumerate() {
                if i > 0 {
                    s.push(' ');
                }
                s.push_str(&format!("{b:02x}"));
            }
            for _ in chunk.len()..16 {
                s.push_str("   ");
            }
            s.push_str("  ");
            for &b in chunk {
                s.push(if (0x20..0x7f).contains(&b) { b as char } else { '.' });
            }
            self.push(Node::styled(s, Style::Hex));
        }
        self
    }

    /// Append a labelled hex dump on one line: `Label: 01 02 03`.
    pub fn hex_field(&mut self, label: &str, data: &[u8]) -> &mut Self {
        let mut s = String::with_capacity(label.len() + 2 + data.len() * 3);
        s.push_str(label);
        s.push(':');
        for b in data {
            s.push_str(&format!(" {b:02x}"));
        }
        self.push(Node::new(s))
    }

    /// Run `f` with the children of the most recently appended node as the current level.
    ///
    /// If nothing has been appended yet at the current level, `f` runs at the current level.
    pub fn nest<R>(&mut self, f: impl FnOnce(&mut Out) -> R) -> R {
        let n = self.current_children().len();
        if n == 0 {
            return f(self);
        }
        self.path.push(n - 1);
        let r = f(self);
        self.path.pop();
        r
    }

    /// Append `text` and then run `f` to append its children.
    pub fn group<R>(&mut self, text: impl Into<String>, f: impl FnOnce(&mut Out) -> R) -> R {
        self.line(text);
        self.nest(f)
    }

    /// Like [`group`](Self::group) but with a style.
    pub fn styled_group<R>(&mut self, style: Style, text: impl Into<String>, f: impl FnOnce(&mut Out) -> R) -> R {
        self.styled(style, text);
        self.nest(f)
    }

    /// Nesting depth of the current level.
    pub fn depth(&self) -> usize {
        self.path.len()
    }
}

/// Append a formatted line to an [`Out`]: `field!(out, "Handle: {}", h)`.
#[macro_export]
macro_rules! field {
    ($out:expr, $($arg:tt)*) => {
        $out.field(format_args!($($arg)*))
    };
}

/// Render nodes as indented text lines.
///
/// `base` is the indentation (in spaces) of the root nodes; every nesting level
/// adds two spaces, matching btmon's layout.
pub fn render_lines(nodes: &[Node], base: usize, mut emit: impl FnMut(usize, &Node)) {
    fn walk(node: &Node, indent: usize, emit: &mut impl FnMut(usize, &Node)) {
        emit(indent, node);
        for c in &node.children {
            walk(c, indent + 2, emit);
        }
    }
    for n in nodes {
        walk(n, base, &mut emit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nesting() {
        let mut out = Out::new();
        field!(out, "Status: {}", "Success");
        out.group("Features", |o| {
            o.line("LE Encryption");
            o.group("Nested", |o| {
                o.line("deep");
            });
        });
        out.line("after");
        let roots = out.finish();
        assert_eq!(roots.len(), 3);
        assert_eq!(roots[1].children.len(), 2);
        assert_eq!(roots[1].children[1].children[0].text, "deep");

        let mut lines = Vec::new();
        render_lines(&roots, 8, |indent, n| lines.push(format!("{}{}", " ".repeat(indent), n.text)));
        assert_eq!(lines[4], "            deep");
    }

    #[test]
    fn hexdump() {
        let mut out = Out::new();
        out.hex(&[0x41, 0x42, 0x00]);
        let text = &out.roots()[0].text;
        assert!(text.starts_with("41 42 00"));
        assert!(text.ends_with("  AB."));
    }
}
