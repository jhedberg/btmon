//! Small UI building blocks: a line editor, popup geometry, tree flattening.

use hcimon_decode::Node;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;

/// Single-line text input with a cursor.
#[derive(Debug, Clone, Default)]
pub struct TextInput {
    pub value: String,
    /// Cursor position in characters.
    pub cursor: usize,
}

impl TextInput {
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        let cursor = value.chars().count();
        TextInput { value, cursor }
    }

    /// Handle an editing key; returns `true` if the key was consumed.
    pub fn handle(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.len(),
            KeyCode::Char('u') if ctrl => {
                let tail: String = self.value.chars().skip(self.cursor).collect();
                self.value = tail;
                self.cursor = 0;
            }
            KeyCode::Char('k') if ctrl => {
                self.value = self.value.chars().take(self.cursor).collect();
            }
            KeyCode::Char('w') if ctrl => {
                let head: Vec<char> = self.value.chars().take(self.cursor).collect();
                let tail: String = self.value.chars().skip(self.cursor).collect();
                let mut n = head.len();
                while n > 0 && head[n - 1] == ' ' {
                    n -= 1;
                }
                while n > 0 && head[n - 1] != ' ' {
                    n -= 1;
                }
                self.value = head[..n].iter().collect::<String>() + &tail;
                self.cursor = n;
            }
            KeyCode::Char(c) if !ctrl => {
                let idx = self.byte_index();
                self.value.insert(idx, c);
                self.cursor += 1;
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    let idx = self.byte_index();
                    self.value.remove(idx);
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.len() {
                    let idx = self.byte_index();
                    self.value.remove(idx);
                }
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.len()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.len(),
            _ => return false,
        }
        true
    }

    pub fn len(&self) -> usize {
        self.value.chars().count()
    }

    fn byte_index(&self) -> usize {
        self.value.char_indices().nth(self.cursor).map(|(i, _)| i).unwrap_or(self.value.len())
    }
}

/// A rectangle of the given size centered in `area` (clamped to it).
pub fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

/// A flattened tree row.
#[derive(Debug, Clone)]
pub struct TreeRow<'a> {
    pub path: Vec<usize>,
    pub depth: usize,
    pub node: &'a Node,
    pub has_children: bool,
    pub collapsed: bool,
}

/// Flatten `nodes` depth-first, skipping the children of collapsed paths.
pub fn flatten_tree<'a>(nodes: &'a [Node], collapsed: &std::collections::HashSet<Vec<usize>>) -> Vec<TreeRow<'a>> {
    fn walk<'a>(nodes: &'a [Node], path: &mut Vec<usize>, depth: usize, collapsed: &std::collections::HashSet<Vec<usize>>, out: &mut Vec<TreeRow<'a>>) {
        for (i, n) in nodes.iter().enumerate() {
            path.push(i);
            let is_collapsed = !n.children.is_empty() && collapsed.contains(path);
            out.push(TreeRow { path: path.clone(), depth, node: n, has_children: !n.children.is_empty(), collapsed: is_collapsed });
            if !is_collapsed {
                walk(&n.children, path, depth + 1, collapsed, out);
            }
            path.pop();
        }
    }
    let mut out = Vec::new();
    walk(nodes, &mut Vec::new(), 0, collapsed, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyEvent;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn text_input_editing() {
        let mut t = TextInput::new("ab");
        assert!(t.handle(key(KeyCode::Char('c'))));
        assert_eq!(t.value, "abc");
        t.handle(key(KeyCode::Left));
        t.handle(key(KeyCode::Backspace));
        assert_eq!(t.value, "ac");
        assert_eq!(t.cursor, 1);
        t.handle(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(t.value, "c");
        assert!(!t.handle(key(KeyCode::F(5))));
    }

    #[test]
    fn tree_flattening_respects_collapsed_paths() {
        let mut root = Node::new("root");
        root.children.push(Node::new("child"));
        let nodes = vec![root, Node::new("sibling")];
        let all = flatten_tree(&nodes, &std::collections::HashSet::new());
        assert_eq!(all.iter().map(|r| r.node.text.as_str()).collect::<Vec<_>>(), ["root", "child", "sibling"]);
        let collapsed: std::collections::HashSet<Vec<usize>> = [vec![0]].into_iter().collect();
        let some = flatten_tree(&nodes, &collapsed);
        assert_eq!(some.iter().map(|r| r.node.text.as_str()).collect::<Vec<_>>(), ["root", "sibling"]);
        assert!(some[0].collapsed);
    }

    #[test]
    fn centered_rect_clamps() {
        let r = centered_rect(Rect::new(0, 0, 10, 10), 40, 4);
        assert_eq!((r.x, r.y, r.width, r.height), (0, 3, 10, 4));
    }
}
