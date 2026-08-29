//! Display-filter expressions over decoded packets.
//!
//! The language is a small subset of Wireshark's:
//!
//! ```text
//! att && handle == 0x001c
//! status != Success
//! address == 4B:65:27:2E:1D:6E || name contains "Heart"
//! (kind == event && event == "Command Complete") || opcode == "LE Set Scan Enable"
//! rssi < -70
//! !log && !(smp || sdp)
//! ```
//!
//! Field names are the labels of decoded lines, lower-cased with spaces and
//! punctuation turned into `_` (`Peer address` is `peer_address`, or quoted:
//! `"peer address"`).  A packet may have several values for one field (e.g.
//! `handle` in Number Of Completed Packets); `==`, `<`, ... hold if any value
//! satisfies them, `!=` holds if the field is present and no value equals.
//! Values are numbers (decimal, `0x` hex, or with a fraction), quoted or bare
//! strings (compared case-insensitively against the name part of an
//! enumeration such as `Success (0x00)`, or the whole text), and addresses.
//!
//! Packet-level fields: `frame` (session sequence number), `kind`
//! (command, event, acl, sco, iso, index, log, control, vendor),
//! `dir` (tx, rx), `index` (controller index), `source`, `opcode`, `event`,
//! `subevent`, `len`, `drops`, `ident` and `prio` (user logging), `text`
//! (headline and every field), `headline`, and `error` (the packet has a
//! decoding problem).  Layer names (`hci`, `l2cap`, `att`, `smp`, `sdp`,
//! `rfcomm`, `avdtp`, `avctp`, `mgmt`, `log`) are true when present.

use std::fmt;

use hcimon_capture::{Opcode, Packet, INDEX_NONE};

use crate::tree::{Node, Style};
use crate::{Decoded, Layer};

// ---------------------------------------------------------------------------
// Field index

/// A value extracted from a decoded line.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldValue {
    /// The text after the label.
    pub text: String,
    /// The name part of `Name (0x..)` style values, otherwise the text.
    pub name: String,
    /// The first number in the text (decimal, hex or with a fraction).
    pub num: Option<f64>,
    /// The raw value given in parentheses, `Name (0x0018)` → 0x18.
    pub raw: Option<u64>,
}

impl FieldValue {
    pub fn parse(text: &str) -> Self {
        let text = text.trim().to_string();
        let name = match text.find(" (") {
            Some(i) if text.ends_with(')') => text[..i].to_string(),
            _ => text.clone(),
        };
        let raw = text.rfind("(0x").and_then(|i| {
            let hex = &text[i + 3..];
            let hex = &hex[..hex.find(')')?];
            match hex.split_once("|0x") {
                // HCI opcodes are printed as `(0xOGF|0xOCF)`.
                Some((ogf, ocf)) => Some((u64::from_str_radix(ogf, 16).ok()? << 10) | u64::from_str_radix(ocf, 16).ok()?),
                None => u64::from_str_radix(hex, 16).ok(),
            }
        });
        let num = first_number(&text);
        FieldValue { text, name, num, raw }
    }

    pub fn from_number(n: u64) -> Self {
        FieldValue { text: n.to_string(), name: n.to_string(), num: Some(n as f64), raw: Some(n) }
    }

    pub fn from_text(s: impl Into<String>) -> Self {
        let text = s.into();
        FieldValue { name: text.clone(), num: first_number(&text), raw: None, text }
    }
}

/// First number in `s`: `0x..` hex, or decimal with optional sign and fraction.
fn first_number(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'0' && i + 1 < b.len() && (b[i + 1] == b'x' || b[i + 1] == b'X') {
            let start = i + 2;
            let mut end = start;
            while end < b.len() && b[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end > start {
                return u64::from_str_radix(&s[start..end], 16).ok().map(|v| v as f64);
            }
        }
        if b[i].is_ascii_digit() || ((b[i] == b'-' || b[i] == b'+') && i + 1 < b.len() && b[i + 1].is_ascii_digit()) {
            let start = i;
            let mut end = i + 1;
            while end < b.len() && (b[end].is_ascii_digit() || b[end] == b'.') {
                end += 1;
            }
            // A hex string like `4c68...` or an address should not be read as a number:
            // require the token to end at a non-alphanumeric boundary.
            if end < b.len() && (b[end].is_ascii_alphabetic() || b[end] == b':') {
                i = end;
                continue;
            }
            return s[start..end].trim_end_matches('.').parse::<f64>().ok();
        }
        i += 1;
    }
    None
}

/// Normalise a label into a field key: lower-case, runs of non-alphanumerics become `_`.
pub fn normalize_key(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    let mut sep = false;
    for c in label.chars() {
        if c.is_alphanumeric() {
            if sep && !out.is_empty() {
                out.push('_');
            }
            sep = false;
            out.extend(c.to_lowercase());
        } else {
            sep = true;
        }
    }
    out
}

/// Metadata about a packet that is not part of [`Decoded`].
#[derive(Debug, Clone, Copy)]
pub struct PacketMeta<'a> {
    /// Session-wide sequence number.
    pub seq: u64,
    pub source: &'a str,
}

/// All fields of a packet, ready for evaluation.
#[derive(Debug, Clone, Default)]
pub struct FieldIndex {
    fields: Vec<(String, FieldValue)>,
    flags: Vec<&'static str>,
    text: String,
}

impl FieldIndex {
    pub fn build(d: &Decoded, pkt: &Packet, meta: PacketMeta<'_>) -> Self {
        let mut ix = FieldIndex::default();
        let mut text = d.headline();
        let mut has_error = d.unknown;
        for n in &d.fields {
            n.walk(0, &mut |_, node| {
                text.push('\n');
                text.push_str(&node.text);
                if matches!(node.style, Style::Error | Style::Unknown) {
                    has_error = true;
                }
                ix.add_node(node);
            });
        }
        ix.text = text;

        ix.push("frame", FieldValue::from_number(meta.seq));
        ix.push("source", FieldValue::from_text(meta.source));
        if pkt.index != INDEX_NONE {
            ix.push("index", FieldValue::from_number(pkt.index as u64));
        }
        ix.push("len", FieldValue::from_number(pkt.data.len() as u64));
        ix.push("drops", FieldValue::from_number(pkt.drops as u64));
        ix.push("headline", FieldValue::from_text(d.headline()));
        let kind = match pkt.opcode {
            Opcode::Command => "command",
            Opcode::Event => "event",
            Opcode::AclTx | Opcode::AclRx => "acl",
            Opcode::ScoTx | Opcode::ScoRx => "sco",
            Opcode::IsoTx | Opcode::IsoRx => "iso",
            Opcode::UserLogging => "log",
            Opcode::CtrlOpen | Opcode::CtrlClose | Opcode::CtrlCommand | Opcode::CtrlEvent => "control",
            Opcode::VendorDiag => "vendor",
            Opcode::SystemNote => "note",
            _ => "index",
        };
        ix.push("kind", FieldValue::from_text(kind));
        let dir = match d.prefix {
            '<' => Some("tx"),
            '>' => Some("rx"),
            _ => None,
        };
        if let Some(dir) = dir {
            ix.push("dir", FieldValue::from_text(dir));
        }
        match pkt.opcode {
            Opcode::Command => ix.push("opcode", FieldValue::parse(&d.summary)),
            Opcode::Event => {
                ix.push("event", FieldValue::parse(&d.summary));
                // Command Complete / Status name the completed opcode in the first line;
                // LE Meta names the subevent there.
                if let Some(first) = d.fields.first() {
                    if d.summary.starts_with("LE Meta") {
                        ix.push("subevent", FieldValue::parse(&first.text));
                    } else if d.summary.starts_with("Command Complete") || d.summary.starts_with("Command Status") {
                        let t = first.text.split(" ncmd").next().unwrap_or(&first.text);
                        ix.push("opcode", FieldValue::parse(t));
                    }
                }
            }
            Opcode::UserLogging => {
                ix.push("ident", FieldValue::from_text(&d.label));
                if let Some(p) = d.priority {
                    ix.push("prio", FieldValue::from_number(p as u64));
                }
                ix.push("message", FieldValue::from_text(&d.summary));
            }
            _ => {}
        }
        for l in &d.layers {
            ix.flags.push(layer_key(*l));
        }
        if has_error {
            ix.flags.push("error");
        }
        ix
    }

    fn add_node(&mut self, node: &Node) {
        if node.style == Style::Hex {
            return;
        }
        let Some(i) = node.text.find(": ") else { return };
        let label = &node.text[..i];
        if label.is_empty() || label.len() > 48 || label.chars().any(|c| c == '(' || c == ')') {
            return;
        }
        let value = &node.text[i + 2..];
        self.push_owned(normalize_key(label), FieldValue::parse(value));
        // `Handle: 3 Address: XX:..` carries a second field.
        if let Some(j) = value.find(" Address: ") {
            self.push_owned("address".into(), FieldValue::parse(&value[j + 10..]));
        }
    }

    fn push(&mut self, key: &str, v: FieldValue) {
        self.fields.push((key.to_string(), v));
    }

    fn push_owned(&mut self, key: String, v: FieldValue) {
        self.fields.push((key, v));
    }

    /// Values of a field (possibly several).
    pub fn get<'a>(&'a self, key: &str) -> impl Iterator<Item = &'a FieldValue> + 'a {
        let key = key.to_string();
        self.fields.iter().filter(move |(k, _)| *k == key).map(|(_, v)| v)
    }

    pub fn has(&self, key: &str) -> bool {
        self.flags.contains(&key) || self.fields.iter().any(|(k, _)| k == key)
    }

    pub fn is_flag(&self, key: &str) -> bool {
        self.flags.contains(&key)
    }

    /// Headline and all field lines, for substring search.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// All `(key, value)` pairs.
    pub fn fields(&self) -> &[(String, FieldValue)] {
        &self.fields
    }
}

fn layer_key(l: Layer) -> &'static str {
    match l {
        Layer::Hci => "hci",
        Layer::L2cap => "l2cap",
        Layer::Att => "att",
        Layer::Smp => "smp",
        Layer::Sdp => "sdp",
        Layer::Rfcomm => "rfcomm",
        Layer::Avdtp => "avdtp",
        Layer::Avctp => "avctp",
        Layer::Mgmt => "mgmt",
        Layer::UserLogging => "log",
    }
}

// ---------------------------------------------------------------------------
// Expressions

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Number(f64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Present(String),
    Compare(String, Op, Literal),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

/// A parsed filter expression.
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    expr: Expr,
    source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub position: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at position {}", self.message, self.position)
    }
}

impl std::error::Error for ParseError {}

impl Query {
    pub fn parse(src: &str) -> Result<Query, ParseError> {
        let tokens = tokenize(src)?;
        let mut p = Parser { tokens, pos: 0 };
        if p.peek().is_none() {
            return Err(ParseError { message: "empty expression".into(), position: 0 });
        }
        let expr = p.expr()?;
        if let Some(t) = p.peek() {
            return Err(ParseError { message: format!("unexpected {}", t.describe()), position: t.pos });
        }
        Ok(Query { expr, source: src.trim().to_string() })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn expr(&self) -> &Expr {
        &self.expr
    }

    pub fn matches(&self, ix: &FieldIndex) -> bool {
        eval(&self.expr, ix)
    }
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

fn eval(e: &Expr, ix: &FieldIndex) -> bool {
    match e {
        Expr::Present(k) => ix.has(k),
        Expr::Not(x) => !eval(x, ix),
        Expr::And(a, b) => eval(a, ix) && eval(b, ix),
        Expr::Or(a, b) => eval(a, ix) || eval(b, ix),
        Expr::Compare(k, op, lit) => {
            if k == "text" {
                return compare_text(ix.text(), *op, lit);
            }
            if ix.is_flag(k) {
                // `att == true` style tests on presence flags.
                return match lit {
                    Literal::Text(t) => matches!(*op, Op::Eq) == t.eq_ignore_ascii_case("true"),
                    Literal::Number(n) => matches!(*op, Op::Eq) == (*n != 0.0),
                };
            }
            let mut any = false;
            let mut all_ne = true;
            for v in ix.get(k) {
                any = true;
                let eq = value_eq(v, lit);
                if eq {
                    all_ne = false;
                }
                let hit = match op {
                    Op::Eq => eq,
                    Op::Ne => false,
                    Op::Contains => match lit {
                        Literal::Text(t) => contains_ci(&v.text, t),
                        Literal::Number(n) => v.num == Some(*n) || v.raw.map(|r| r as f64) == Some(*n),
                    },
                    Op::Lt | Op::Le | Op::Gt | Op::Ge => {
                        let Literal::Number(n) = lit else { return false };
                        let Some(x) = v.num.or(v.raw.map(|r| r as f64)) else { continue };
                        match op {
                            Op::Lt => x < *n,
                            Op::Le => x <= *n,
                            Op::Gt => x > *n,
                            _ => x >= *n,
                        }
                    }
                };
                if hit {
                    return true;
                }
            }
            *op == Op::Ne && any && all_ne
        }
    }
}

fn compare_text(text: &str, op: Op, lit: &Literal) -> bool {
    let s = match lit {
        Literal::Text(t) => t.clone(),
        Literal::Number(n) => n.to_string(),
    };
    match op {
        Op::Contains | Op::Eq => contains_ci(text, &s),
        Op::Ne => !contains_ci(text, &s),
        _ => false,
    }
}

fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(&needle.to_lowercase())
}

fn value_eq(v: &FieldValue, lit: &Literal) -> bool {
    match lit {
        Literal::Number(n) => v.raw.map(|r| r as f64) == Some(*n) || v.num == Some(*n),
        Literal::Text(t) => {
            v.name.eq_ignore_ascii_case(t)
                || v.text.eq_ignore_ascii_case(t)
                // Addresses may carry a suffix: `4B:65:27:2E:1D:6E (Resolvable)`.
                || (looks_like_address(t) && v.text.to_ascii_uppercase().starts_with(&t.to_ascii_uppercase()))
        }
    }
}

fn looks_like_address(s: &str) -> bool {
    s.len() == 17 && s.bytes().enumerate().all(|(i, b)| if i % 3 == 2 { b == b':' } else { b.is_ascii_hexdigit() })
}

// ---------------------------------------------------------------------------
// Tokenizer / parser

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Num(f64),
    Op(Op),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

#[derive(Debug, Clone)]
struct Token {
    tok: Tok,
    pos: usize,
}

impl Token {
    fn describe(&self) -> String {
        match &self.tok {
            Tok::Ident(s) => format!("`{s}`"),
            Tok::Str(s) => format!("\"{s}\""),
            Tok::Num(n) => n.to_string(),
            Tok::Op(_) => "operator".into(),
            Tok::And => "`&&`".into(),
            Tok::Or => "`||`".into(),
            Tok::Not => "`!`".into(),
            Tok::LParen => "`(`".into(),
            Tok::RParen => "`)`".into(),
        }
    }
}

fn tokenize(src: &str) -> Result<Vec<Token>, ParseError> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let pos = i;
        let two = if i + 1 < b.len() { &src[i..i + 2] } else { "" };
        let tok = match two {
            "&&" => {
                i += 2;
                Tok::And
            }
            "||" => {
                i += 2;
                Tok::Or
            }
            "==" => {
                i += 2;
                Tok::Op(Op::Eq)
            }
            "!=" => {
                i += 2;
                Tok::Op(Op::Ne)
            }
            "<=" => {
                i += 2;
                Tok::Op(Op::Le)
            }
            ">=" => {
                i += 2;
                Tok::Op(Op::Ge)
            }
            _ => match c {
                b'(' => {
                    i += 1;
                    Tok::LParen
                }
                b')' => {
                    i += 1;
                    Tok::RParen
                }
                b'!' => {
                    i += 1;
                    Tok::Not
                }
                b'<' => {
                    i += 1;
                    Tok::Op(Op::Lt)
                }
                b'>' => {
                    i += 1;
                    Tok::Op(Op::Gt)
                }
                b'=' => {
                    i += 1;
                    Tok::Op(Op::Eq)
                }
                b'~' => {
                    i += 1;
                    Tok::Op(Op::Contains)
                }
                b'"' | b'\'' => {
                    let quote = c;
                    let start = i + 1;
                    let mut end = start;
                    while end < b.len() && b[end] != quote {
                        end += 1;
                    }
                    if end >= b.len() {
                        return Err(ParseError { message: "unterminated string".into(), position: pos });
                    }
                    i = end + 1;
                    Tok::Str(src[start..end].to_string())
                }
                _ => {
                    // Bare word: identifier, number, address, or keyword.
                    let start = i;
                    while i < b.len() && !b[i].is_ascii_whitespace() && !b"()!<>=&|~\"'".contains(&b[i]) {
                        i += 1;
                    }
                    let word = &src[start..i];
                    match word.to_ascii_lowercase().as_str() {
                        "and" => Tok::And,
                        "or" => Tok::Or,
                        "not" => Tok::Not,
                        "contains" => Tok::Op(Op::Contains),
                        "eq" => Tok::Op(Op::Eq),
                        "ne" => Tok::Op(Op::Ne),
                        "lt" => Tok::Op(Op::Lt),
                        "le" => Tok::Op(Op::Le),
                        "gt" => Tok::Op(Op::Gt),
                        "ge" => Tok::Op(Op::Ge),
                        _ => match parse_number(word) {
                            Some(n) => Tok::Num(n),
                            None => Tok::Ident(word.to_string()),
                        },
                    }
                }
            },
        };
        out.push(Token { tok, pos });
    }
    Ok(out)
}

fn parse_number(w: &str) -> Option<f64> {
    if let Some(h) = w.strip_prefix("0x").or_else(|| w.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok().map(|v| v as f64);
    }
    if w.chars().next().map(|c| c.is_ascii_digit() || c == '-').unwrap_or(false) && !w.contains(':') {
        return w.parse::<f64>().ok();
    }
    None
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn end_pos(&self) -> usize {
        self.tokens.last().map(|t| t.pos + 1).unwrap_or(0)
    }

    fn expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.and()?;
        while matches!(self.peek().map(|t| &t.tok), Some(Tok::Or)) {
            self.next();
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.unary()?;
        while matches!(self.peek().map(|t| &t.tok), Some(Tok::And)) {
            self.next();
            let right = self.unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek().map(|t| &t.tok), Some(Tok::Not)) {
            self.next();
            let inner = self.unary()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, ParseError> {
        let Some(t) = self.next() else {
            return Err(ParseError { message: "expected a field name".into(), position: self.end_pos() });
        };
        match t.tok {
            Tok::LParen => {
                let e = self.expr()?;
                match self.next() {
                    Some(Token { tok: Tok::RParen, .. }) => Ok(e),
                    Some(other) => Err(ParseError { message: format!("expected `)`, found {}", other.describe()), position: other.pos }),
                    None => Err(ParseError { message: "expected `)`".into(), position: self.end_pos() }),
                }
            }
            Tok::Ident(name) | Tok::Str(name) => {
                let key = normalize_key(&name);
                match self.peek().map(|t| t.tok.clone()) {
                    Some(Tok::Op(op)) => {
                        self.next();
                        let lit = match self.next() {
                            Some(Token { tok: Tok::Num(n), .. }) => Literal::Number(n),
                            Some(Token { tok: Tok::Str(s), .. }) | Some(Token { tok: Tok::Ident(s), .. }) => Literal::Text(s),
                            Some(other) => {
                                return Err(ParseError { message: format!("expected a value, found {}", other.describe()), position: other.pos })
                            }
                            None => return Err(ParseError { message: "expected a value".into(), position: self.end_pos() }),
                        };
                        Ok(Expr::Compare(key, op, lit))
                    }
                    _ => Ok(Expr::Present(key)),
                }
            }
            Tok::Num(_) => Err(ParseError { message: "a comparison must start with a field name".into(), position: t.pos }),
            _ => Err(ParseError { message: format!("unexpected {}", t.describe()), position: t.pos }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Context;
    use crate::decode;

    fn index(pkt: &Packet) -> FieldIndex {
        let mut ctx = Context::new();
        let d = decode(&mut ctx, pkt);
        FieldIndex::build(&d, pkt, PacketMeta { seq: 7, source: "test" })
    }

    fn q(s: &str) -> Query {
        Query::parse(s).unwrap()
    }

    #[test]
    fn values() {
        let v = FieldValue::parse("Success (0x00)");
        assert_eq!(v.name, "Success");
        assert_eq!(v.raw, Some(0));
        let v = FieldValue::parse("30.000 msec (0x0018)");
        assert_eq!(v.num, Some(30.0));
        assert_eq!(v.raw, Some(0x18));
        let v = FieldValue::parse("-45 dBm (0xd3)");
        assert_eq!(v.num, Some(-45.0));
        let v = FieldValue::parse("4B:65:27:2E:1D:6E (Resolvable)");
        assert_eq!(v.num, None);
        assert_eq!(normalize_key("Peer address type"), "peer_address_type");
        assert_eq!(normalize_key("16-bit Service UUIDs (complete)"), "16_bit_service_uuids_complete");
    }

    #[test]
    fn parsing() {
        assert!(Query::parse("").is_err());
        assert!(Query::parse("handle ==").is_err());
        assert!(Query::parse("(att").is_err());
        assert!(Query::parse("== 3").is_err());
        let e = q("att && (handle == 0x1c || status != Success) and not smp");
        assert!(matches!(e.expr(), Expr::And(..)));
        let e = q("\"peer address\" == 4B:65:27:2E:1D:6E");
        assert_eq!(e.expr(), &Expr::Compare("peer_address".into(), Op::Eq, Literal::Text("4B:65:27:2E:1D:6E".into())));
        let e = q("rssi < -70");
        assert_eq!(e.expr(), &Expr::Compare("rssi".into(), Op::Lt, Literal::Number(-70.0)));
    }

    #[test]
    fn evaluation() {
        // Disconnection Complete: status 0, handle 0x0040, reason 0x13.
        let pkt = Packet::new(Opcode::Event, 0, vec![0x05, 0x04, 0x00, 0x40, 0x00, 0x13]);
        let ix = index(&pkt);
        assert!(q("event == \"Disconnection Complete\"").matches(&ix));
        assert!(q("event == 0x05").matches(&ix));
        assert!(q("kind == event && dir == rx").matches(&ix));
        assert!(q("handle == 64").matches(&ix));
        assert!(q("handle == 0x40").matches(&ix));
        assert!(q("status == Success").matches(&ix));
        assert!(!q("status != Success").matches(&ix));
        assert!(q("reason == \"Remote User Terminated Connection\"").matches(&ix));
        assert!(q("reason == 0x13 && frame == 7").matches(&ix));
        assert!(q("hci && !att").matches(&ix));
        assert!(q("text contains \"terminated\"").matches(&ix));
        assert!(!q("error").matches(&ix));
        assert!(!q("rssi").matches(&ix));
        assert!(!q("rssi < -70").matches(&ix));
        assert!(q("index == 0 && source == test && len == 6").matches(&ix));
    }

    #[test]
    fn command_opcode_and_unknown() {
        let pkt = Packet::new(Opcode::Command, 0, vec![0x0a, 0x20, 0x01, 0x01]);
        let ix = index(&pkt);
        assert!(q("opcode == \"LE Set Advertising Enable\"").matches(&ix));
        assert!(q("opcode == 0x200a").matches(&ix));
        assert!(q("advertising == Enabled").matches(&ix));
        assert!(q("kind == command && dir == tx").matches(&ix));

        let bad = Packet::new(Opcode::Command, 0, vec![0xff, 0x3e, 0x00]);
        let ix = index(&bad);
        assert!(q("error").matches(&ix));
    }
}
