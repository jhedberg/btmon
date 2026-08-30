//! Decoding state that persists across packets.

use std::collections::{HashMap, VecDeque};

use crate::reader::BdAddr;
use crate::uuid::Uuid;
use crate::{Link, LinkKind};

/// A request waiting for its answer: the frame it was sent in and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending {
    pub frame: u64,
    pub ts: Option<hcimon_capture::Timestamp>,
}

/// Longest queue of unanswered commands kept per opcode.
const MAX_PENDING_CMDS: usize = 16;

/// Tunables that affect decoding.
#[derive(Debug, Clone)]
pub struct Options {
    /// Decode the payload of SCO packets (btmon `--sco`).
    pub sco: bool,
    /// Decode the payload of ISO packets (btmon `--iso`).
    pub iso: bool,
    /// Manufacturer to assume for vendor-specific commands when the controller
    /// has not reported one (btmon `--vendor`).
    pub fallback_manufacturer: Option<u16>,
}

impl Default for Options {
    fn default() -> Self {
        Options { sco: true, iso: true, fallback_manufacturer: None }
    }
}

/// Type of logical link a connection handle refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkType {
    /// BR/EDR ACL.
    Acl,
    /// LE ACL.
    Le,
    Sco,
    Esco,
    /// LE isochronous (CIS or BIS).
    Iso,
    Unknown,
}

/// A connection the decoder has seen being established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub handle: u16,
    pub link: LinkType,
    pub addr: BdAddr,
    /// HCI address type (0 public, 1 random, ...); meaningful for LE links.
    pub addr_type: u8,
    /// 0 central, 1 peripheral.
    pub role: u8,
    /// Frame number of the packet that established the connection.
    pub since_frame: u64,
    /// L2CAP state for this link.
    pub l2cap: L2capState,
    /// ATT state for this link.
    pub att: AttState,
}

impl Connection {
    pub fn new(handle: u16, link: LinkType) -> Self {
        Connection {
            handle,
            link,
            addr: BdAddr::ZERO,
            addr_type: 0,
            role: 0,
            since_frame: 0,
            l2cap: L2capState::default(),
            att: AttState::default(),
        }
    }
}

/// L2CAP channel mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum L2capMode {
    #[default]
    Basic,
    Retransmission,
    FlowControl,
    EnhancedRetransmission,
    Streaming,
    LeCreditBased,
    EnhancedCreditBased,
}

/// A dynamically allocated L2CAP channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2capChannel {
    /// CID as seen in the direction the channel is keyed by.
    pub local_cid: u16,
    pub remote_cid: u16,
    pub psm: u16,
    pub mode: L2capMode,
    pub mtu: u16,
    /// Whether the channel was opened by the LE (0x0005) signaling channel.
    pub le: bool,
    /// Whether the Extended Window Size option was negotiated (frames carry the extended control field).
    pub ext_ctrl: bool,
    /// "No FCS" requested in a Configure Request, per direction of the request (`false` = TX, `true` = RX).
    pub no_fcs: [bool; 2],
    /// SDU being reassembled from credit based PDUs or I-frame segments, per data direction.
    pub sdu: [Option<Reassembly>; 2],
}

/// Per-connection L2CAP state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L2capState {
    /// Channels keyed by CID.  Both the local and the remote CID map to the same channel
    /// (they are distinct values on the wire), so a lookup by any CID works.
    pub channels: HashMap<u16, L2capChannel>,
    /// Pending connection requests keyed by signaling identifier: `(psm, source cid)`.
    pub pending: HashMap<u8, (u16, u16)>,
    /// Pending enhanced credit based connection requests: `(psm, source cids)`.
    pub pending_ecred: HashMap<u8, (u16, Vec<u16>)>,
    /// Unanswered signaling requests keyed by `(sent by the local host, identifier)`.
    pub pending_reqs: HashMap<(bool, u8), Pending>,
    /// Unanswered SDP transactions keyed by `(sent by the local host, transaction id)`.
    pub sdp_pending: HashMap<(bool, u16), Pending>,
    /// Incomplete ACL fragments per direction (`false` = TX, `true` = RX).
    pub reassembly: [Option<Reassembly>; 2],
}

/// An L2CAP PDU being reassembled from ACL fragments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reassembly {
    /// Total PDU length announced in the basic header (excluding the 4-byte header).
    pub expected: usize,
    pub data: Vec<u8>,
}

impl L2capState {
    pub fn channel(&self, cid: u16) -> Option<&L2capChannel> {
        self.channels.get(&cid)
    }
}

/// Per-connection ATT state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttState {
    /// Negotiated MTU.
    pub mtu: u16,
    /// Outstanding requests (opcode + parameters), oldest first, per direction of the request.
    pub pending: VecDeque<AttRequest>,
    /// Attribute handle → type UUID, learned from discovery responses.
    pub attr_types: HashMap<u16, Uuid>,
    /// Characteristic value handle → characteristic UUID, learned from discovery.
    pub char_values: HashMap<u16, Uuid>,
    /// The request answered by the PDU being decoded, for linking.
    pub answered: Option<Pending>,
}

impl Default for AttState {
    fn default() -> Self {
        AttState { mtu: 23, pending: VecDeque::new(), attr_types: HashMap::new(), char_values: HashMap::new(), answered: None }
    }
}

/// A request that awaits a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttRequest {
    pub opcode: u8,
    /// Whether the request was sent by the local host (TX) or received (RX).
    pub tx: bool,
    /// Copy of the request parameters.
    pub params: Vec<u8>,
    pub frame: u64,
    pub ts: Option<hcimon_capture::Timestamp>,
}

/// Everything known about one controller (an HCI index).
#[derive(Debug, Clone, Default)]
pub struct IndexState {
    /// Packets seen for this index.
    pub frames: u64,
    pub name: String,
    pub addr: BdAddr,
    pub manufacturer: Option<u16>,
    /// Connections keyed by handle.
    pub conns: HashMap<u16, Connection>,
    /// Handles reported by LE CIS Request / Create BIG that are not yet complete.
    pub pending_iso: Vec<u16>,
    /// Advertising set → periodic advertising info, as needed.
    pub adv_sets: HashMap<u8, AdvSet>,
    /// Last frame's timestamp, if any.
    pub last_ts: Option<hcimon_capture::Timestamp>,
    /// Timestamp of the packet being decoded.
    pub cur_ts: Option<hcimon_capture::Timestamp>,
    /// Links produced while decoding the current packet.
    pub links: Vec<Link>,
    /// Commands awaiting Command Complete / Command Status, per opcode.
    pub pending_cmds: HashMap<u16, VecDeque<Pending>>,
    /// Device names learned from advertising data, EIR and remote name responses.
    pub names: HashMap<BdAddr, String>,
    /// ACL packets sent to the controller that it has not yet reported as completed, per handle.
    pub acl_outstanding: HashMap<u16, VecDeque<Pending>>,
    /// Number of ACL data packets the controller can hold (from Read Buffer Size / LE Read Buffer Size).
    pub acl_buffers: Option<u16>,
    /// Manufacturer-specific event prefix (Microsoft extension) if configured.
    pub msft_evt_prefix: Vec<u8>,
    /// Connections established or closed by the packet being decoded.
    pub lifecycle: Vec<crate::Lifecycle>,
}

/// Bookkeeping for an extended advertising set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvSet {
    pub periodic: bool,
}

impl IndexState {
    pub fn conn(&self, handle: u16) -> Option<&Connection> {
        self.conns.get(&handle)
    }

    pub fn conn_mut(&mut self, handle: u16) -> Option<&mut Connection> {
        self.conns.get_mut(&handle)
    }

    /// Get or create the connection with the given handle.
    pub fn conn_or_insert(&mut self, handle: u16, link: LinkType) -> &mut Connection {
        self.conns.entry(handle).or_insert_with(|| Connection::new(handle, link))
    }

    /// Forget a connection and everything else keyed by its handle.
    pub fn remove_conn(&mut self, handle: u16) -> Option<Connection> {
        self.acl_outstanding.remove(&handle);
        self.lifecycle.push(crate::Lifecycle::Closed(handle));
        self.conns.remove(&handle)
    }

    /// A connection was established on `conn.handle`: whatever the handle
    /// carried before (a link whose disconnection was not captured) is gone.
    pub fn establish_conn(&mut self, conn: Connection) -> &mut Connection {
        let handle = conn.handle;
        self.acl_outstanding.remove(&handle);
        self.lifecycle.push(crate::Lifecycle::Established(handle));
        self.conns.insert(handle, conn);
        self.conns.get_mut(&handle).expect("just inserted")
    }

    /// The controller started over (New Index, or a successful HCI Reset):
    /// its links, outstanding packets and settings belong to the past, as
    /// do commands sent before frame `since` (those sent after an HCI Reset
    /// command but before its completion are still going to be answered).
    /// Learned device names and the frame count stay.
    pub fn reset_controller(&mut self, since: u64) {
        self.conns.clear();
        self.pending_iso.clear();
        self.adv_sets.clear();
        self.pending_cmds.retain(|_, q| {
            q.retain(|p| p.frame > since);
            !q.is_empty()
        });
        self.acl_outstanding.clear();
        self.acl_buffers = None;
        self.msft_evt_prefix.clear();
    }

    /// Manufacturer to use for vendor-specific decoding.
    pub fn manufacturer(&self, options: &Options) -> Option<u16> {
        self.manufacturer.or(options.fallback_manufacturer)
    }

    /// The packet being decoded, as something to wait for an answer to.
    pub fn pending(&self) -> Pending {
        Pending { frame: self.frames, ts: self.cur_ts }
    }

    /// Record that the packet being decoded answers `req`.
    pub fn link_to(&mut self, req: Pending) {
        let elapsed_us = match (self.cur_ts, req.ts) {
            (Some(now), Some(then)) => Some(now.micros_since(then)),
            _ => None,
        };
        self.links.push(Link { kind: LinkKind::ResponseTo, frame: req.frame, elapsed_us });
    }

    /// Remember an HCI command until its Command Complete / Status arrives.
    pub fn push_command(&mut self, opcode: u16) {
        let p = self.pending();
        let q = self.pending_cmds.entry(opcode).or_default();
        while q.len() >= MAX_PENDING_CMDS {
            q.pop_front();
        }
        q.push_back(p);
    }

    /// Link the packet being decoded to the oldest unanswered command with
    /// `opcode`; returns that command's frame number.
    pub fn answer_command(&mut self, opcode: u16) -> Option<u64> {
        let p = self.pending_cmds.get_mut(&opcode).and_then(|q| q.pop_front())?;
        self.link_to(p);
        Some(p.frame)
    }

    /// Remember an ACL packet sent to the controller until it is reported completed.
    pub fn push_acl_tx(&mut self, handle: u16) {
        let p = self.pending();
        let q = self.acl_outstanding.entry(handle).or_default();
        while q.len() >= 64 {
            q.pop_front();
        }
        q.push_back(p);
    }

    /// Complete `count` ACL packets on `handle`; returns the latencies (µs) of the completed ones.
    pub fn complete_acl(&mut self, handle: u16, count: u16) -> Vec<Option<i64>> {
        let mut out = Vec::new();
        for _ in 0..count {
            let Some(p) = self.acl_outstanding.get_mut(&handle).and_then(|q| q.pop_front()) else { break };
            let elapsed_us = match (self.cur_ts, p.ts) {
                (Some(now), Some(then)) => Some(now.micros_since(then)),
                _ => None,
            };
            self.links.push(Link { kind: LinkKind::Completes, frame: p.frame, elapsed_us });
            out.push(elapsed_us);
        }
        out
    }

    /// ACL packets currently in flight towards the controller.
    pub fn acl_in_flight(&self) -> usize {
        self.acl_outstanding.values().map(|q| q.len()).sum()
    }
}

/// State for all controllers plus decoding options.
#[derive(Debug, Default)]
pub struct Context {
    pub options: Options,
    pub indexes: HashMap<u16, IndexState>,
    /// Total packets decoded.
    pub packets: u64,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: Options) -> Self {
        Context { options, ..Default::default() }
    }

    pub fn index(&self, index: u16) -> Option<&IndexState> {
        self.indexes.get(&index)
    }

    pub fn index_mut(&mut self, index: u16) -> &mut IndexState {
        self.indexes.entry(index).or_default()
    }

    pub fn remove_index(&mut self, index: u16) {
        self.indexes.remove(&index);
    }
}

impl Default for L2capChannel {
    fn default() -> Self {
        L2capChannel {
            local_cid: 0,
            remote_cid: 0,
            psm: 0,
            mode: L2capMode::Basic,
            mtu: 0,
            le: false,
            ext_ctrl: false,
            no_fcs: [false; 2],
            sdu: [None, None],
        }
    }
}
