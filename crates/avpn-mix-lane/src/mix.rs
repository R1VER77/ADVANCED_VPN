//! Relay mix node: the §1.2 processing pipeline around [`crate::sphinx`].
//!
//! Responsibilities (the "integration surface" the reference pack documented
//! as NOT included — this module IS that surface):
//!
//! - **Exp(μ) per-cell delay** (default μ = 1 s), sampled from a swappable
//!   [`ScheduleRng`] — the same marker-trait convention as the parity pack's
//!   `ScheduleRng`/DC-net PRG markers.
//! - **Little's-law bounded delay queue.** Queue capacity L = λW (arrival
//!   rate × mean delay, with a safety factor) via [`MixConfig::little_law`].
//!   On overflow, cover traffic is evicted first: cover exists to pad timing,
//!   never to carry payload, so it is the correct sacrificial class.
//! - **Rotating two-epoch replay cache** (§1.6) with a bounded per-epoch
//!   capacity — the DoS firewall. A tag seen in the current or previous
//!   epoch is a replay.
//! - **Mailbox store** for delivered cells (bounded, drop-oldest).
//! - **§1.2 failure discipline:** a cell that fails processing (foreign,
//!   corrupted, or replayed) still occupies a full Exp(μ) delay slot before
//!   being silently discarded. Nothing about WHY a cell died is observable
//!   on any wire. Only framing garbage (not a 4096-byte cell at all) is
//!   rejected at ingress — that is a link-layer event, not a Sphinx event.
//!
//! Wire integration with the paced links (parity pack `obfs_stream`): a cell
//! is exactly one bucket-4096 frame — [`frame_for_wire`] produces it.

use crate::sphinx::{self, Action, MixSecret, CELL_SIZE};
use std::collections::{HashMap, HashSet, VecDeque};

pub const DEFAULT_MEAN_DELAY_MS: u64 = 1_000;
pub const DEFAULT_EPOCH_MS: u64 = 60_000;
pub const DEFAULT_REPLAY_CAPACITY: usize = 1 << 20;
pub const DEFAULT_QUEUE_CAPACITY: usize = 4_096;
pub const DEFAULT_MAILBOX_CAPACITY: usize = 256;

/// Wire bucket for a 4096-byte cell in the parity pack `obfs_stream` format.
pub const WIRE_BUCKET: u16 = 4_096;

// ---------------------------------------------------------------------------
// Scheduling RNG (SWAPPABLE marker: back with the platform CSPRNG)
// ---------------------------------------------------------------------------

pub trait ScheduleRng {
    /// Uniform in (0, 1).
    fn next_unit(&mut self) -> f64;
}

/// INSECURE xorshift64* RNG — tests and lab simulation only.
/// Never ship: replace with a CSPRNG-backed uniform at the integration point.
pub struct TestScheduleRng(pub u64);

impl ScheduleRng for TestScheduleRng {
    fn next_unit(&mut self) -> f64 {
        if self.0 == 0 {
            self.0 = 0x9E37_79B9_7F4A_7C15;
        }
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        ((v >> 11) as f64) / ((1u64 << 53) as f64)
    }
}

/// Exponential(1/mean_ms) sample, in milliseconds.
pub fn exp_delay_ms(mean_ms: u64, rng: &mut dyn ScheduleRng) -> u64 {
    let mut u = rng.next_unit();
    while u <= 0.0 {
        u = rng.next_unit();
    }
    // Millisecond granularity: clamp at 1 ms — a zero delay would couple
    // ingress and egress timing directly (anti-discipline).
    ((-(mean_ms as f64) * u.ln()).round() as u64).max(1)
}

// ---------------------------------------------------------------------------
// Traffic classes (Maybenot-consistent: cover < data)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrafficClass {
    /// Padding / cover traffic: first to be evicted on queue overflow.
    Cover = 0,
    /// Payload-bearing traffic.
    Data = 1,
}

// ---------------------------------------------------------------------------
// Replay cache (§1.6): rotating two-epoch, bounded
// ---------------------------------------------------------------------------

pub struct ReplayCache {
    epoch_ms: u64,
    capacity: usize,
    current_epoch: u64,
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
    /// Times an epoch's cache was cleared because it hit capacity. Should
    /// stay 0; non-zero means someone is flooding distinct tags.
    pub overflows: u64,
}

impl ReplayCache {
    pub fn new(epoch_ms: u64, capacity: usize) -> Self {
        ReplayCache {
            epoch_ms: epoch_ms.max(1),
            capacity: capacity.max(1),
            current_epoch: 0,
            current: HashSet::new(),
            previous: HashSet::new(),
            overflows: 0,
        }
    }

    fn epoch_of(&self, now: u64) -> u64 {
        now / self.epoch_ms
    }

    /// Insert `tag`; `false` means it was already seen (replay).
    ///
    /// Degradation contract: on reaching `capacity` distinct tags within an
    /// epoch the CURRENT set is cleared (the previous set survives). An
    /// attacker flooding >capacity distinct cells per epoch can age current
    /// tags out early; the alternative — unbounded memory — is worse. The
    /// `overflows` counter makes the attack observable.
    pub fn check_and_insert(&mut self, tag: &[u8; 32], now: u64) -> bool {
        let target = self.epoch_of(now);
        while self.current_epoch < target {
            self.previous = std::mem::take(&mut self.current);
            self.current_epoch += 1;
        }
        if self.previous.contains(tag) || self.current.contains(tag) {
            return false;
        }
        if self.current.len() >= self.capacity {
            self.current.clear();
            self.overflows += 1;
        }
        self.current.insert(*tag);
        true
    }

    pub fn tracked(&self) -> usize {
        self.current.len() + self.previous.len()
    }
}

// ---------------------------------------------------------------------------
// Mailbox store
// ---------------------------------------------------------------------------

pub struct Mailboxes {
    capacity_per_mailbox: usize,
    map: HashMap<[u8; 16], VecDeque<[u8; CELL_SIZE]>>,
    /// Cells dropped because a mailbox was full (drop-oldest).
    pub dropped: u64,
}

impl Mailboxes {
    pub fn new(capacity_per_mailbox: usize) -> Self {
        Mailboxes {
            capacity_per_mailbox: capacity_per_mailbox.max(1),
            map: HashMap::new(),
            dropped: 0,
        }
    }

    pub fn push(&mut self, mailbox: &[u8; 16], cell: [u8; CELL_SIZE]) {
        let q = self.map.entry(*mailbox).or_default();
        if q.len() >= self.capacity_per_mailbox {
            q.pop_front();
            self.dropped += 1;
        }
        q.push_back(cell);
    }

    /// Drain all cells for `mailbox` (client pull).
    pub fn drain(&mut self, mailbox: &[u8; 16]) -> Vec<[u8; CELL_SIZE]> {
        match self.map.get_mut(mailbox) {
            None => Vec::new(),
            Some(q) => q.drain(..).collect(),
        }
    }

    pub fn total(&self) -> usize {
        self.map.values().map(|q| q.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct MixConfig {
    /// μ: mean Exp delay per cell, in milliseconds (design default 1000).
    pub mean_delay_ms: u64,
    /// Replay-cache epoch length in milliseconds.
    pub epoch_ms: u64,
    /// Distinct replay tags tracked per epoch.
    pub replay_capacity: usize,
    /// Maximum cells occupying the delay queue (Little's law bound).
    pub queue_capacity: usize,
    /// Cells retained per mailbox.
    pub mailbox_capacity: usize,
}

impl Default for MixConfig {
    fn default() -> Self {
        MixConfig {
            mean_delay_ms: DEFAULT_MEAN_DELAY_MS,
            epoch_ms: DEFAULT_EPOCH_MS,
            replay_capacity: DEFAULT_REPLAY_CAPACITY,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            mailbox_capacity: DEFAULT_MAILBOX_CAPACITY,
        }
    }
}

impl MixConfig {
    /// Little's law: L = λW with a 1.5× safety factor, minimum 4.
    ///
    /// `arrival_per_sec` is the measured sustained ingress rate for THIS mix
    /// (over the prior epoch); `mean_delay_ms` is μ. A queue larger than
    /// λW·safety only adds latency; a smaller one drops traffic.
    pub fn little_law(arrival_per_sec: f64, mean_delay_ms: u64) -> usize {
        let littles = arrival_per_sec * mean_delay_ms as f64 / 1000.0;
        (littles * 1.5).ceil().max(4.0) as usize
    }

    /// Default config with the queue sized by Little's law.
    pub fn with_littles_law(arrival_per_sec: f64) -> Self {
        let mut cfg = MixConfig::default();
        cfg.queue_capacity = Self::little_law(arrival_per_sec, cfg.mean_delay_ms);
        cfg
    }
}

// ---------------------------------------------------------------------------
// Mix node
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Disposition {
    Forward { next_id: [u8; 16] },
    Deliver { mailbox: [u8; 16] },
    Discard,
}

struct QueuedCell {
    ready_at: u64,
    class: TrafficClass,
    disposition: Disposition,
    /// `None` for discards (nothing is ever emitted for them).
    cell: Option<Box<[u8; CELL_SIZE]>>,
}

#[derive(Debug, Default, Clone)]
pub struct MixStats {
    pub accepted: u64,
    pub forwarded: u64,
    pub delivered: u64,
    /// Cells that parsed as cells but failed processing (foreign or
    /// corrupted) — §1.2 discards.
    pub not_mine: u64,
    pub replays: u64,
    /// Cover cells evicted to make room for data under queue pressure.
    pub cover_evicted: u64,
    /// Cells refused outright because the queue was full of data.
    pub dropped_full: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AcceptError {
    /// Not a Sphinx cell at all (framing garbage) — link-layer reject.
    NotACell,
    /// Delay queue full with no cover left to evict.
    QueueFull,
}

/// What `drain` hands the daemon for one expired delay slot.
#[derive(Debug, PartialEq, Eq)]
pub enum Outbound {
    /// Forward to `next_id` over the paced link (bucket-4096 frame).
    Forward {
        next_id: [u8; 16],
        cell: Box<[u8; CELL_SIZE]>,
    },
    /// A slot expired with nothing emitted (foreign / corrupted / replayed
    /// cell). Surfaced so the daemon's accounting sees uniform activity —
    /// the WIRE sees nothing, which is the point of §1.2.
    Silent,
}

pub struct MixNode {
    id: [u8; 16],
    secret: MixSecret,
    cfg: MixConfig,
    replay: ReplayCache,
    mailboxes: Mailboxes,
    queue: VecDeque<QueuedCell>,
    pub stats: MixStats,
}

impl MixNode {
    pub fn new(id: [u8; 16], secret: MixSecret, cfg: MixConfig) -> Self {
        let replay = ReplayCache::new(cfg.epoch_ms, cfg.replay_capacity);
        let mailboxes = Mailboxes::new(cfg.mailbox_capacity);
        MixNode {
            id,
            secret,
            cfg,
            replay,
            mailboxes,
            queue: VecDeque::new(),
            stats: MixStats::default(),
        }
    }

    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    pub fn config(&self) -> &MixConfig {
        &self.cfg
    }

    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    pub fn replay_cache(&self) -> &ReplayCache {
        &self.replay
    }

    /// Accept a cell from an ingress link. Returns the sampled departure
    /// tick. The delay slot is occupied REGARDLESS of the processing
    /// outcome — the caller cannot observe, from timing, whether the cell
    /// was healthy.
    pub fn accept(
        &mut self,
        cell: &[u8; CELL_SIZE],
        class: TrafficClass,
        now: u64,
        rng: &mut dyn ScheduleRng,
    ) -> Result<u64, AcceptError> {
        let ready_at = now + exp_delay_ms(self.cfg.mean_delay_ms, rng);

        // Enqueue under the Little's-law bound. Pressure policy (§1.4):
        // cover is the sacrificial class — an incoming DATA cell may evict a
        // queued cover; an incoming COVER cell at a full queue is simply
        // dropped (evicting an old cover for a new one would be churn, and
        // would let a cover flood displace queued cover indefinitely).
        if self.queue.len() >= self.cfg.queue_capacity {
            let evictable = class == TrafficClass::Data;
            if evictable {
                if let Some(pos) = self
                    .queue
                    .iter()
                    .position(|q| q.class == TrafficClass::Cover)
                {
                    self.queue.remove(pos);
                    self.stats.cover_evicted += 1;
                } else {
                    self.stats.dropped_full += 1;
                    return Err(AcceptError::QueueFull);
                }
            } else {
                self.stats.dropped_full += 1;
                return Err(AcceptError::QueueFull);
            }
        }

        // §1.6 replay filter.
        let tag = sphinx::replay_tag(cell).map_err(|_| AcceptError::NotACell)?;
        let fresh = self.replay.check_and_insert(&tag, now);

        let mut buf = *cell;
        let disposition = if !fresh {
            self.stats.replays += 1;
            Disposition::Discard
        } else {
            match sphinx::process_cell(&mut buf, &self.secret) {
                Ok(Action::Forward { next_id, .. }) => {
                    self.stats.forwarded += 1;
                    Disposition::Forward { next_id }
                }
                Ok(Action::Deliver { mailbox }) => {
                    self.stats.delivered += 1;
                    Disposition::Deliver { mailbox }
                }
                Err(_) => {
                    // Foreign or corrupted — indistinguishable here by
                    // construction (§1.2). Delay slot still occupied.
                    self.stats.not_mine += 1;
                    Disposition::Discard
                }
            }
        };

        let out_cell = if matches!(disposition, Disposition::Discard) {
            None
        } else {
            Some(Box::new(buf))
        };
        self.queue.push_back(QueuedCell {
            ready_at,
            class,
            disposition,
            cell: out_cell,
        });
        self.stats.accepted += 1;
        Ok(ready_at)
    }

    /// Expire every delay slot that has elapsed by `now`. Deliveries land
    /// in the mailbox store; forwards are returned for the daemon to send.
    pub fn drain(&mut self, now: u64) -> Vec<Outbound> {
        let mut out = Vec::new();
        let mut rest = VecDeque::with_capacity(self.queue.len());
        for qc in self.queue.drain(..) {
            if qc.ready_at > now {
                rest.push_back(qc);
                continue;
            }
            match qc.disposition {
                Disposition::Forward { next_id } => out.push(Outbound::Forward {
                    next_id,
                    cell: qc.cell.expect("forward keeps its cell"),
                }),
                Disposition::Deliver { mailbox } => {
                    self.mailboxes
                        .push(&mailbox, *qc.cell.expect("deliver keeps its cell"));
                }
                Disposition::Discard => out.push(Outbound::Silent),
            }
        }
        self.queue = rest;
        out
    }

    /// Client pull: all cells waiting in `owner`'s mailbox.
    pub fn pull_mailbox(&mut self, owner: &[u8; 16]) -> Vec<[u8; CELL_SIZE]> {
        self.mailboxes.drain(owner)
    }

    pub fn mailboxes(&self) -> &Mailboxes {
        &self.mailboxes
    }
}

// ---------------------------------------------------------------------------
// Paced-link wire framing (obfs_stream interop)
// ---------------------------------------------------------------------------

/// Frame a cell as one bucket-4096 frame in the parity pack `obfs_stream`
/// format: `[u16 payload_len][u16 bucket] || cell || padding` — here the
/// payload is the full 4096-byte cell, so the frame is exactly 4 + 4096.
pub fn frame_for_wire(cell: &[u8]) -> Vec<u8> {
    debug_assert_eq!(cell.len(), CELL_SIZE);
    let mut frame = Vec::with_capacity(4 + WIRE_BUCKET as usize);
    frame.extend_from_slice(&(cell.len() as u16).to_le_bytes());
    frame.extend_from_slice(&WIRE_BUCKET.to_le_bytes());
    frame.extend_from_slice(cell);
    frame.resize(4 + WIRE_BUCKET as usize, 0);
    frame
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::needless_range_loop, clippy::while_let_loop)] // test-only index loops
mod tests {
    use super::*;
    use crate::sphinx::{build_cell, mix_keypair, open_payload, DetRng, MixKeys, SphinxRng};

    fn fill32(rng: &mut dyn SphinxRng) -> [u8; 32] {
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        b
    }

    fn make_mix(id: [u8; 16], seed: u64) -> (MixKeys, MixSecret) {
        let mut rng = DetRng(seed);
        mix_keypair(&fill32(&mut rng), &fill32(&mut rng), fill32(&mut rng), id)
    }

    fn fast_cfg(queue: usize) -> MixConfig {
        MixConfig {
            mean_delay_ms: 10,
            epoch_ms: 1_000,
            replay_capacity: 1024,
            queue_capacity: queue,
            mailbox_capacity: 8,
        }
    }

    fn srng(seed: u64) -> TestScheduleRng {
        TestScheduleRng(seed)
    }

    fn as_cell(v: &[u8]) -> &[u8; CELL_SIZE] {
        v.try_into().expect("cell-sized")
    }

    #[test]
    fn exp_delays_are_positive_and_meanly_correct() {
        let mut rng = srng(1);
        let mut sum = 0f64;
        let mut max = 0u64;
        for _ in 0..10_000 {
            let d = exp_delay_ms(100, &mut rng);
            assert!(d > 0, "delay must be positive");
            sum += d as f64;
            max = max.max(d);
        }
        let mean = sum / 10_000.0;
        // Loose bounds: Exp(100) has stddev 100; 10k samples pin the mean
        // well within ±15% with overwhelming probability for any fixed seed
        // (this is deterministic, so the bound is exact for this seed).
        assert!(mean > 85.0 && mean < 115.0, "mean {mean} out of bounds");
        assert!(max > 300, "max {max} implausibly small for Exp(100)");
    }

    #[test]
    fn littles_law_math() {
        // λ = 10/s, W = 1 s → L = 10, ×1.5 safety → 15.
        assert_eq!(MixConfig::little_law(10.0, 1_000), 15);
        // λ = 0.1/s, W = 1 s → L = 0.1 → floor at 4.
        assert_eq!(MixConfig::little_law(0.1, 1_000), 4);
        let cfg = MixConfig::with_littles_law(100.0);
        assert_eq!(cfg.queue_capacity, 150);
    }

    #[test]
    fn replay_cache_rejects_within_and_across_one_epoch() {
        let mut c = ReplayCache::new(1_000, 1024);
        let t = [7u8; 32];
        assert!(c.check_and_insert(&t, 0));
        assert!(!c.check_and_insert(&t, 1), "same epoch: replay");
        assert!(!c.check_and_insert(&t, 999), "still same epoch: replay");
        assert!(
            !c.check_and_insert(&t, 1_900),
            "previous epoch: still a replay (two-epoch window)"
        );
        assert!(
            !c.check_and_insert(&t, 1_999),
            "previous epoch, later: still a replay"
        );
        assert!(
            c.check_and_insert(&t, 2_500),
            "two epochs later: fully aged out"
        );
    }

    #[test]
    fn replay_cache_overflow_degrades_and_counts() {
        let mut c = ReplayCache::new(60_000, 4);
        for i in 0..4u8 {
            assert!(c.check_and_insert(&[i; 32], 0));
        }
        // Fifth distinct tag clears the current epoch (counter bumps) and is
        // itself inserted.
        assert!(c.check_and_insert(&[9; 32], 0));
        assert_eq!(c.overflows, 1);
        // The cleared tags are accepted again — degradation is observable
        // and bounded, per the contract.
        assert!(c.check_and_insert(&[0; 32], 1));
    }

    #[test]
    fn mailbox_capacity_drops_oldest() {
        let mut m = Mailboxes::new(2);
        let mb = [1u8; 16];
        for i in 0..5u8 {
            m.push(&mb, [i; CELL_SIZE]);
        }
        assert_eq!(m.dropped, 3);
        let got = m.drain(&mb);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], [3u8; CELL_SIZE]);
        assert_eq!(got[1], [4u8; CELL_SIZE]);
        assert_eq!(m.drain(&mb).len(), 0, "drain empties the mailbox");
    }

    #[test]
    fn healthy_cell_forwards_after_its_delay() {
        let (a_keys, a_sec) = make_mix([0xA1; 16], 1);
        let (b_keys, b_sec) = make_mix([0xB1; 16], 2);
        let mut mix_a = MixNode::new([0xA1; 16], a_sec, fast_cfg(64));

        let built = build_cell(
            &[a_keys.clone(), b_keys.clone()],
            &[0xEE; 16],
            b"hello",
            &mut DetRng(3),
        )
        .unwrap();
        let ready = mix_a
            .accept(as_cell(&built.cell), TrafficClass::Data, 0, &mut srng(4))
            .unwrap();

        // Before the delay elapses: nothing.
        assert!(mix_a.drain(ready - 1).is_empty());
        // At/after the delay: one forward to B.
        let out = mix_a.drain(ready);
        assert_eq!(out.len(), 1);
        match &out[0] {
            Outbound::Forward { next_id, cell } => {
                assert_eq!(*next_id, [0xB1; 16]);
                // Hop 2 finishes the path.
                let mut mix_b = MixNode::new([0xB1; 16], b_sec, fast_cfg(64));
                let r2 = mix_b
                    .accept(cell, TrafficClass::Data, ready, &mut srng(5))
                    .unwrap();
                let out2 = mix_b.drain(r2);
                assert!(out2.is_empty(), "delivery does not emit a forward");
                let mail = mix_b.pull_mailbox(&[0xEE; 16]);
                assert_eq!(mail.len(), 1);
                assert_eq!(
                    open_payload(&mail[0], &built.payload_key).unwrap(),
                    b"hello"
                );
            }
            other => panic!("expected forward, got {other:?}"),
        }
    }

    #[test]
    fn foreign_and_corrupted_cells_occupy_a_delay_slot_silently() {
        let (a_keys, a_sec) = make_mix([0xA1; 16], 11);
        let mut mix = MixNode::new([0xA1; 16], a_sec, fast_cfg(64));

        // A cell addressed to some other network entirely.
        let others = make_mix([0xC1; 16], 13);
        let built = build_cell(
            &[others.0.clone(), others.0.clone()],
            &[0x77; 16],
            b"x",
            &mut DetRng(14),
        )
        .unwrap();
        let ready = mix
            .accept(as_cell(&built.cell), TrafficClass::Data, 0, &mut srng(15))
            .unwrap();
        assert_eq!(mix.stats.not_mine, 1);

        // A corrupted cell for THIS mix: flip a byte inside slot 1's routing
        // block (covered by MAC_1). Both slot attempts fail → not-mine.
        // (Contrast: payload-region corruption traverses and dies
        // client-side — that discipline is tested in the sphinx suite.)
        let mut corrupt = build_cell(
            &[a_keys.clone(), others.0.clone()],
            &[0x66; 16],
            b"y",
            &mut DetRng(17),
        )
        .unwrap();
        corrupt.cell[1_150] ^= 0x40;
        let ready2 = mix
            .accept(as_cell(&corrupt.cell), TrafficClass::Data, 0, &mut srng(18))
            .unwrap();

        // Both drain as Silent — nothing on any wire, timing preserved.
        let mut saw_silent = 0;
        for r in [ready, ready2] {
            for ob in mix.drain(r) {
                assert_eq!(ob, Outbound::Silent);
                saw_silent += 1;
            }
        }
        assert_eq!(saw_silent, 2);
        assert_eq!(mix.stats.accepted, 2);
    }

    #[test]
    fn replayed_cell_is_discarded_not_delivered() {
        let (a_keys, a_sec) = make_mix([0xA1; 16], 21);
        let (b_keys, b_sec) = make_mix([0xB1; 16], 22);
        let mut mix_a = MixNode::new([0xA1; 16], a_sec, fast_cfg(64));
        let mut mix_b = MixNode::new([0xB1; 16], b_sec, fast_cfg(64));

        let built = build_cell(
            &[a_keys.clone(), b_keys.clone()],
            &[0xEE; 16],
            b"once",
            &mut DetRng(23),
        )
        .unwrap();
        let r1 = mix_a
            .accept(as_cell(&built.cell), TrafficClass::Data, 0, &mut srng(24))
            .unwrap();
        // Adversary replays the identical bytes on the ingress link.
        let r2 = mix_a
            .accept(as_cell(&built.cell), TrafficClass::Data, 5, &mut srng(25))
            .unwrap();
        assert_eq!(mix_a.stats.replays, 1);

        let mut delivered = 0;
        for (t, _original) in [(r1, built.cell.clone()), (r2, built.cell.clone())] {
            for ob in mix_a.drain(t) {
                if let Outbound::Forward { cell, .. } = ob {
                    let rb = mix_b
                        .accept(&cell, TrafficClass::Data, t, &mut srng(26))
                        .unwrap();
                    mix_b.drain(rb);
                    delivered += mix_b.pull_mailbox(&[0xEE; 16]).len();
                }
            }
        }
        assert_eq!(
            delivered, 1,
            "exactly one delivery — the replay died silently"
        );
    }

    #[test]
    fn queue_overflow_evicts_cover_before_refusing_data() {
        let (_a_keys, a_sec) = make_mix([0xA1; 16], 31);
        let mut mix = MixNode::new([0xA1; 16], a_sec, fast_cfg(4));

        let others = make_mix([0xC1; 16], 32);
        // Four DISTINCT foreign cover cells fill the queue (distinct bytes:
        // identical bytes would be replay-filtered, muddying the queue
        // mechanics under test).
        let mut rng = DetRng(330);
        let cover_cells: Vec<_> = (0..4u8)
            .map(|i| {
                build_cell(
                    &[others.0.clone(), others.0.clone()],
                    &[i; 16],
                    &[i; 4],
                    &mut rng,
                )
                .unwrap()
                .cell
            })
            .collect();
        for c in &cover_cells {
            mix.accept(as_cell(c), TrafficClass::Cover, 0, &mut srng(34))
                .unwrap();
        }
        assert_eq!(mix.queue_len(), 4);

        // Five DISTINCT data cells. The first four each evict a cover; the
        // fifth finds a data-only queue and is refused.
        let data_cells: Vec<_> = (0..5u8)
            .map(|i| {
                build_cell(
                    &[others.0.clone(), others.0.clone()],
                    &[0x40 + i; 16],
                    &[i; 4],
                    &mut rng,
                )
                .unwrap()
                .cell
            })
            .collect();
        for (i, c) in data_cells.iter().enumerate() {
            let r = mix.accept(
                as_cell(c),
                TrafficClass::Data,
                1 + i as u64,
                &mut srng(35 + i as u64),
            );
            if i < 4 {
                assert!(r.is_ok(), "data {i} accepted by evicting cover");
            } else {
                assert_eq!(
                    r,
                    Err(AcceptError::QueueFull),
                    "data {i} refused: queue full of data"
                );
            }
        }
        assert_eq!(
            mix.stats.cover_evicted, 4,
            "all four covers evicted for data"
        );
        assert_eq!(mix.stats.dropped_full, 1, "exactly one hard refusal");
        assert_eq!(mix.queue_len(), 4, "queue still at capacity");
        assert_eq!(mix.stats.replays, 0, "all cells distinct: no replays");
        assert!(mix.stats.accepted >= 8);
    }

    #[test]
    fn framing_matches_obfs_stream_bucket_format() {
        let cell = [0xABu8; CELL_SIZE];
        let frame = frame_for_wire(&cell);
        assert_eq!(frame.len(), 4 + 4_096);
        assert_eq!(u16::from_le_bytes([frame[0], frame[1]]), CELL_SIZE as u16);
        assert_eq!(u16::from_le_bytes([frame[2], frame[3]]), 4_096);
        assert_eq!(&frame[4..], &cell[..]);
    }

    #[test]
    fn not_a_cell_rejected_at_ingress() {
        let (_, a_sec) = make_mix([0xA1; 16], 41);
        let mut mix = MixNode::new([0xA1; 16], a_sec, fast_cfg(4));
        let mut garbage = [0u8; CELL_SIZE];
        garbage[0] = 9; // bad version
        garbage[1] = 3;
        assert_eq!(
            mix.accept(&garbage, TrafficClass::Data, 0, &mut srng(42)),
            Err(AcceptError::NotACell)
        );
        assert_eq!(mix.stats.accepted, 0);
    }
}
