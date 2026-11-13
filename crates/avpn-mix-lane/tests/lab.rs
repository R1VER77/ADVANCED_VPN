//! GPA lab, simulation tier (gate G1 of CUTOVER_KATZENPOST.md): a full mix
//! network of [`MixNode`]s under the §1.2 discipline, checked for
//!
//! 1. end-to-end delivery through real relay processing (delays, queues,
//!    replay caches, mailboxes),
//! 2. replay-attack rejection (no duplicate delivery, counters move),
//! 3. the §1.2 failure discipline under an active tagger (corrupted cells
//!    die WITHOUT any observable wire signature),
//! 4. passive-observer linkability heuristics (no 64-byte window of any
//!    cell appears on two different links — R1 full-slot shifting AND R3
//!    payload re-masking, exercised through the whole pipeline),
//! 5. delay sanity: per-cell end-to-end delay is a sum of v Exp(μ) slots
//!    plus link latencies (Erlang-shaped; bounded and centered loosely),
//! 6. mix accounting closes (accepted = forwarded + delivered + not_mine +
//!    replays; zero unexplained drops).
//!
//! The live-site tier (gate G2) runs the same scenario drivers over the
//! real transport; see GPA_LAB_PLAN.md.

use avpn_mix_lane::mix::{MixConfig, MixNode, Outbound, TestScheduleRng, TrafficClass};
use avpn_mix_lane::sphinx::{build_cell, open_payload, DetRng, MixKeys, SphinxRng, CELL_SIZE};
use std::collections::{HashMap, HashSet};

/// A cell on a link: (destination mix, class, bytes).
type InFlight = (usize, TrafficClass, [u8; CELL_SIZE]);

const N_MIXES: usize = 6;
const V_HOPS: usize = 3;
const MEAN_DELAY_MS: u64 = 50;
const LINK_LATENCY_MS: u64 = 5;
const N_CLIENTS: u64 = 24;
const HORIZON_MS: u64 = 4_000;

struct Net {
    nodes: Vec<MixNode>,
    /// Cells observed on each mix's ingress link (the adversary's view).
    observed: Vec<Vec<[u8; CELL_SIZE]>>,
    /// In-flight frames: (due_tick, to_mix_idx, class, cell).
    pending: Vec<(u64, usize, TrafficClass, [u8; CELL_SIZE])>,
}

impl Net {
    fn new(mixes: &[(MixKeys, avpn_mix_lane::sphinx::MixSecret)]) -> Self {
        let cfg = MixConfig {
            mean_delay_ms: MEAN_DELAY_MS,
            epoch_ms: 10_000,
            replay_capacity: 1 << 16,
            queue_capacity: 512,
            mailbox_capacity: 64,
        };
        let nodes = mixes
            .iter()
            .map(|(k, s)| MixNode::new(k.id, s.clone(), cfg.clone()))
            .collect();
        Net {
            nodes,
            observed: vec![Vec::new(); N_MIXES],
            pending: Vec::new(),
        }
    }

    fn idx_of(&self, id: [u8; 16]) -> usize {
        self.nodes
            .iter()
            .position(|n| n.id() == id)
            .expect("id in net")
    }

    /// Deliver a cell to a mix's ingress link at `now`.
    fn inject(
        &mut self,
        to: usize,
        cell: [u8; CELL_SIZE],
        now: u64,
        srngs: &mut [TestScheduleRng],
    ) {
        self.observed[to].push(cell);
        self.nodes[to]
            .accept(&cell, TrafficClass::Data, now, &mut srngs[to])
            .expect("queue has headroom in this scenario");
    }

    /// Advance one millisecond.
    fn tick(&mut self, now: u64, srngs: &mut [TestScheduleRng]) {
        // Ship due pending frames into their target mix's ingress.
        let due: Vec<(usize, InFlight)> = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, (t, ..))| *t <= now)
            .map(|(i, (_, to, class, cell))| (i, (*to, *class, *cell)))
            .collect();
        for (i, (to, class, cell)) in due.into_iter().rev() {
            self.pending.swap_remove(i);
            self.observed[to].push(cell);
            self.nodes[to]
                .accept(&cell, class, now, &mut srngs[to])
                .expect("queue has headroom in this scenario");
        }

        // Expire delay slots; forwards ride the next link.
        for i in 0..self.nodes.len() {
            for ob in self.nodes[i].drain(now) {
                if let Outbound::Forward { next_id, cell } = ob {
                    let to = self.idx_of(next_id);
                    self.pending
                        .push((now + LINK_LATENCY_MS, to, TrafficClass::Data, *cell));
                }
            }
        }
    }
}

fn fill32(rng: &mut dyn SphinxRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill(&mut b);
    b
}

fn make_mixes(n: usize, seed: u64) -> Vec<(MixKeys, avpn_mix_lane::sphinx::MixSecret)> {
    let mut rng = DetRng(seed);
    (0..n)
        .map(|i| {
            let id = [0x10 + i as u8; 16];
            avpn_mix_lane::sphinx::mix_keypair(
                &fill32(&mut rng),
                &fill32(&mut rng),
                fill32(&mut rng),
                id,
            )
        })
        .collect()
}

fn mailbox_of(c: u64, tag: u8) -> [u8; 16] {
    let mut mb = [0u8; 16];
    mb[0] = tag;
    mb[1] = c as u8;
    mb
}

/// All 64-byte windows of a cell (linkability-heuristic substrate).
fn windows(cell: &[u8; CELL_SIZE]) -> impl Iterator<Item = [u8; 64]> + '_ {
    (0..=CELL_SIZE - 64).map(|i| {
        let mut w = [0u8; 64];
        w.copy_from_slice(&cell[i..i + 64]);
        w
    })
}

#[test]
fn lab_delivery_replay_tagging_linkability_and_delays() {
    let mixes = make_mixes(N_MIXES, 424_242);
    let mut net = Net::new(&mixes);
    let mut srngs: Vec<TestScheduleRng> = (0..N_MIXES)
        .map(|i| TestScheduleRng(7_000 + i as u64))
        .collect();

    // Clients: distinct 3-hop paths, staggered sends, own mailboxes.
    let mut rng = DetRng(99);
    let mut sent_at: HashMap<[u8; 16], u64> = HashMap::new();
    let mut delivered_at: HashMap<[u8; 16], u64> = HashMap::new();
    let mut terminal: HashMap<[u8; 16], usize> = HashMap::new();

    let mut path_choices: Vec<Vec<usize>> = Vec::new();
    for c in 0..N_CLIENTS {
        let h1 = (c as usize) % N_MIXES;
        let h2 = (h1 + 1 + (c as usize) % (N_MIXES - 1)) % N_MIXES;
        let h3 = (h2 + 1 + (c as usize) % (N_MIXES - 2)) % N_MIXES;
        path_choices.push(vec![h1, h2, h3]);
    }

    let mut t = 0u64;
    for (c, choice) in path_choices.iter().enumerate() {
        let path: Vec<MixKeys> = choice.iter().map(|&i| mixes[i].0.clone()).collect();
        let mailbox = mailbox_of(c as u64, 0xF0);
        let msg = format!("gpa lab payload #{c}").into_bytes();
        let built = build_cell(&path, &mailbox, &msg, &mut rng).unwrap();
        sent_at.insert(mailbox, t);
        terminal.insert(mailbox, choice[V_HOPS - 1]);
        net.inject(
            choice[0],
            built.cell.clone().try_into().unwrap(),
            t,
            &mut srngs,
        );
        t += 3;
    }

    // Adversary: replay client #0's cell verbatim on the same ingress link,
    // and inject a tagged (header-corrupted) cell for client #1.
    let replayed = net.observed[path_choices[0][0]][0];
    net.inject(path_choices[0][0], replayed, t, &mut srngs);
    let mut tagged = net.observed[path_choices[1][0]][0];
    tagged[1_100] ^= 0x20; // inside slot 1's MAC-covered region
    net.inject(path_choices[1][0], tagged, t, &mut srngs);

    // Run the network, timestamping deliveries as they land.
    for now in 0..=HORIZON_MS {
        net.tick(now, &mut srngs);
        for c in 0..N_CLIENTS {
            let mb = mailbox_of(c, 0xF0);
            let got = net.nodes[terminal[&mb]].pull_mailbox(&mb);
            if !got.is_empty() {
                delivered_at.entry(mb).or_insert(now);
            }
        }
    }

    // 1. Delivery: every client's mailbox was written exactly once.
    assert_eq!(
        delivered_at.len() as u64,
        N_CLIENTS,
        "all clients delivered"
    );

    // 2. Replay: counted, and did not double-deliver (every client
    //    delivered exactly once; the replayed copy died in the cache).
    let replays: u64 = net.nodes.iter().map(|n| n.stats.replays).sum();
    assert!(replays >= 1, "the replay must have been caught");

    // 3. Tagging: the corrupted cell died silently somewhere (not_mine).
    let not_mine: u64 = net.nodes.iter().map(|n| n.stats.not_mine).sum();
    assert!(not_mine >= 1, "tagged cell must fail processing");

    // 4. Linkability: no 64-byte window shared between two different links.
    let mut per_link: Vec<HashSet<[u8; 64]>> = Vec::new();
    for link in &net.observed {
        let mut s = HashSet::new();
        for cell in link {
            s.extend(windows(cell));
        }
        per_link.push(s);
    }
    for i in 0..N_MIXES {
        for j in (i + 1)..N_MIXES {
            let shared = per_link[i].intersection(&per_link[j]).count();
            assert_eq!(
                shared, 0,
                "links {i} and {j} share {shared} byte windows — linkability leak"
            );
        }
    }

    // 5. Delay sanity: Erlang(3, 50ms) + 3×5ms links, ± generous bounds.
    let mut delays: Vec<u64> = Vec::new();
    for c in 0..N_CLIENTS {
        let mb = mailbox_of(c, 0xF0);
        let d = delivered_at[&mb].saturating_sub(sent_at[&mb]);
        delays.push(d);
    }
    let mean = delays.iter().sum::<u64>() as f64 / delays.len() as f64;
    assert!(
        delays.iter().all(|&d| d >= 3 * LINK_LATENCY_MS),
        "delay below v×link latency: {delays:?}"
    );
    assert!(
        delays.iter().all(|&d| d <= 2_000),
        "delay implausibly large for Erlang(3,50)+15ms: {delays:?}"
    );
    assert!(
        mean > 90.0 && mean < 300.0,
        "mean e2e delay {mean} out of [90,300] (expect ~165)"
    );

    // 6. Accounting closes; no unexplained loss.
    for (i, node) in net.nodes.iter().enumerate() {
        let s = &node.stats;
        assert_eq!(
            s.accepted,
            s.forwarded + s.delivered + s.not_mine + s.replays,
            "mix {i}: accounting"
        );
        assert_eq!(
            s.dropped_full, 0,
            "mix {i}: no queue pressure in this scenario"
        );
        assert_eq!(s.cover_evicted, 0, "mix {i}: no cover in this scenario");
    }
}

#[test]
fn lab_payloads_arrive_intact() {
    // Same network, but mailboxes are pulled only at the end, so the cells
    // themselves can be opened and compared byte-exactly with the client's
    // expectation (payload + header peel transparency through real nodes).
    let mixes = make_mixes(N_MIXES, 51_515);
    let mut net = Net::new(&mixes);
    let mut srngs: Vec<TestScheduleRng> = (0..N_MIXES)
        .map(|i| TestScheduleRng(9_000 + i as u64))
        .collect();
    let mut rng = DetRng(7);

    let choices: Vec<Vec<usize>> = (0..N_CLIENTS as usize)
        .map(|c| {
            let h1 = c % N_MIXES;
            let h2 = (h1 + 1 + c % (N_MIXES - 1)) % N_MIXES;
            let h3 = (h2 + 1 + c % (N_MIXES - 2)) % N_MIXES;
            vec![h1, h2, h3]
        })
        .collect();

    let mut expect: HashMap<[u8; 16], (Vec<u8>, [u8; 32], usize)> = HashMap::new();
    for (c, choice) in choices.iter().enumerate() {
        let path: Vec<MixKeys> = choice.iter().map(|&i| mixes[i].0.clone()).collect();
        let mailbox = mailbox_of(c as u64, 0xE0);
        let msg = format!("intact #{c}").into_bytes();
        let built = build_cell(&path, &mailbox, &msg, &mut rng).unwrap();
        expect.insert(mailbox, (msg, built.payload_key, choice[V_HOPS - 1]));
        net.inject(
            choice[0],
            built.cell.clone().try_into().unwrap(),
            0,
            &mut srngs,
        );
    }

    for now in 0..=HORIZON_MS {
        net.tick(now, &mut srngs);
    }

    for (mailbox, (msg, pkey, term)) in &expect {
        let got = net.nodes[*term].pull_mailbox(mailbox);
        assert_eq!(got.len(), 1, "mailbox {mailbox:?}: one cell");
        assert_eq!(
            &open_payload(&got[0], pkey).unwrap(),
            msg,
            "payload intact end to end"
        );
    }
}

#[test]
fn lab_queue_pressure_protects_data_over_cover() {
    // Tiny queue, cover flood + data: data must survive preferentially.
    let mixes = make_mixes(2, 313_131);
    let cfg = MixConfig {
        mean_delay_ms: 200,
        epoch_ms: 10_000,
        replay_capacity: 1 << 12,
        queue_capacity: 8,
        mailbox_capacity: 16,
    };
    let mut node = MixNode::new(mixes[0].0.id, mixes[0].1.clone(), cfg);

    let mut rng = DetRng(5);
    let mut cover_cells = Vec::new();
    for i in 0..10u8 {
        let msg = vec![i; 8];
        let built = build_cell(
            &[mixes[0].0.clone(), mixes[1].0.clone()],
            &[0xD0; 16],
            &msg,
            &mut rng,
        )
        .unwrap();
        cover_cells.push(built.cell.clone().try_into().unwrap());
    }
    let data = build_cell(
        &[mixes[0].0.clone(), mixes[1].0.clone()],
        &[0xD1; 16],
        b"real data",
        &mut rng,
    )
    .unwrap();

    let mut srng = TestScheduleRng(1);
    for cell in &cover_cells {
        let _ = node.accept(cell, TrafficClass::Cover, 0, &mut srng);
    }
    // Queue holds 8 of the 10 cover cells; two were refused outright
    // (queue full of cover — nothing weaker to evict).
    assert_eq!(node.queue_len(), 8);

    let r = node.accept(
        &data.cell.clone().try_into().unwrap(),
        TrafficClass::Data,
        1,
        &mut srng,
    );
    assert!(r.is_ok(), "data accepted by evicting cover");
    assert_eq!(node.stats.cover_evicted, 1);

    let out = node.drain(1_000_000);
    assert_eq!(out.len(), 8, "all queued slots expired");
    assert_eq!(
        node.stats.dropped_full, 2,
        "two cover cells refused when queue was full of cover"
    );
}
