//! The DAITA (Maybenot) machines the WireGuard carrier runs, built here so they can be tested.
//!
//! There is exactly one defense posture: a **constant-rate stream**, on every hop.
//! After the tunnel's first packet, each endpoint holds every outgoing packet
//! ([`hold`]) and releases traffic only in fixed slots on one constant clock
//! ([`stream`]): each slot carries one queued data packet or, when none is waiting, a
//! same-size decoy. The wire therefore shows the same rate, the same sizes and the same
//! timing whether the user is idle, loading a page or downloading: there are no page
//! boundaries for a classifier to cut out, no bursts, and no direction-specific shape.
//!
//! Speed is the slot rate, not a security dial: [`RateClass`] fixes the clock and the
//! number of slots per tick for the whole chain at signing time, so every class is the
//! same traffic-independent stream and differs only in cost (bytes per day while
//! connected). See `docs/evidence/RATE_CLASSES.json`.
//!
//! Earlier versions stacked netflow padding, re-armed FRONT, Tamaraw and a separate
//! cover clock. Measured with this module's own harness, the cover clock *added* to
//! Tamaraw's instead of replacing it: 50 packets/s idle became about 119 packets/s
//! during a page load, which marked every load. One clock replaces them all; the
//! FRONT and Tamaraw builders stay below as tested library pieces, not shipped.
//!
//! Maybenot times are in microseconds. The public FRONT generator takes its padding
//! window in those units, unlike Tamaraw, which takes seconds and scales them itself.
//! A window of 1.0 is therefore 1 µs: all of FRONT's padding leaves at once. The
//! generator's machine also runs only once, at the first packet of the tunnel's life.
//! Here the window is given in microseconds, and FRONT is re-armed: after each run it
//! waits for a burst of traffic (a page load, say), and pads again around it.
use enum_map::enum_map;
use maybenot::{
    Machine,
    action::Action,
    constants::STATE_END,
    counter::{Counter, Operation},
    dist::{Dist, DistType},
    event::Event,
    state::{State, Trans},
};
use rand::RngCore;

/// Most decoys one FRONT run may send (each run's budget is drawn below this).
pub const FRONT_BUDGET_MAX: u32 = 256;
/// FRONT's padding window, in seconds, drawn between these two once per tunnel.
pub const FRONT_WINDOW_SECONDS: (f64, f64) = (1.0, 4.0);
/// FRONT approximates its padding curve with this many states.
pub const FRONT_STATES: usize = 8;
/// FRONT runs again when this many data packets pass within [`BURST_WINDOW_SECONDS`].
/// Keepalives on an idle tunnel stay far below it; any page load passes it at once.
pub const BURST_PACKETS: f64 = 12.0;
/// The time window in which [`BURST_PACKETS`] must pass.
pub const BURST_WINDOW_SECONDS: f64 = 1.0;
/// Least time between the end of one FRONT run and the start of the next.
pub const FRONT_COOLDOWN_SECONDS: f64 = 5.0;
/// Tamaraw sends one packet every this many seconds, in each direction.
pub const TAMARAW_INTERVAL_SECONDS: f64 = 0.02;
/// Tamaraw stops when no data packet was sent for this many microseconds.
pub const TAMARAW_STOP_MICROS: f64 = 500_000.0;
/// Tamaraw rounds each trace up to a multiple of this many packets per direction, so
/// at one packet per [`TAMARAW_INTERVAL_SECONDS`] its length in time rounds up to a
/// multiple of 2 s: every page whose load ends in the same 2 s step looks the same.
pub const TAMARAW_L: f64 = 100.0;
/// Cover sends one packet every this many seconds. Kept equal to the Tamaraw clock so
/// cover and shaped traffic are indistinguishable on the wire.
pub const COVER_INTERVAL_SECONDS: f64 = TAMARAW_INTERVAL_SECONDS;
const MICROS: f64 = 1_000_000.0;

fn constant(value: f64) -> Dist {
    Dist {
        dist: DistType::Uniform {
            low: value,
            high: value,
        },
        start: 0.0,
        max: 0.0,
    }
}

fn timer(state: &mut State, micros: f64) {
    state.action = Some(Action::UpdateTimer {
        replace: true,
        duration: constant(micros),
        limit: None,
    });
}

/// FRONT, re-armed, with explicit parameters. Where the generator's machine ends, it
/// instead cools down, then watches for `burst_packets` data packets within
/// `burst_window_seconds` and, on seeing them, runs its padding states again.
pub fn rearmed_front_with(
    front: Machine,
    burst_packets: f64,
    burst_window_seconds: f64,
    cooldown_seconds: f64,
) -> Machine {
    let n = front.states.len();
    let (cooldown, watch, count) = (n, n + 1, n + 2);
    let mut states: Vec<State> = front
        .states
        .into_iter()
        .map(|s| {
            let mut transitions = s.get_transitions();
            for (_, targets) in transitions.iter_mut() {
                for t in targets.iter_mut().filter(|t| t.0 == STATE_END) {
                    t.0 = cooldown;
                }
            }
            let mut state = State::new(transitions);
            state.action = s.action;
            state.counter = s.counter;
            state
        })
        .collect();
    let mut cool = State::new(enum_map! {
        Event::TimerEnd => vec![Trans(watch, 1.0)],
        _ => vec![],
    });
    timer(&mut cool, cooldown_seconds * MICROS);
    // Watch: start a burst window and expect burst_packets data packets within it.
    let mut w = State::new(enum_map! {
        Event::NormalSent | Event::NormalRecv => vec![Trans(count, 1.0)],
        Event::TimerEnd => vec![Trans(watch, 1.0)],
        _ => vec![],
    });
    timer(&mut w, burst_window_seconds * MICROS);
    w.counter = (
        Some(Counter {
            operation: Operation::Set,
            dist: Some(constant(burst_packets)),
            copy: false,
        }),
        None,
    );
    // Count: each data packet takes one off; reaching zero starts FRONT's first padding state.
    let mut c = State::new(enum_map! {
        Event::NormalSent | Event::NormalRecv => vec![Trans(count, 1.0)],
        Event::CounterZero => vec![Trans(1, 1.0)],
        Event::TimerEnd => vec![Trans(watch, 1.0)],
        _ => vec![],
    });
    c.counter = (
        Some(Counter {
            operation: Operation::Decrement,
            dist: None,
            copy: false,
        }),
        None,
    );
    states.extend([cool, w, c]);
    Machine::new(
        front.allowed_padding_packets,
        front.max_padding_frac,
        front.allowed_blocked_microsec,
        front.max_blocking_frac,
        states,
    )
    .expect("a re-armed FRONT machine is valid")
}

/// FRONT, re-armed, with the shipped constants.
pub fn rearmed_front(front: Machine) -> Machine {
    rearmed_front_with(
        front,
        BURST_PACKETS,
        BURST_WINDOW_SECONDS,
        FRONT_COOLDOWN_SECONDS,
    )
}

/// FRONT with explicit parameters: the window in seconds (converted to the
/// microseconds Maybenot expects), re-armed for every burst.
pub fn front_with<R: RngCore>(
    budget_max: u32,
    window_seconds: (f64, f64),
    states: usize,
    burst_packets: f64,
    burst_window_seconds: f64,
    cooldown_seconds: f64,
    rng: &mut R,
) -> Vec<Machine> {
    maybenot_machines::front::front(
        budget_max,
        window_seconds.0 * MICROS,
        window_seconds.1 * MICROS,
        states,
        rng,
    )
    .into_iter()
    .map(|m| rearmed_front_with(m, burst_packets, burst_window_seconds, cooldown_seconds))
    .collect()
}

/// FRONT with its window in microseconds, as Maybenot expects, re-armed for every burst.
pub fn front<R: RngCore>(rng: &mut R) -> Vec<Machine> {
    front_with(
        FRONT_BUDGET_MAX,
        FRONT_WINDOW_SECONDS,
        FRONT_STATES,
        BURST_PACKETS,
        BURST_WINDOW_SECONDS,
        FRONT_COOLDOWN_SECONDS,
        rng,
    )
}

fn counter(operation: Operation, value: Option<f64>) -> (Option<Counter>, Option<Counter>) {
    let dist = value.map(constant);
    (
        Some(Counter {
            operation,
            dist,
            copy: false,
        }),
        None,
    )
}

/// Tamaraw with explicit parameters: upstream's padding machine (once a trace starts,
/// it holds back data and sends one packet, data or decoy, every `interval_seconds`)
/// with this stop machine instead of upstream's.
///
/// Upstream's stop machine stops counting packets once data flows, then ends each
/// trace with about `l` decoys sent 1 µs apart: a burst that marks exactly
/// when the page finished, while the trace's length is not rounded at all. This one
/// counts every packet sent, data and decoy, and once no data was sent for
/// `stop_micros`, keeps the constant clock running until the count reaches a
/// multiple of `l`. Data that turns up meanwhile simply continues the trace.
pub fn tamaraw_with(interval_seconds: f64, stop_micros: f64, l: f64) -> Vec<Machine> {
    let mut machines = maybenot_machines::tamaraw::tamaraw(interval_seconds, stop_micros);
    machines.truncate(1);
    // Upstream's padding machine leaves its next decoy armed when the trace ends, so one
    // decoy trails every trace. End instead in a start state that cancels it.
    let padding = machines
        .pop()
        .expect("upstream Tamaraw has a padding machine");
    let mut states = padding.states;
    let restart = states.len();
    let mut t = states[2].get_transitions();
    t[Event::BlockingEnd] = vec![Trans(restart, 1.0)];
    let action = states[2].action;
    states[2] = State::new(t);
    states[2].action = action;
    let mut cancel = State::new(states[0].get_transitions());
    cancel.action = Some(Action::Cancel {
        timer: maybenot::action::Timer::Action,
    });
    states.push(cancel);
    machines.push(
        Machine::new(
            padding.allowed_padding_packets,
            padding.max_padding_frac,
            padding.allowed_blocked_microsec,
            padding.max_blocking_frac,
            states,
        )
        .expect("a valid Tamaraw padding machine"),
    );
    let (wait, arm, reset, count, refill, tail, tail_count, end) = (0, 1, 2, 3, 4, 5, 6, 7);
    let l = Some(l);
    // While a trace runs: count every sent packet, and restart the stop window on data.
    let running = |extra: Option<(Event, usize)>| {
        let mut t = enum_map! {
            Event::TunnelSent => vec![Trans(count, 1.0)],
            Event::NormalSent => vec![Trans(reset, 1.0)],
            Event::TimerEnd => vec![Trans(tail, 1.0)],
            _ => vec![],
        };
        if let Some((event, to)) = extra {
            t[event] = vec![Trans(to, 1.0)];
        }
        State::new(t)
    };
    let s_wait = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(arm, 1.0)],
        _ => vec![],
    });
    let mut s_arm = running(None);
    s_arm.counter = counter(Operation::Set, l);
    timer(&mut s_arm, stop_micros);
    let mut s_reset = running(None);
    timer(&mut s_reset, stop_micros);
    let mut s_count = running(Some((Event::CounterZero, refill)));
    s_count.counter = counter(Operation::Decrement, None);
    let mut s_refill = running(None);
    s_refill.counter = counter(Operation::Set, l);
    // Stopping: the padding machine keeps its clock; count its packets to the next multiple.
    let s_tail = State::new(enum_map! {
        Event::TunnelSent => vec![Trans(tail_count, 1.0)],
        Event::NormalSent => vec![Trans(reset, 1.0)],
        _ => vec![],
    });
    let mut s_tail_count = State::new(enum_map! {
        Event::TunnelSent => vec![Trans(tail_count, 1.0)],
        Event::NormalSent => vec![Trans(reset, 1.0)],
        Event::CounterZero => vec![Trans(end, 1.0)],
        _ => vec![],
    });
    s_tail_count.counter = counter(Operation::Decrement, None);
    // A zero-length block ends the padding machine's blocking, and with it the trace.
    let mut s_end = State::new(enum_map! {
        Event::BlockingEnd => vec![Trans(wait, 1.0)],
        _ => vec![],
    });
    s_end.action = Some(Action::BlockOutgoing {
        bypass: true,
        replace: true,
        timeout: constant(0.0),
        duration: constant(0.0),
        limit: None,
    });
    let states = vec![
        s_wait,
        s_arm,
        s_reset,
        s_count,
        s_refill,
        s_tail,
        s_tail_count,
        s_end,
    ];
    machines.push(
        Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, states).expect("a valid Tamaraw stop machine"),
    );
    machines
}

/// Tamaraw with the shipped constants.
pub fn tamaraw() -> Vec<Machine> {
    tamaraw_with(TAMARAW_INTERVAL_SECONDS, TAMARAW_STOP_MICROS, TAMARAW_L)
}

/// Bidirectional constant-rate cover with an explicit clock. Once any tunnel activity
/// is seen, the machine emits one decoy every `interval_seconds` and re-arms itself on
/// every decoy it sends, so the stream is self-sustaining while the run is up. Every
/// endpoint of every hop runs it, which makes the cover bidirectional: each direction
/// of each link carries a constant-rate stream, real packets replacing same-direction
/// decoys.
///
/// The machine is deliberately unbudgeted (`u64::MAX`): resource limits belong to the
/// node's operator and are enforced by the controller's daily cover budget
/// (`tools/mesh.py`), fail-closed at the carrier level by the existing byte budget —
/// never by weakening the defense mid-run.
pub fn cover_with(interval_seconds: f64) -> Machine {
    let start = State::new(enum_map! {
        Event::NormalSent | Event::NormalRecv | Event::TunnelSent | Event::TunnelRecv =>
            vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut tick = State::new(enum_map! {
        Event::PaddingSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    tick.action = Some(Action::SendPadding {
        bypass: true,
        replace: true,
        timeout: constant(interval_seconds * MICROS),
        limit: None,
    });
    Machine::new(u64::MAX, 0.0, 0, 0.0, vec![start, tick]).expect("a valid cover machine")
}

/// Bidirectional constant-rate cover on the shipped clock.
pub fn cover() -> Machine {
    cover_with(COVER_INTERVAL_SECONDS)
}

/// How long one [`hold`] lasts before it must be renewed, in seconds.
pub const HOLD_SECONDS: f64 = 10.0;
/// [`hold`] renews itself after this many seconds, well before the hold would lapse
/// (a lapse flushes every queued packet at once: exactly the burst the stream hides).
pub const HOLD_RENEW_SECONDS: f64 = 4.0;

/// The constant clock of a chain: one tick every `clock_us` microseconds, `slots`
/// packets per tick. Fixed per chain when the operator signs it, the same on every hop,
/// never changed by traffic. Every class is the same stream; only the rate (and so the
/// bytes spent per connected hour) differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateClass {
    /// 50 slots/s: about 0.5 Mbit/s. For hops on small monthly allowances.
    Metered,
    /// 500 slots/s: about 5 Mbit/s.
    Standard,
    /// 4000 slots/s: about 40 Mbit/s.
    Fast,
    /// 16000 slots/s: about 160 Mbit/s, for unmetered hops.
    Line,
}

impl RateClass {
    /// Every class, slowest first.
    pub const ALL: [RateClass; 4] = [
        RateClass::Metered,
        RateClass::Standard,
        RateClass::Fast,
        RateClass::Line,
    ];
    /// The class's signed name.
    pub fn name(self) -> &'static str {
        match self {
            RateClass::Metered => "metered",
            RateClass::Standard => "standard",
            RateClass::Fast => "fast",
            RateClass::Line => "line",
        }
    }
    /// Parse a signed name; anything else is refused, never guessed.
    pub fn parse(name: &str) -> Option<RateClass> {
        RateClass::ALL.into_iter().find(|c| c.name() == name)
    }
    /// Microseconds between ticks. Tokio's timers resolve to about 1 ms, and an idle
    /// runtime wakes later than a busy one; at a 1 ms clock that made the idle rate
    /// measurably lower than the busy rate. No class ticks faster than every 2 ms:
    /// faster classes send more slots per tick instead.
    pub fn clock_us(self) -> u64 {
        match self {
            RateClass::Metered => 20_000,
            RateClass::Standard | RateClass::Fast | RateClass::Line => 2_000,
        }
    }
    /// Packets per tick.
    pub fn slots(self) -> u32 {
        match self {
            RateClass::Metered | RateClass::Standard => 1,
            RateClass::Fast => 8,
            RateClass::Line => 32,
        }
    }
    /// Packets per second in each direction of each link.
    pub fn packets_per_second(self) -> f64 {
        self.slots() as f64 * 1e6 / self.clock_us() as f64
    }
}

/// Hold every outgoing packet from the tunnel's first packet on, renewing the hold
/// before it lapses. Held packets leave only through [`stream`]'s slots.
pub fn hold() -> Machine {
    let (block, wait) = (1, 2);
    let s_start = State::new(enum_map! {
        Event::NormalSent | Event::NormalRecv | Event::TunnelSent | Event::TunnelRecv =>
            vec![Trans(block, 1.0)],
        _ => vec![],
    });
    let mut s_block = State::new(enum_map! {
        Event::BlockingBegin => vec![Trans(wait, 1.0)],
        _ => vec![],
    });
    s_block.action = Some(Action::BlockOutgoing {
        bypass: true,
        replace: true,
        timeout: constant(0.0),
        duration: constant(HOLD_SECONDS * MICROS),
        limit: None,
    });
    let mut s_wait = State::new(enum_map! {
        Event::TimerEnd => vec![Trans(block, 1.0)],
        _ => vec![],
    });
    timer(&mut s_wait, HOLD_RENEW_SECONDS * MICROS);
    Machine::new(u64::MAX, 0.0, u64::MAX, 0.0, vec![s_start, s_block, s_wait])
        .expect("a valid hold machine")
}

/// The constant-rate stream on an explicit clock: [`hold`] plus `slots` copies of the
/// slot clock ([`cover_with`]), each of whose ticks sends one held packet or a decoy.
pub fn stream(interval_seconds: f64, slots: u32) -> Vec<Machine> {
    let mut machines = vec![hold()];
    machines.extend((0..slots).map(|_| cover_with(interval_seconds)));
    machines
}

/// Every machine the carrier runs for `rate`: the constant-rate stream, the same on
/// every hop of every chain.
pub fn machines(rate: RateClass) -> Vec<Machine> {
    stream(rate.clock_us() as f64 / MICROS, rate.slots())
}

/// One entry of the ephemeral defense database (DAITA v2's idea, taken further):
/// a full randomized parameterization of the strong posture, valid for a bounded
/// window. An observer who fingerprints one parameterization finds it gone at the
/// next rotation; a captured database says nothing about future schedules.
///
/// Entries are generated offline by `tools/defense_db.py` and rotated by the
/// controller. Every field is validated fail-closed at load: out-of-range values
/// are refused, never clamped, and the cover clock must equal the Tamaraw clock
/// (cover and shaped traffic stay indistinguishable on the wire).
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefenseProfile {
    /// Opaque identifier of this entry (the generator's random tag).
    pub id: String,
    /// Start of the validity window, seconds since the epoch.
    pub not_before: u64,
    /// End of the validity window, seconds since the epoch (exclusive).
    pub not_after: u64,
    /// Tamaraw's constant clock, seconds per packet.
    pub tamaraw_interval_seconds: f64,
    /// Tamaraw's trace length quantum, packets per direction.
    pub tamaraw_l: f64,
    /// FRONT's per-run decoy budget cap.
    pub front_budget_max: u32,
    /// FRONT's padding window, seconds (the generator draws inside it once per tunnel).
    pub front_window_seconds: (f64, f64),
    /// FRONT's curve approximation depth, states.
    pub front_states: usize,
    /// Burst size that re-arms FRONT, data packets.
    pub burst_packets: f64,
    /// The window those packets must pass within, seconds.
    pub burst_window_seconds: f64,
    /// Least time between FRONT runs, seconds.
    pub front_cooldown_seconds: f64,
    /// The cover clock; must equal [`Self::tamaraw_interval_seconds`].
    pub cover_interval_seconds: f64,
}

impl DefenseProfile {
    /// Fail-closed validation; every bound mirrors SAFE_RANGES in tools/defense_db.py.
    pub fn validate(&self) -> Result<(), String> {
        let bad = |what: &str| Err(format!("defense profile {}: {what}", self.id));
        if self.id.is_empty() || self.id.len() > 64 {
            return bad("bad id");
        }
        if self.not_after <= self.not_before {
            return bad("empty validity window");
        }
        if !(0.01..=0.05).contains(&self.tamaraw_interval_seconds) {
            return bad("tamaraw interval out of range [0.01, 0.05] s");
        }
        if self.cover_interval_seconds != self.tamaraw_interval_seconds {
            return bad("cover clock must equal the tamaraw clock");
        }
        if !(50.0..=400.0).contains(&self.tamaraw_l) || self.tamaraw_l.fract() != 0.0 {
            return bad("tamaraw L out of range [50, 400] packets");
        }
        if !(64..=512).contains(&self.front_budget_max) {
            return bad("FRONT budget out of range [64, 512]");
        }
        let (lo, hi) = self.front_window_seconds;
        if !(0.5..=8.0).contains(&lo) || !(0.5..=8.0).contains(&hi) || lo > hi {
            return bad("FRONT window out of range [0.5, 8.0] s");
        }
        if !(4..=32).contains(&self.front_states) {
            return bad("FRONT states out of range [4, 32]");
        }
        if !(4.0..=32.0).contains(&self.burst_packets) {
            return bad("burst size out of range [4, 32] packets");
        }
        if !(0.25..=4.0).contains(&self.burst_window_seconds) {
            return bad("burst window out of range [0.25, 4.0] s");
        }
        if !(1.0..=30.0).contains(&self.front_cooldown_seconds) {
            return bad("FRONT cooldown out of range [1, 30] s");
        }
        Ok(())
    }
}

/// The ephemeral defense database: a sequence of [`DefenseProfile`] windows.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefenseDb {
    /// Database schema; 1 is the only version.
    pub schema: u32,
    /// The rotation schedule; entries may abut but should not overlap.
    pub profiles: Vec<DefenseProfile>,
}

impl DefenseDb {
    /// Load and fully validate a database from a private file (0600, owned, no links).
    pub fn load(path: &std::path::Path) -> anyhow::Result<DefenseDb> {
        use anyhow::{Context, ensure};
        let db: DefenseDb = serde_json::from_slice(&crate::config::private_read(path, 1 << 20)?)
            .context("defense database is not valid JSON")?;
        ensure!(db.schema == 1, "unsupported defense database schema");
        for p in &db.profiles {
            p.validate().map_err(anyhow::Error::msg)?;
        }
        Ok(db)
    }

    /// The profile in force at `now` (seconds since the epoch), if any: the entry
    /// with the latest `not_before` whose window contains `now`.
    pub fn select(&self, now: u64) -> Option<&DefenseProfile> {
        self.profiles
            .iter()
            .filter(|p| p.not_before <= now && now < p.not_after)
            .max_by_key(|p| p.not_before)
    }
}

/// The stream built from one ephemeral profile: the same constant-rate stream as
/// [`machines`], on the profile's clock (one slot per tick). Only the metered range of
/// clocks is valid in a profile (see [`DefenseProfile::validate`]).
pub fn machines_from_profile(profile: &DefenseProfile) -> Vec<Machine> {
    stream(profile.cover_interval_seconds, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maybenot::{Framework, MachineId, TriggerAction, TriggerEvent};
    use rand::SeedableRng;
    use std::time::{Duration, Instant};

    /// Drive `machines` through the real Maybenot framework, as GotaTun does, given the
    /// times (seconds) of the tunnel's data packets. Every padding timer fires on time.
    /// Returns when each padding packet left.
    fn padding_times(machines: &[Machine], packets: &[f64], end: f64) -> Vec<Duration> {
        simulate(machines, packets, end).0
    }

    /// As [`padding_times`], also returning when any hold lapsed (a `BlockingEnd`).
    fn simulate(machines: &[Machine], packets: &[f64], end: f64) -> (Vec<Duration>, Vec<Duration>) {
        let t0 = Instant::now();
        let mut fw =
            Framework::new(machines, 0.5, 0.5, t0, rand::rngs::StdRng::seed_from_u64(1)).unwrap();
        let k = machines.len();
        let mut action: Vec<Option<Duration>> = vec![None; k];
        let mut internal: Vec<Option<Duration>> = vec![None; k];
        let mut block_begin: Option<(Duration, usize)> = None;
        let mut block_end: Option<Duration> = None;
        let mut packets: Vec<Duration> = packets
            .iter()
            .map(|s| Duration::from_secs_f64(*s))
            .collect();
        packets.sort();
        let (mut next, mut sent, mut lapses) = (0, vec![], vec![]);
        loop {
            let mut due: Vec<(Duration, u8, usize)> = vec![];
            if let Some(p) = packets.get(next) {
                due.push((*p, 0, 0));
            }
            for i in 0..k {
                due.extend(action[i].map(|t| (t, 1, i)));
                due.extend(internal[i].map(|t| (t, 2, i)));
            }
            due.extend(block_begin.map(|(t, i)| (t, 3, i)));
            due.extend(block_end.map(|t| (t, 4, 0)));
            let Some(&(now, kind, i)) = due.iter().min() else {
                break;
            };
            if now > Duration::from_secs_f64(end) {
                break;
            }
            let events = match kind {
                0 => {
                    next += 1;
                    vec![TriggerEvent::NormalSent, TriggerEvent::TunnelSent]
                }
                1 => {
                    action[i] = None;
                    sent.push(now);
                    let machine = MachineId::from_raw(i);
                    vec![
                        TriggerEvent::PaddingSent { machine },
                        TriggerEvent::TunnelSent,
                    ]
                }
                2 => {
                    internal[i] = None;
                    vec![TriggerEvent::TimerEnd {
                        machine: MachineId::from_raw(i),
                    }]
                }
                3 => {
                    block_begin = None;
                    vec![TriggerEvent::BlockingBegin {
                        machine: MachineId::from_raw(i),
                    }]
                }
                _ => {
                    block_end = None;
                    lapses.push(now);
                    vec![TriggerEvent::BlockingEnd]
                }
            };
            let actions: Vec<TriggerAction> =
                fw.trigger_events(&events, t0 + now).cloned().collect();
            for a in actions {
                match a {
                    TriggerAction::SendPadding {
                        timeout, machine, ..
                    } => action[machine.into_raw()] = Some(now + timeout),
                    TriggerAction::UpdateTimer {
                        duration,
                        replace,
                        machine,
                    } => {
                        let j = machine.into_raw();
                        if replace || internal[j].is_none_or(|t| now + duration > t) {
                            internal[j] = Some(now + duration);
                        }
                    }
                    TriggerAction::Cancel { machine, .. } => action[machine.into_raw()] = None,
                    TriggerAction::BlockOutgoing {
                        timeout,
                        duration,
                        machine,
                        ..
                    } => {
                        block_begin = Some((now + timeout, machine.into_raw()));
                        block_end = Some(now + timeout + duration);
                    }
                }
            }
        }
        (sent, lapses)
    }

    /// An idle tunnel's keepalives (one every 0.7 s), with page loads (60 packets in
    /// 0.2 s) at the given times.
    fn browsing(loads: &[f64], end: f64) -> Vec<f64> {
        let mut p: Vec<f64> = (0..(end / 0.7) as usize).map(|i| i as f64 * 0.7).collect();
        for l in loads {
            p.extend((0..60).map(|i| l + i as f64 * 0.2 / 60.0));
        }
        p
    }

    fn between(t: &[Duration], a: f64, b: f64) -> Vec<f64> {
        t.iter()
            .map(Duration::as_secs_f64)
            .filter(|s| (a..b).contains(s))
            .collect()
    }

    #[test]
    fn front_pads_every_page_load_over_seconds_and_stays_quiet_when_idle() {
        for seed in 0..20 {
            let machines = front(&mut rand::rngs::StdRng::seed_from_u64(seed));
            let sent = padding_times(&machines, &browsing(&[0.0, 30.0, 60.0], 90.0), 90.0);
            for load in [0.0, 30.0, 60.0] {
                let run = between(&sent, load, load + 25.0);
                assert!(
                    !run.is_empty(),
                    "seed {seed}: no padding around the load at {load} s"
                );
                if run.len() > 3 {
                    // Spread over the window, not sent in one instant (the 1-4 µs bug).
                    let spread = run.last().unwrap() - run.first().unwrap();
                    assert!(
                        spread > 0.3,
                        "seed {seed}: {} decoys within {spread} s at {load} s",
                        run.len()
                    );
                }
            }
            // Keepalives alone never start a run.
            let idle = padding_times(&machines, &browsing(&[0.0], 90.0), 90.0);
            assert!(
                between(&idle, 25.0, 90.0).is_empty(),
                "seed {seed}: padding while idle"
            );
        }
    }

    #[test]
    fn front_waits_out_its_cooldown() {
        let machines = front(&mut rand::rngs::StdRng::seed_from_u64(3));
        // Continuous traffic: 20 packets a second for 60 s.
        let busy: Vec<f64> = (0..1200).map(|i| i as f64 * 0.05).collect();
        let sent = padding_times(&machines, &busy, 60.0);
        let mut runs = 0;
        let mut last = -100.0;
        for s in sent.iter().map(Duration::as_secs_f64) {
            if s - last > FRONT_COOLDOWN_SECONDS {
                runs += 1;
            }
            last = s;
        }
        // Each run lasts at least about the 1 s window, and FRONT_COOLDOWN_SECONDS separates them.
        assert!((2..=10).contains(&runs), "{runs} runs in 60 s");
    }

    #[test]
    fn the_shipped_generator_call_would_send_everything_at_once() {
        // Guard the reasoning above: the generator takes microseconds.
        let old = maybenot_machines::front::front(
            256,
            1.0,
            4.0,
            8,
            &mut rand::rngs::StdRng::seed_from_u64(7),
        );
        let sent = padding_times(&old, &[0.0, 60.0], 120.0);
        assert!(!sent.is_empty());
        assert!(sent.iter().all(|t| *t < Duration::from_millis(1)));
    }

    /// Gaps between consecutive padding packets, in seconds.
    fn gaps(sent: &[Duration]) -> Vec<f64> {
        sent.windows(2)
            .map(|w| (w[1] - w[0]).as_secs_f64())
            .collect()
    }

    #[test]
    fn tamaraw_rounds_every_trace_on_its_clock() {
        // Three page loads of different length: data every 30 ms for 1, 2.5 and 4 s.
        for (start, length) in [(0.0, 1.0), (20.0, 2.5), (40.0, 4.0)] {
            let data: Vec<f64> = (0..(length / 0.03) as usize)
                .map(|i| start + i as f64 * 0.03)
                .collect();
            let sent = padding_times(&tamaraw(), &data, start + 15.0);
            // Constant clock to the end: no burst anywhere.
            assert!(
                gaps(&sent).iter().all(|g| *g > 0.005),
                "load at {start} s: padding burst"
            );
            // Every packet counted, none trailing: data plus decoys is a multiple of L
            // (the first data packet goes out before blocking starts).
            let total = data.len() + sent.len();
            assert!(
                matches!(total % TAMARAW_L as usize, 0 | 1),
                "load at {start} s: {total} packets"
            );
            // And it stops.
            assert!(sent.last().unwrap().as_secs_f64() < start + length + 4.0);
        }
    }

    #[test]
    fn tamaraw_loads_in_the_same_step_look_the_same() {
        // Data every 30 ms for `length` seconds: total packets and when the trace ends.
        let trace = |length: f64| {
            let data: Vec<f64> = (0..(length / 0.03) as usize)
                .map(|i| i as f64 * 0.03)
                .collect();
            let sent = padding_times(&tamaraw(), &data, 20.0);
            (data.len() + sent.len(), sent.len())
        };
        // Here data is not held back into Tamaraw's slots as the carrier does, so a load
        // runs at about 66 packets/s, not 50: 0.6 s and 0.9 s still fall in one step, but
        // only the packet count is compared. (The DAITA lab measures timing on the carrier.)
        let (short, longer, long) = (trace(0.6), trace(0.9), trace(3.0));
        assert_eq!(short.0, longer.0, "0.6 s and 0.9 s loads differ in packets");
        let steps = (long.0 - short.0) as f64 / TAMARAW_L;
        assert!(
            steps >= 1.0 && steps.fract() == 0.0,
            "3 s load: {long:?} vs {short:?}"
        );
    }

    #[test]
    fn upstream_tamaraw_ends_in_a_burst() {
        // Guard the reasoning above: upstream's stop machine sends its tail 1 µs apart.
        let data: Vec<f64> = (0..100).map(|i| i as f64 * 0.03).collect();
        let upstream =
            maybenot_machines::tamaraw::tamaraw(TAMARAW_INTERVAL_SECONDS, TAMARAW_STOP_MICROS);
        let sent = padding_times(&upstream, &data, 15.0);
        assert!(gaps(&sent).iter().filter(|g| **g < 0.001).count() > 50);
    }

    #[test]
    fn cover_ticks_on_its_constant_clock_once_started() {
        // One data packet starts the cover; it then sustains itself on its own decoys.
        let sent = padding_times(&[cover()], &[0.0], 10.0);
        assert!(sent.len() > 400, "{} cover packets in 10 s", sent.len());
        for g in gaps(&sent) {
            assert!(
                (g - COVER_INTERVAL_SECONDS).abs() < 0.002,
                "cover gap {g} s off the {COVER_INTERVAL_SECONDS} s clock"
            );
        }
    }

    #[test]
    fn cover_stays_silent_before_any_activity() {
        let sent = padding_times(&[cover()], &[], 10.0);
        assert!(
            sent.is_empty(),
            "cover must not run before the tunnel is used"
        );
    }

    #[test]
    fn every_class_is_a_hold_plus_its_slots() {
        for class in RateClass::ALL {
            assert_eq!(machines(class).len(), 1 + class.slots() as usize);
            assert_eq!(RateClass::parse(class.name()), Some(class));
        }
        assert_eq!(RateClass::parse("balanced"), None);
        assert_eq!(RateClass::parse(""), None);
    }

    /// Wire packets per second in [a, b): every slot tick is one packet on the wire,
    /// whether it carries held data or a decoy.
    fn rate(sent: &[Duration], a: f64, b: f64) -> f64 {
        between(sent, a, b).len() as f64 / (b - a)
    }

    /// The posture the stream replaced: netflow + re-armed FRONT + Tamaraw + cover.
    fn stacked() -> Vec<Machine> {
        let mut m = vec![maybenot_machines::netflow::simple_netflow()];
        m.extend(front(&mut rand::rngs::StdRng::seed_from_u64(0)));
        m.extend(tamaraw());
        m.push(cover());
        m
    }

    /// One packet starts the tunnel; a 3 s page load (data every 30 ms) at 20 s.
    fn idle_then_load() -> Vec<f64> {
        let mut data = vec![0.0];
        data.extend((0..100).map(|i| 20.0 + i as f64 * 0.03));
        data
    }

    /// The shape gate: the wire rate is the same idle, during a load, and after it.
    fn assert_constant(machines: &[Machine], per_second: f64) {
        let sent = padding_times(machines, &idle_then_load(), 40.0);
        for (a, b) in [(5.0, 15.0), (20.0, 23.0), (30.0, 40.0)] {
            let r = rate(&sent, a, b);
            assert!(
                (r - per_second).abs() / per_second < 0.02,
                "{r:.1} packets/s in [{a}, {b}) s, expected {per_second}"
            );
        }
    }

    #[test]
    fn the_stream_is_the_same_idle_and_during_a_load() {
        for class in [RateClass::Metered, RateClass::Standard] {
            assert_constant(&machines(class), class.packets_per_second());
        }
        // Faster classes in a shorter window: same gate.
        let fast = machines(RateClass::Fast);
        let sent = padding_times(&fast, &idle_then_load(), 24.0);
        assert!(RateClass::ALL.iter().all(|c| c.clock_us() >= 2_000));
        let (idle, load) = (rate(&sent, 10.0, 15.0), rate(&sent, 20.0, 23.0));
        let want = RateClass::Fast.packets_per_second();
        assert!((idle - want).abs() / want < 0.02, "fast idle {idle:.0}/s");
        assert!((load - want).abs() / want < 0.02, "fast load {load:.0}/s");
    }

    #[test]
    fn the_stacked_posture_marked_every_load() {
        // Guard the reasoning in the module docs: cover added to Tamaraw's clock.
        let sent = padding_times(&stacked(), &idle_then_load(), 40.0);
        assert!(rate(&sent, 20.0, 23.0) > 1.5 * rate(&sent, 5.0, 15.0));
    }

    #[test]
    fn the_hold_never_lapses() {
        // A lapse flushes every held packet at once. Renewal keeps the hold for good.
        let (_, lapses) = simulate(&[hold()], &idle_then_load(), 120.0);
        assert!(lapses.is_empty(), "hold lapsed at {lapses:?}");
    }

    #[test]
    fn nothing_is_sent_before_the_tunnel_is_used() {
        for class in RateClass::ALL {
            let (sent, lapses) = simulate(&machines(class), &[], 5.0);
            assert!(sent.is_empty() && lapses.is_empty());
        }
    }

    fn sample_profile(id: &str, not_before: u64, not_after: u64) -> DefenseProfile {
        DefenseProfile {
            id: id.to_string(),
            not_before,
            not_after,
            tamaraw_interval_seconds: 0.03,
            tamaraw_l: 150.0,
            front_budget_max: 200,
            front_window_seconds: (1.0, 3.0),
            front_states: 8,
            burst_packets: 10.0,
            burst_window_seconds: 1.0,
            front_cooldown_seconds: 4.0,
            cover_interval_seconds: 0.03,
        }
    }

    #[test]
    fn a_valid_profile_passes_and_builds_the_stream() {
        let p = sample_profile("a", 100, 200);
        assert!(p.validate().is_ok());
        let m = machines_from_profile(&p);
        assert_eq!(m.len(), 2);
        assert_constant(&m, 1.0 / p.cover_interval_seconds);
    }

    #[test]
    fn validation_is_fail_closed_on_every_bound() {
        let cases: Vec<fn(&mut DefenseProfile)> = vec![
            |p| p.id = String::new(),
            |p| p.not_after = p.not_before,
            |p| p.tamaraw_interval_seconds = 0.5,
            |p| p.cover_interval_seconds = 0.04, // must equal the tamaraw clock
            |p| p.tamaraw_l = 33.3,
            |p| p.tamaraw_l = 10.0,
            |p| p.front_budget_max = 1,
            |p| p.front_window_seconds = (9.0, 10.0),
            |p| p.front_window_seconds = (3.0, 1.0),
            |p| p.front_states = 1,
            |p| p.burst_packets = 100.0,
            |p| p.burst_window_seconds = 0.01,
            |p| p.front_cooldown_seconds = 0.0,
        ];
        for (i, mutate) in cases.into_iter().enumerate() {
            let mut p = sample_profile("x", 100, 200);
            mutate(&mut p);
            assert!(p.validate().is_err(), "case {i} must be refused");
        }
    }

    #[test]
    fn select_picks_the_window_containing_now() {
        let db = DefenseDb {
            schema: 1,
            profiles: vec![
                sample_profile("old", 0, 100),
                sample_profile("current", 100, 200),
                sample_profile("next", 200, 300),
            ],
        };
        assert_eq!(db.select(50).map(|p| p.id.as_str()), Some("old"));
        assert_eq!(db.select(150).map(|p| p.id.as_str()), Some("current"));
        assert_eq!(db.select(200).map(|p| p.id.as_str()), Some("next"));
        assert!(
            db.select(300).is_none(),
            "no profile in force: refuse, never guess"
        );
    }

    #[test]
    fn profiled_tamaraw_rounds_on_its_own_quantum() {
        // The parameterized stop machine rounds to the profile's L, not the constant.
        let p = sample_profile("q", 0, 1);
        let machines = tamaraw_with(p.tamaraw_interval_seconds, TAMARAW_STOP_MICROS, p.tamaraw_l);
        let data: Vec<f64> = (0..40).map(|i| i as f64 * 0.03).collect();
        let sent = padding_times(&machines, &data, 20.0);
        let total = data.len() + sent.len();
        assert!(
            matches!(total % p.tamaraw_l as usize, 0 | 1),
            "{total} packets not on the L={} quantum",
            p.tamaraw_l
        );
    }
}
