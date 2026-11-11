//! The DAITA (Maybenot) machines the WireGuard carrier runs, built here so they can be tested.
//!
//! There is exactly one defense posture: **strong**. The `balanced` profile was
//! removed (AVPN/Mesh, carrier schema 3): a dial that trades security for speed is
//! one users cannot calibrate. Every carrier, on every hop, runs the full stack:
//!
//! - NetFlow padding (idle links do not form flow records),
//! - FRONT decoys, re-armed for every burst of traffic,
//! - Tamaraw constant-rate shaping with a stop machine that rounds every trace to
//!   a multiple of [`TAMARAW_L`] packets on the constant clock,
//! - [`cover`]: bidirectional constant-rate cover. After the first tunnel activity
//!   each endpoint emits one decoy per [`COVER_INTERVAL_SECONDS`] until the run
//!   ends, so idle links keep a constant stream and real sessions hide among the
//!   scheduled cover. Node-level daily cover budgets are enforced by the
//!   controller (`tools/mesh.py`), never by weakening the machines.
//!
//! Every hop builds its machines from its own OS-seeded RNG, so the schedules are
//! independent per hop: identical shaping at every hop would preserve cross-link
//! correlation, and client-side-only shaping is eroded by downstream queueing
//! (see docs/MESH_DESIGN.md and the measurements in tools/mesh_wf_sim.py).
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

/// FRONT, re-armed. Where the generator's machine ends, it instead cools down, then
/// watches for [`BURST_PACKETS`] data packets within [`BURST_WINDOW_SECONDS`] and, on
/// seeing them, runs its padding states again.
pub fn rearmed_front(front: Machine) -> Machine {
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
    timer(&mut cool, FRONT_COOLDOWN_SECONDS * MICROS);
    // Watch: start a burst window and expect BURST_PACKETS data packets within it.
    let mut w = State::new(enum_map! {
        Event::NormalSent | Event::NormalRecv => vec![Trans(count, 1.0)],
        Event::TimerEnd => vec![Trans(watch, 1.0)],
        _ => vec![],
    });
    timer(&mut w, BURST_WINDOW_SECONDS * MICROS);
    w.counter = (
        Some(Counter {
            operation: Operation::Set,
            dist: Some(constant(BURST_PACKETS)),
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

/// FRONT with its window in microseconds, as Maybenot expects, re-armed for every burst.
pub fn front<R: RngCore>(rng: &mut R) -> Vec<Machine> {
    maybenot_machines::front::front(
        FRONT_BUDGET_MAX,
        FRONT_WINDOW_SECONDS.0 * MICROS,
        FRONT_WINDOW_SECONDS.1 * MICROS,
        FRONT_STATES,
        rng,
    )
    .into_iter()
    .map(rearmed_front)
    .collect()
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

/// Tamaraw: upstream's padding machine (once a trace starts, it holds back data and
/// sends one packet, data or decoy, every [`TAMARAW_INTERVAL_SECONDS`]) with this stop
/// machine instead of upstream's.
///
/// Upstream's stop machine stops counting packets once data flows, then ends each
/// trace with about [`TAMARAW_L`] decoys sent 1 µs apart: a burst that marks exactly
/// when the page finished, while the trace's length is not rounded at all. This one
/// counts every packet sent, data and decoy, and once no data was sent for
/// [`TAMARAW_STOP_MICROS`], keeps the constant clock running until the count reaches a
/// multiple of [`TAMARAW_L`]. Data that turns up meanwhile simply continues the trace.
pub fn tamaraw() -> Vec<Machine> {
    let mut machines =
        maybenot_machines::tamaraw::tamaraw(TAMARAW_INTERVAL_SECONDS, TAMARAW_STOP_MICROS);
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
    let l = Some(TAMARAW_L);
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
    timer(&mut s_arm, TAMARAW_STOP_MICROS);
    let mut s_reset = running(None);
    timer(&mut s_reset, TAMARAW_STOP_MICROS);
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

/// Bidirectional constant-rate cover. Once any tunnel activity is seen, the machine
/// emits one decoy every [`COVER_INTERVAL_SECONDS`] and re-arms itself on every decoy
/// it sends, so the stream is self-sustaining while the run is up. Every endpoint of
/// every hop runs it, which makes the cover bidirectional: each direction of each
/// link carries a constant-rate stream, real packets replacing same-direction decoys.
///
/// The machine is deliberately unbudgeted (`u64::MAX`): resource limits belong to the
/// node's operator and are enforced by the controller's daily cover budget
/// (`tools/mesh.py`), fail-closed at the carrier level by the existing byte budget —
/// never by weakening the defense mid-run.
pub fn cover() -> Machine {
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
        timeout: constant(COVER_INTERVAL_SECONDS * MICROS),
        limit: None,
    });
    Machine::new(u64::MAX, 0.0, 0, 0.0, vec![start, tick]).expect("a valid cover machine")
}

/// Every machine the carrier runs. There is one posture — strong — and every hop of
/// every chain runs the full set, built from this endpoint's own OS-seeded RNG so
/// each hop's schedule is independent (see the module docs).
pub fn machines<R: RngCore>(rng: &mut R) -> Vec<Machine> {
    let mut machines = vec![maybenot_machines::netflow::simple_netflow()];
    machines.extend(front(rng));
    machines.extend(tamaraw());
    machines.push(cover());
    machines
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
        let (mut next, mut sent) = (0, vec![]);
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
        sent
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
            let strong = machines(&mut rand::rngs::StdRng::seed_from_u64(0));
            let sent = padding_times(&strong[2..], &data, start + 15.0);
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
        assert!(sent.is_empty(), "cover must not run before the tunnel is used");
    }

    #[test]
    fn the_machine_set_is_strong_only_and_complete() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        // netflow + FRONT + Tamaraw (padding and stop) + cover.
        assert_eq!(machines(&mut rng).len(), 5);
    }
}
