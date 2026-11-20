//! Kani proofs over `src/link_bounds.rs`, the very file the data plane compiles
//! (docs/VERIFICATION_PLAN.md item 1). Run: `cargo kani` in this directory.
//!
//! - No replay: within any sequence of counters, a counter is accepted at most once.
//! - Nothing older than the window: an accepted counter is less than 128 below the
//!   highest one accepted before it.
//! - Liveness: a counter above every one seen is always accepted.
//! - No amplification: from zero, under any interleaving of authenticated cells received
//!   and replies attempted, the replies sent never exceed the cells received, and the
//!   credit never exceeds its cap.

#[allow(dead_code)]
#[path = "../../../src/link_bounds.rs"]
mod link_bounds;

#[cfg(kani)]
mod proofs {
    use super::link_bounds::{Window, earn, spend};

    const N: usize = 5;

    #[kani::proof]
    #[kani::unwind(6)]
    fn no_counter_is_accepted_twice() {
        let mut w = Window::default();
        let xs: [u64; N] = kani::any();
        let mut accepted = [false; N];
        for i in 0..N {
            accepted[i] = w.accept(xs[i]);
        }
        for i in 0..N {
            for j in (i + 1)..N {
                assert!(!(accepted[i] && accepted[j] && xs[i] == xs[j]));
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn nothing_older_than_the_window_is_accepted_and_anything_newer_is() {
        let mut w = Window::default();
        let mut highest: Option<u64> = None;
        for _ in 0..N {
            let n: u64 = kani::any();
            let ok = w.accept(n);
            if let Some(h) = highest {
                if ok {
                    assert!(n > h || h - n < 128);
                }
                if n > h {
                    assert!(ok);
                }
            } else {
                assert!(ok);
            }
            if ok {
                highest = Some(highest.map_or(n, |h| h.max(n)));
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn replies_never_outnumber_authenticated_cells() {
        let cap: u64 = kani::any();
        kani::assume(cap >= 1);
        let mut credit = 0u64;
        let (mut received, mut sent) = (0u64, 0u64);
        for _ in 0..8 {
            if kani::any() {
                credit = earn(credit, cap);
                received += 1;
            } else if let Some(c) = spend(credit) {
                credit = c;
                sent += 1;
            }
            assert!(credit <= cap);
            assert!(sent <= received);
            assert!(sent + credit <= received);
        }
    }
}
