//! The link's arithmetic state, kept free of dependencies so that
//! `crates/avpn-kani` model-checks this very file (docs/VERIFICATION_PLAN.md item 1):
//! the replay window, and the reply credit that keeps a link from amplifying.

/// Sliding 128-cell replay window over one sender session's counters.
#[derive(Default)]
pub(crate) struct Window {
    highest: Option<u64>,
    seen: u128,
}

impl Window {
    /// Whether `n` is new (accepting it marks it seen).
    pub(crate) fn accept(&mut self, n: u64) -> bool {
        match self.highest {
            None => {
                self.highest = Some(n);
                self.seen = 1;
                true
            }
            Some(h) if n > h => {
                let shift = n - h;
                self.seen = if shift >= 128 { 0 } else { self.seen << shift };
                self.seen |= 1;
                self.highest = Some(n);
                true
            }
            Some(h) => {
                let back = h - n;
                if back >= 128 || self.seen & (1u128 << back) != 0 {
                    return false;
                }
                self.seen |= 1u128 << back;
                true
            }
        }
    }
}

/// Reply credit after one authenticated cell from the peer: one more, at most `cap`.
pub(crate) fn earn(credit: u64, cap: u64) -> u64 {
    credit.saturating_add(1).min(cap)
}

/// Reply credit after sending one cell to the peer; `None`: no credit, send nothing.
pub(crate) fn spend(credit: u64) -> Option<u64> {
    credit.checked_sub(1)
}
