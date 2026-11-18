"""Interpret recorder/observer evidence without selecting away failed browser loads."""

import math


def bracket(rows, start, end, max_gap=1.5):
    """Require finite, ordered wall/monotonic observations surrounding the window."""
    if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in (start, end)) or end <= start:
        return None, "invalid_window"
    if not rows or any(
        not all(isinstance(r.get(k), (int, float)) and math.isfinite(r[k]) for k in ("time", "monotonic")) for r in rows
    ):
        return None, "missing_or_invalid_observations"
    if any(b["time"] < a["time"] or b["monotonic"] < a["monotonic"] for a, b in zip(rows, rows[1:], strict=False)):
        return None, "observation_clock_reversed"
    before = [i for i, r in enumerate(rows) if r["time"] <= start]
    after = [i for i, r in enumerate(rows) if r["time"] >= end]
    if not before or not after:
        return None, "observations_do_not_cover_window"
    points = rows[max(before) : min(after) + 1]
    for a, b in zip(points, points[1:], strict=False):
        elapsed = b["monotonic"] - a["monotonic"]
        if elapsed > max_gap:
            return None, "observation_gap"
        if abs((b["time"] - a["time"]) - elapsed) > 0.1:
            return None, "observation_clock_step"
    return points, None


def capture_window(report, heartbeats, start, end):
    """A zero-drop, clean-stop recorder window; loss or absent evidence invalidates capture."""
    if (
        report.get("schema") != 1
        or report.get("timestamp_source") not in ("kernel_time64", "linux_pcap_host_ns")
        or report.get("clean_stop") is not True
    ):
        return dict(valid=False, reason="recorder_not_verified_or_not_stopped")
    if report.get("drops") != 0 or report.get("malformed") != 0:
        return dict(valid=False, reason="capture_drop_or_malformed_packet")
    points, reason = bracket(heartbeats, start, end)
    if reason:
        return dict(valid=False, reason=reason)
    if any(r.get("drops") != 0 for r in points):
        return dict(valid=False, reason="capture_drops_during_window")
    return dict(
        valid=True,
        reason="kernel_timestamps_zero_drops_and_bracketed_heartbeats",
        observations=len(points),
        underlay_audit_passed=report.get("unexpected_outgoing") == 0,
    )


def protection_window(rows, start, end, defended):
    """Report sampled evidence separately; no sampling interval proves continuous protection."""
    points, reason = bracket(rows, start, end)
    if reason:
        return dict(observed=False, all_samples_protected=False, reason=reason)
    expected = "protected" if defended else "control"
    wrong = sum(r.get("protection") != expected for r in points)
    return dict(
        observed=True,
        observations=len(points),
        unexpected_samples=wrong,
        all_samples_protected=defended and wrong == 0,
        control_samples_valid=not defended and wrong == 0,
        reason="sampled_evidence_only_not_continuous_proof",
    )
