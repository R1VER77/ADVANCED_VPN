# Streaming eligibility (generated)

Version 2026-11-21.1, generated 2026-11-21T11:04:11+00:00.

> Streaming eligibility is measured per exit, per service, dated in the exit's descriptor; run `avpn stream-check` to test yours. No blanket 'works with service X' claim is made or implied by this table.

Rows older than 30 days are marked `stale` and must be re-measured before use.

## Measured (from `avpn stream-check` records)

| Exit | Service | Region | Result | Transport | Checked | State |
|---|---|---|---|---|---|---|
| _no measurements yet — be the first: `avpn run -- stream-check netflix`_ | | | | | | |

## Class knowledge (unmeasured background, replaced by any measurement)

| Provider class | Service | Result | Note |
|---|---|---|---|
| AWS | Netflix | blocked (class, unmeasured) |  |
| Google Cloud | Netflix | blocked (class, unmeasured) |  |
| Hetzner | BBC iPlayer | blocked (class, unmeasured) |  |
| Hetzner | Netflix | blocked (class, unmeasured) | r/selfhosted and devrunners.com report Hetzner ranges blocked by Netflix |
| Oracle Cloud | Netflix | blocked (class, unmeasured) | the owner's current OCI exit is believed blocked; measure it with `avpn run -- stream-check netflix` to replace this row |
