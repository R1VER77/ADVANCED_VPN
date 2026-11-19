# cypherpunk_vpn desktop/controller contract

Version 1, 17 November 2026. Authoritative implementations are
`tools/controller_bridge.py`, `tools/controller_backend.py`,
`tools/controller_status.py` and `crates/cypherpunk-controller`.

## Trust boundary

The ordinary-user Tauri app keeps one system-bus connection. Its unique name,
bus ID and UID come from the bus driver, never GUI arguments. The root broker uses
Polkit with a system-bus-name subject. Observe access requires an active local
session; applying an action requires administrator authentication for that action.
The shipped policy does not retain administrator authorization.

Public interface: `org.cypherpunk_vpn.Controller1`, object
`/org/cypherpunk_vpn/Controller1`. Each response is a bounded JSON string with
`schema: 1`. Tauri exposes only these seven explicitly allowed commands:

| D-Bus method | Input | Result |
|---|---|---|
| GetSnapshot | none | public status |
| GetSetup | create or join | deterministic checklist |
| SearchProviders | query, cursor, filter | bounded local discovery page |
| PreviewAction | strict action JSON | inert reviewed plan |
| ApplyAction | 64-character plan ID | operation ID and progress |
| GetOperation | caller-owned operation ID | progress |
| CancelOperation | caller-owned operation ID | cancellation requested |

`SearchProviders` uses observe authorization only and cannot create an action plan,
download a plugin or provision a server. Query size is at most 256 UTF-8 bytes,
cursor size at most 512 characters and a page contains at most 50 public entries.
The D-Bus cursor is an empty string for the first page; the worker receives JSON null.
Opaque cursors bind the index, query and filter; they are not authorization tokens.
The worker loads only the digest-pinned index inside its authenticated application
slot. Listing and review-candidate flags never enable provisioning. No reviewed
OpenTofu recipes ship yet. The create screen supports local search and tentative
selection, with that limit visible. Search does not log or transmit query text.

`GetPlan` is an inherited-pipe lookup used inside the native broker, not a public
D-Bus method. Before authorization the broker obtains the caller-owned stored plan
and sends its canonical summary, effects and action digest to the native Polkit
agent. The worker mutex is released while authentication is pending. Cancellation
requires observe permission and exact operation ownership, without a second admin
prompt. A refused request preserves the caller's live bus connection.

The privileged Python worker accepts inherited private pipes only. Its executable
and scripts come from the native broker's physical application slot. It receives
no caller-controlled environment or command. Public failures omit raw diagnostics.

## Plans and actions

Plans bind the bus identity, UID, canonical input SHA-256, configuration generation,
checked device/profile inputs and displayed effects. They expire after 90 monotonic
seconds and are consumed once, including on failure. Apply rechecks the live inputs
under the cooperating mutation lock. A changed device or profile requires a new plan.
There are at most 32 plans globally and four per caller.

Allowed actions: connect with explicit scope, disconnect, retry, hardware unlock,
create a client device request, bounded enrollment import, install a reviewed udev
rule, and enable the selected YubiKey FIDO2 interface. No shell, arbitrary command,
PIN, credential, firmware update, key reset or recovery phrase is accepted.
Enrollment supplies canonical base64 bytes (bundle at most 1 MiB; operator public
key at most 8 KiB), never a privileged path. Signatures and device binding are
inspected before native hardware authentication or installation. Operator trust
requires a separately verified public-key fingerprint.

Cancellation signals only the owned operation/prompt. Completed durable changes
remain reflected in subsequent checks. It never clears a guard or rewinds counters.

## Status and evidence

Status includes `observed_at`, actual active `scope`, `state`, `protection`,
`kill_switch` and public signed-route endpoints. A valid client profile is required.
The current profile format has no signed geographic coordinates: `chain` remains
empty, and the map may not supply invented locations. Hardware vault protection is
reported as hardware; systemd-creds is not automatically described as a TPM.

A protected verdict requires a controller status inode no older than 1.5 seconds,
a live controller PID/start identity, live child PID/start identities, explicit
active guard, supervising state and all three fresh measurements:

| Evidence | Maximum age |
|---|---:|
| Mutual cloak key confirmation | 3 seconds |
| Carrier handshake | 3 seconds |
| Whole-path probe | 15 seconds |

An explicit blocked verdict requires fresh controller evidence and the active guard.
Contradictions, stale status, absent scope and dead/reused PIDs yield unknown. The GUI
also expires its displayed status after three seconds. After a stopped supervisor,
this implementation does not yet independently verify retained kernel rules, so it
shows unknown rather than asserting a blocked state from old files.

Applications scope protects applications launched in the VPN namespace. Whole-device
scope opts into the persistent independent boot guard and network-manager ordering.
Neither mode currently offers a hotspot/forwarding service: whole-device policy
drops forwarded IPv4 and IPv6 packets. Unlock means answer a hardware prompt; it
never means cleartext. Explicit CLI reset is separate from these GUI actions.

## Remaining gates

Native bus spoofing/authorization tests, actual WebKit flow, complete owner/provider
onboarding, physical enrolled/reboot recovery, five participant sessions and the
open build-toolchain dependency advisory remain tracked in the main plan. A
compiling boundary or simulated setup is not production qualification.
