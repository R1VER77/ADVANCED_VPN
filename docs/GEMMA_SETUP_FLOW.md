# Gemma-centric setup flow

Owner direction, 20 November 2026 ([decision D007](DECISIONS.md)). Setup is one ordered
flow, led conversationally by a local Gemma model inside the app. It replaces the separate
roadmap items for provisioning, hardware setup, the GUI and the assistant
([roadmap §3](ROADMAP.md)).

## The flow

1. **First launch: provisioning.** The app opens in the conversation, not the main window.
   Gemma walks the person through:
   - the hardware key: detection, ranking ([device ranking](DEVICE_COMPATIBILITY_VALIDATION.md)),
     repairs, vault creation and the client's enrollment request;
   - where the chain runs: a provider from the narrowed catalog (below), or a server the
     person already has (SSH);
   - provisioning through pinned OpenTofu modules: exact-plan preview with cost, then
     apply, with teardown on failure;
   - signing the chain with the key and enrolling this device.
2. **When provisioning completes, the GUI appears**: the status, map and controls of
   `apps/cypherpunk-vpn`, showing the new profile.
3. **Every later launch** first checks for a viable profile:
   - none: back to step 1;
   - one or more: choose one, or add another (step 1 again, the existing ones kept).

A **viable profile** is an enrolled chain whose signed bundle verifies and is current
(`require_current`), whose protection is intact (hardware or TPM sealing as required), and
whose servers answered the last health check (`avpn cloud health`), or which the person
chooses to check now. A profile with a problem is listed with its problem and fix (the
same findings as `avpn cloud health`: stopped, locked, out of credits), not hidden.

## What Gemma does, and does not

Unchanged from [D002](DECISIONS.md): setup stays deterministic underneath.

- Gemma leads the conversation, explains each step and the typed findings, and proposes
  the next action by calling **typed tools**: the same controller checks, setup engine
  (`setup_cli`), cloud planner and OpenTofu plan/apply wrappers the CLI uses.
- The deterministic engine validates every call and runs it. Gemma never runs a shell
  command, writes a file or reaches the network itself.
- The person approves every privileged or billable change in a native dialog outside the
  model, which repeats the exact plan, cost and digest.
- Hardware PINs and touches stay on the key's own prompt; cloud credentials stay in the
  provider CLIs' stores. Neither enters the model's context, and Gemma cannot certify
  protection: status comes only from controller evidence.

## What Gemma knows

The catalog is already narrowed to providers qualified for this VPN
(`tools/providers.py`, `avpn cloud suggest`), not the thousands in the OpenTofu registry:

- tested free tiers: Oracle (OCI), AWS and Azure; Google Cloud as a beacon only;
- paid hosts, including non-US legal spheres: Hetzner, netcup, OVHcloud, 1984 Hosting,
  Infomaniak, Exoscale, IONOS, RackNerd;
- any server the person already has, over SSH.

Each provider joins the catalog only with a reviewed, pinned OpenTofu module and a live
qualification. Gemma is trained (or tuned) for the conversation and the tool calls over
this catalog. Its facts come at run time from the versioned catalog and provider
documentation shipped with the release: the roadmap's rule that training does not replace
current documentation stands, so a changed provider flow is fixed in the catalog, not by
retraining.

## Gates

- Every tool call is typed and validated by the engine; adversarial tests show the model
  cannot run an unlisted action, skip an approval or see a secret.
- The same flow works without Gemma (CLI and plain GUI steps), so a model failure never
  blocks setup.
- Usability with new participants, and an evaluation of the model's guidance against the
  deterministic engine on every catalog provider, before it is the default.
- Multiple profiles need the client to hold more than one enrolled chain (today one,
  `/etc/advanced-vpn/enrolled`): a profile store with an active selection.
