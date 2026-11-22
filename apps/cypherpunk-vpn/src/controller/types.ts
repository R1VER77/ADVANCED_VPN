// The controller's status object (CONTROLLER_CONTRACT.md). The GUI renders it; it never
// decides on its own whether traffic is protected.

export type State =
  | 'unknown'
  | 'not_enrolled'
  | 'locked'
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'failed'
  | 'cleartext_allowed'

export type Protection = 'protected' | 'blocked' | 'unprotected' | 'unknown'

export type Reason =
  | 'network_down'
  | 'relay_unreachable'
  | 'server_auth_failed'
  | 'chain_outdated'
  | 'nitrokey_pin_rejected'
  | 'nitrokey_missing'
  | 'firewall_tampering'
  | 'privacy_budget'
  | 'service_stopped'

export type Next =
  | 'wait'
  | 'retry'
  | 'resign_chain'
  | 'unlock'
  | 'insert_key'
  | 'restart_service'
  | 'wait_or_raise_limit'
  | 'start_service'

export type Rate = 'metered' | 'standard' | 'fast' | 'line'

export interface Hop {
  hop: 'relay' | 'middle' | 'exit'
  provider: string
  region: string
  country: string // ISO 3166 alpha-2
  city: string
  lat: number // the region's location (from the profile, never looked up)
  lon: number
}

export interface Evidence {
  cloak_confirmed_at: number
  carrier_handshake_at: number
  path_probe_at: number
}

export interface Status {
  schema: 1
  observed_at: number
  scope: 'applications' | 'whole-device' | 'none' | 'unknown'
  enrolled: boolean
  state: State
  protection: Protection
  since: number
  reason: Reason | null
  next: Next | null
  detail?: string
  evidence?: Evidence
  chain: Hop[]
  rate: Rate | null
  kill_switch: 'active' | 'none' | 'unknown'
  unlock: 'nitrokey' | 'hardware' | 'systemd-creds' | 'none'
  crypto: { kex: string; auth: string; cloak: string } | null
  exit_ip: string | null
}

export type EnrollError = 'bundle_invalid' | 'bundle_wrong_operator' | 'bundle_expired'

export type CommandResult = { ok: true; status: Status } | { ok: false; reason: string; detail?: string }

/** What the GUI may ask of the controller. The kill switch has no "off", by design. */
export interface Controller {
  status(): Promise<Status>
  connect(): Promise<CommandResult>
  disconnect(): Promise<CommandResult>
  retry(): Promise<CommandResult>
  enroll(bundle: string): Promise<CommandResult>
  setRate(rate: Rate): Promise<CommandResult>
  startService(): Promise<CommandResult>
  readonly kind: 'mock' | 'real'
}

/** The GUI-side state when the controller cannot be read at all. */
export const UNAVAILABLE = 'controller_unavailable' as const

/** Evidence older than this means the controller must not say "protected". */
export const EVIDENCE_MAX_AGE = { cloak_confirmed_at: 3, carrier_handshake_at: 3, path_probe_at: 15 }

export type SetupBranch = 'create' | 'join'
export interface ProviderListing {
  id: string
  namespace: string
  name: string
  tier: 'recipe_candidate' | 'listed_only'
  reviewed_recipe_candidate: boolean
  recipe_available: boolean
  can_launch_provisioning: boolean
}
export interface ProviderSearchPage {
  schema: 1
  index_sha256: string
  total_matches: number
  returned: number
  next_cursor: string | null
  results: ProviderListing[]
}
export type StepState = 'pending' | 'running' | 'waiting_for_user' | 'waiting_for_hardware' | 'blocked' | 'failed' | 'complete' | 'skipped'
export interface SetupFinding { code: string; severity: 'ok' | 'info' | 'warning' | 'blocker'; message: string; repair: string | null }
export interface SetupStep {
  id: string
  title: string
  state: StepState
  say: string
  actions: ActionRequest[]
  findings?: SetupFinding[]
}
export interface KeySoftwareRow { package: string; installed: string | null; candidate: string | null; state: 'ok' | 'missing' | 'upgrade' | 'unavailable' }
export interface SetupSnapshot {
  schema: 1
  branch: SetupBranch
  complete: number
  total: number
  current: string | null
  finished: boolean
  steps: SetupStep[]
  device_request?: { text: string; sha256: string } | null
  key_software?: KeySoftwareRow[]
  key_device?: { name: string; firmware: string | null; firmware_source: 'fido2' | 'usb' | null; open_firmware: boolean
    verification: 'pin' | 'on_device' | null; pin_retries: number | null } | null
}
export type ActionRequest =
  | { action: 'connect'; scope: 'applications' | 'whole-device' }
  | { action: 'disconnect' | 'retry' | 'unlock' | 'request_device' }
  | { action: 'repair'; repair: 'install_udev_rule' | 'yubikey_enable_fido2'; selector: string | null }
  | { action: 'import_bundle'; bundle_base64: string; operator_key_base64: string; replace: boolean }
  | { action: 'key_software'; mode: 'install' | 'upgrade' }
  // The setup wizard's create-branch writes (tools/controller_create_join.py):
  // branch-bound, previewed through the same Preview/Apply contract, and the
  // backend always states the cover-traffic allowance (--accept-cost is CLI-only).
  | { action: 'create_operator_keys' | 'request_exit'; branch: 'create' }
  | { action: 'sign_route'; branch: 'create'; hops: 1 | 2 | 3; exit: string; relay?: string; middle?: string;
      cover_name?: string; allowance_gib: number; extra_requests: { role: 'relay' | 'middle'; name: string }[] }
export interface ActionPlan {
  schema: 1
  id: string
  input_digest: string
  generation: string
  expires_at: number
  summary: string
  effects: string[]
}
export interface Operation {
  schema: 1
  id: string
  state: 'running' | 'waiting_for_user' | 'waiting_for_hardware' | 'complete' | 'failed' | 'cancelled'
  message: string
}

// The observation commands (controller_extension.py): reads only. The GUI
// renders these; it never derives protection claims from them.
export interface StreamingEligibilityRow {
  kind: 'measured' | 'class-knowledge'
  exit: string | null
  provider: string | null
  service: string
  region: string | null
  result: string
  transport_profile: string | null
  checked: string | null
  stale: boolean
  unmeasured: boolean
}
export interface StreamingEligibility {
  schema: 1
  rows: StreamingEligibilityRow[]
  source: string
  generated: string | null
  note: string
}
export interface MultihopPreset {
  name: string
  hops: number
  label: string
  description: string
  rate: string | null
  requires: string | null
}
export interface MultihopPresets {
  schema: 1
  presets: MultihopPreset[]
  default: string
  ceiling: number
  note: string
}
export interface AutoconnectPolicy {
  schema: 1
  enabled: boolean
  wired_trusted: boolean
  trusted_ssids_count: number
  note: string
}

// The own-servers side of setup (tools/desktop_setup.py, run as this user).
export interface CatalogProvider {
  key: string; service: string; company: string; parent: string; tier: 1 | 2 | 3
  server_usd: number | null; egress_gb: number | 'unmetered' | null; over_usd_gb: number | null
  month_usd: number | null; how: 'create' | 'ssh'; why: string; note: string; source: string
}
export interface ProviderCatalog { schema: 1; checked: string; plan_gb: number; providers: CatalogProvider[] }
export interface RecordedServer {
  name: string; provider: string; role: string | null; region: string | null; address: string
  family: 'ipv4' | 'ipv6'; sphere: string | null; in_chain: boolean; first_hop_ok: boolean
}
export interface OperatorState {
  schema: 1
  profile: { name: string; created: string; providers: string[]; hours_per_day: number; active_providers: number
    checked: Record<string, { ready: boolean; why: string; at: string }> }
  servers: RecordedServer[]
  chain: { hops: string[]; created: string | null; operator_vault: boolean }
}
export interface BuildEvent {
  event: 'progress' | 'done' | 'error'
  plan?: string[]; step?: number; state?: 'run' | 'wait' | 'done'; note?: string
  hops?: string[]; bundle_base64?: string; operator_base64?: string; message?: string; error?: string
  server?: string; profile?: string
}
export interface BuildStatus { schema: 1; running: boolean; events: BuildEvent[] }
