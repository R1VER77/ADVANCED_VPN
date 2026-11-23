// DEMONSTRATION ONLY: a simulated controller. It touches no network, no firewall, no key.
// It follows CONTROLLER_CONTRACT.md so the real adapter can replace it unchanged.
import { countryName, routeOf } from './locations'
import type { CommandResult, Controller, Hop, Rate, Reason, State, Status } from './types'

export type Fault = 'network_down' | 'server_auth_failed' | 'controller_unavailable' | 'service_stopped'

export interface MockOptions {
  /** What the simulated system PIN dialog will answer. */
  pinOutcome: 'ok' | 'wrong' | 'no_key'
}

const DEFAULT_ROUTE = ['sto', 'fra'] // Stockholm entry, Frankfurt exit

const now = () => Math.floor(Date.now() / 1000)

export class MockController implements Controller {
  readonly kind = 'mock' as const
  options: MockOptions = { pinOutcome: 'ok' }
  /** Called when the simulated system PIN dialog should appear (the real one is pinentry). */
  onPinRequest: ((answer: (ok: boolean) => void) => void) | null = null
  private s: Status
  private unavailable = false
  private networkUp = true
  private timers: number[] = []
  private pinRetries = 8
  private chain: Hop[] = routeOf(DEFAULT_ROUTE)

  constructor(start: 'fresh' | 'disconnected' | 'connected' = 'fresh') {
    this.s = this.base(start === 'fresh' ? 'not_enrolled' : 'disconnected')
    if (start !== 'fresh') this.s.enrolled = true
    if (start === 'connected') this.toConnected()
  }

  private base(state: State): Status {
    return {
      schema: 1, observed_at: now(), scope: 'applications', enrolled: false, state, protection: state === 'not_enrolled' ? 'unprotected' : 'blocked',
      since: now(), reason: null, next: null, chain: [], rate: null, kill_switch: 'none', unlock: 'none',
      crypto: null, exit_ip: null,
    }
  }

  private set(state: State, extra: Partial<Status> = {}) {
    const enrolled = this.s.enrolled
    const protection = state === 'connected' ? 'protected' : state === 'cleartext_allowed' ? 'unprotected' : 'blocked'
    this.s = {
      ...this.s, state, protection, since: now(), reason: null, next: null, detail: undefined,
      evidence: undefined, exit_ip: null, ...extra,
    }
    if (enrolled) {
      this.s.enrolled = true
      this.s.chain = this.chain
      this.s.kill_switch = 'active'
      this.s.unlock = 'nitrokey'
      this.s.rate ??= 'fast'
      this.s.crypto = { kex: 'X25519MLKEM768', auth: 'ML-DSA-65', cloak: 'v2' }
    }
  }

  private clearTimers() {
    this.timers.forEach((t) => clearTimeout(t))
    this.timers = []
  }

  private after(ms: number, f: () => void) {
    this.timers.push(window.setTimeout(f, ms))
  }

  private toConnected() {
    const t = now()
    this.set('connected', {
      evidence: { cloak_confirmed_at: t, carrier_handshake_at: t, path_probe_at: t },
      exit_ip: '203.0.113.7',
    })
  }

  private fail(reason: Reason, next: Status['next'], detail?: string) {
    this.clearTimers()
    this.set('failed', { reason, next, detail })
  }

  private ok(): CommandResult {
    return { ok: true, status: structuredClone(this.s) }
  }

  private guard(): CommandResult | null {
    return this.unavailable ? { ok: false, reason: 'controller_unavailable' } : null
  }

  async status(): Promise<Status> {
    if (this.unavailable) throw new Error('controller_unavailable')
    if (this.s.state === 'connected' && this.s.evidence) {
      this.s.evidence.path_probe_at = now() // the real controller re-probes every few seconds
      this.s.evidence.carrier_handshake_at = now()
    }
    this.s.observed_at = now()
    return structuredClone(this.s)
  }

  async connect(): Promise<CommandResult> {
    const g = this.guard()
    if (g) return g
    if (!this.s.enrolled) return { ok: false, reason: 'not_enrolled' }
    this.clearTimers()
    this.set('locked', { detail: 'Enter your Nitrokey PIN in the system dialog, then touch the key' })
    const ask = (resolve: (ok: boolean) => void) => {
      if (this.onPinRequest) this.onPinRequest(resolve)
      else this.after(800, () => resolve(true))
    }
    ask((entered) => {
      if (!entered) return this.set('disconnected')
      if (this.options.pinOutcome === 'no_key') return this.fail('nitrokey_missing', 'insert_key')
      if (this.options.pinOutcome === 'wrong') {
        this.pinRetries -= 1
        return this.fail('nitrokey_pin_rejected', 'unlock', `${this.pinRetries} attempts left before the key locks`)
      }
      this.build()
    })
    return this.ok()
  }

  private build(from: 'connecting' | 'reconnecting' = 'connecting') {
    const steps: [number, string][] = [
      [0, 'Reaching the first server over HTTP/3'],
      [900, 'Checking that the server proves your key (post-quantum)'],
      [1800, `Building the chain through ${this.through()}`],
      [2700, 'Verifying that traffic only leaves through the chain'],
    ]
    for (const [ms, text] of steps) this.after(ms, () => this.set(from, { detail: text }))
    this.after(3600, () => {
      if (!this.networkUp) return this.set('reconnecting', { reason: 'network_down', next: 'wait' })
      this.toConnected()
    })
  }

  async disconnect(): Promise<CommandResult> {
    const g = this.guard()
    if (g) return g
    this.clearTimers()
    this.set(this.s.enrolled ? 'disconnected' : 'not_enrolled')
    return this.ok()
  }

  async retry(): Promise<CommandResult> {
    const g = this.guard()
    if (g) return g
    this.clearTimers()
    if (!this.networkUp) {
      this.set('reconnecting', { reason: 'network_down', next: 'wait' })
      return this.ok()
    }
    this.build(this.s.state === 'reconnecting' ? 'reconnecting' : 'connecting')
    return this.ok()
  }

  async enroll(bundle: string): Promise<CommandResult> {
    const g = this.guard()
    if (g) return g
    await new Promise((r) => setTimeout(r, 900))
    if (!bundle.endsWith('.cpvpn') || bundle.includes('corrupt')) return { ok: false, reason: 'bundle_invalid' }
    if (bundle.includes('other-operator')) return { ok: false, reason: 'bundle_wrong_operator' }
    if (bundle.includes('expired')) return { ok: false, reason: 'bundle_expired' }
    this.s.enrolled = true
    this.set('disconnected')
    return this.ok()
  }

  async setRate(rate: Rate): Promise<CommandResult> {
    const g = this.guard()
    if (g) return g
    this.s.rate = rate
    if (this.s.state === 'connected') {
      this.clearTimers()
      this.build('reconnecting')
    }
    return this.ok()
  }

  async startService(): Promise<CommandResult> {
    await new Promise((r) => setTimeout(r, 1200))
    this.unavailable = false
    this.clearTimers()
    this.set(this.s.enrolled ? 'disconnected' : 'not_enrolled')
    return this.ok()
  }

  // --- Demo controls: inject what the real world would do -------------------------------
  inject(fault: Fault) {
    switch (fault) {
      case 'network_down':
        this.networkUp = false
        if (this.s.state === 'connected' || this.s.state === 'connecting') {
          this.clearTimers()
          this.set('reconnecting', { reason: 'network_down', next: 'wait', detail: 'Waiting for a network' })
        }
        break
      case 'server_auth_failed':
        this.fail('server_auth_failed', 'resign_chain',
          'The first server could not prove it holds your key. It may be an impostor, or your chain was signed for an older protocol.')
        break
      case 'controller_unavailable':
        this.unavailable = true
        this.clearTimers()
        break
      case 'service_stopped':
        this.unavailable = true
        this.clearTimers()
        break
    }
  }

  /** Demo: the route a new device file would carry. Connected, it rebuilds through it. */
  setRoute(ids: string[]) {
    this.chain = routeOf(ids)
    if (!this.s.enrolled) return
    this.s.chain = this.chain
    if (['connected', 'connecting', 'reconnecting'].includes(this.s.state)) {
      this.clearTimers()
      this.build('reconnecting')
    }
  }

  private through() {
    const names = [...new Set(this.chain.map((h) => countryName(h.country)))]
    return names.length > 1 ? names.slice(0, -1).join(', ') + ' and ' + names[names.length - 1] : names[0]
  }

  restoreNetwork() {
    this.networkUp = true
    if (this.s.state === 'reconnecting') {
      this.clearTimers()
      this.build('reconnecting')
    }
  }

  get demo() {
    return { networkUp: this.networkUp, unavailable: this.unavailable }
  }
}
