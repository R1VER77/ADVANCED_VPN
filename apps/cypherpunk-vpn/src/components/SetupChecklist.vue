<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { controller, operator } from '../controller/real'
import catalogJson from '../controller/providers.json'
import ProviderLogo from './ProviderLogo.vue'
import ProviderSheet from './ProviderSheet.vue'
import type { ActionRequest, BuildEvent, Operation, OperatorState, ProviderCatalog, RecordedServer, SetupSnapshot, Status } from '../controller/types'

// One setup, run in order once the person starts it. Steps that need no decision run by
// themselves (the system's own password, PIN and touch prompts still ask); choosing
// providers and a route, building the route on billable servers, upgrades and connecting
// are the person's own clicks. Nothing is copied or pasted by hand.
const props = defineProps<{ status: Status | null; fresh: boolean }>()
const catalog = catalogJson as ProviderCatalog
const USABLE_KEYS = ['Nitrokey 3', 'Solo 2', 'CanoKey', 'TKey', 'Trezor', 'YubiKey 5', 'Ledger']
const SPHERES: Record<string, string> = { US: 'US', DE: 'German', FR: 'French', CH: 'Swiss', IS: 'Icelandic', KN: 'Nevis' }

const started = ref(false)
const open = ref(true)
const setup = ref<SetupSnapshot | null>(null)
const ops = ref<OperatorState | null>(null)
const sheet = ref(false)
const busy = ref(false)
const activity = ref<{ title: string; effects: string[]; message: string } | null>(null)
const error = ref('')
const attempted = new Set<string>()
const mode = ref<'own' | 'join'>('own')
const order = ref<string[]>([])
const hops = ref(2)
const hours = ref(8)
const scope = ref<'applications' | 'whole-device'>('applications')
const build = ref<{ running: boolean; plan: string[]; step: number; note: string; installing: boolean; failed: boolean } | null>(null)
// A route server whose cloud sign-in ran out: the build stops before the key is asked for anything.
const signedOut = ref<{ server: string; profile: string } | null>(null)
const signingIn = ref(false)
// The build's own steps, then installing the signed route here; each row is done, working or waiting.
const INSTALL = 'Install the signed route on this device'
const buildRows = computed(() => build.value ? [...build.value.plan, INSTALL].map((title, i) => ({
  title, done: i < build.value!.step, working: i === build.value!.step && (build.value!.running || build.value!.installing),
  failed: build.value!.failed && i === Math.max(build.value!.step, 0),
})) : [])
const bundle = ref<File | null>(null)
const operatorKey = ref<File | null>(null)
let timer = 0

const step = (id: string) => setup.value?.steps.find(s => s.id === id)
const keyStep = computed(() => step('key'))
const device = computed(() => setup.value?.key_device ?? null)
const deviceLine = computed(() => {
  const d = device.value
  if (!d) return ''
  return [d.name, d.firmware ? `firmware ${d.firmware}` : 'firmware not reported', d.open_firmware ? 'open firmware' : 'closed firmware',
    d.verification === 'on_device' ? 'PIN entered on the key' : 'PIN typed on this computer',
    d.pin_retries !== null ? `${d.pin_retries} PIN tries left` : ''].filter(Boolean).join(' · ')
})
const working = computed(() => busy.value || !!build.value?.running || (started.value && !setup.value))
const software = computed(() => setup.value?.key_software ?? [])
const missing = computed(() => software.value.filter(r => r.state === 'missing'))
const upgrades = computed(() => software.value.filter(r => r.state === 'upgrade'))
const enrolled = computed(() => !!props.status?.enrolled || step('profile')?.state === 'complete')
const connected = computed(() => props.fresh && props.status?.state === 'connected' && props.status.protection === 'protected')

const stages = computed(() => {
  const s = [
    { id: 'key', title: 'Security key', done: keyStep.value?.state === 'complete' },
    { id: 'software', title: 'Key software', done: !!setup.value && missing.value.length === 0 },
    { id: 'device', title: 'Device keys', done: step('vault')?.state === 'complete' },
  ]
  if (mode.value === 'own') {
    s.push({ id: 'providers', title: 'Cloud providers', done: (ops.value?.profile.active_providers ?? 0) > 0 })
    s.push({ id: 'route', title: 'Route and jurisdictions', done: enrolled.value })
  } else {
    s.push({ id: 'join', title: 'Device file from your operator', done: enrolled.value })
  }
  s.push({ id: 'connect', title: 'Connect', done: connected.value })
  return s
})
const complete = computed(() => stages.value.filter(s => s.done).length)
const current = computed(() => stages.value.find(s => !s.done)?.id ?? null)

const usable = computed(() => ops.value?.servers ?? [])
const options = (index: number) => usable.value.filter(s => (index > 0 || s.first_hop_ok) && !order.value.slice(0, index).includes(s.name))
const chosen = computed(() => order.value.slice(0, hops.value).map(n => usable.value.find(s => s.name === n)).filter((s): s is RecordedServer => !!s))
const routeReady = computed(() => chosen.value.length === hops.value && !!setup.value?.device_request && !!ops.value?.chain.operator_vault)
const spheres = computed(() => [...new Set(chosen.value.map(s => s.sphere ?? '?'))])
const sameProvider = computed(() => chosen.value.length > 1 && chosen.value[0].provider === chosen.value[chosen.value.length - 1].provider)
const providerName = (key: string) => catalog.providers.find(p => p.key === key)?.service ?? (key === 'own' ? 'Your own server' : key)
const role = (i: number) => i === hops.value - 1 ? (hops.value === 1 ? 'Entry and exit' : 'Exit') : i === 0 ? 'Entry' : 'Middle'

async function refresh() {
  if (!props.fresh) return
  try { setup.value = await controller.setup('join') } catch { setup.value = null }
  if (started.value) void advance()
}

async function loadOperator(next?: Promise<OperatorState>) {
  try {
    ops.value = await (next ?? operator.state())
    if (!order.value.length) {
      const recorded = ops.value.chain.hops.filter(n => ops.value!.servers.some(s => s.name === n))
      order.value = recorded.length ? recorded : ops.value.servers.filter(s => s.first_hop_ok).slice(0, 1).map(s => s.name)
      hops.value = Math.max(1, Math.min(3, order.value.length || 1))
      hours.value = ops.value.profile.hours_per_day
    }
  } catch { error.value = 'Your server records could not be read.' }
}

async function act(title: string, request: ActionRequest): Promise<boolean> {
  busy.value = true
  error.value = ''
  try {
    const plan = await controller.preview(request)
    activity.value = { title, effects: plan.effects, message: 'Waiting for your approval in the system prompt…' }
    let op: Operation = await controller.apply(plan.id)
    while (['running', 'waiting_for_user', 'waiting_for_hardware'].includes(op.state)) {
      activity.value.message = op.message
      await new Promise(r => setTimeout(r, 700))
      op = await controller.operation(op.id)
    }
    if (op.state !== 'complete') { error.value = op.message || `${title} did not finish.`; return false }
    activity.value = null
    return true
  } catch {
    error.value = `${title} was not approved or could not run. You can try again.`
    return false
  } finally {
    busy.value = false
    await refresh()
  }
}

// The steps that need no decision run by themselves, each once per start.
async function advance() {
  if (busy.value || !setup.value || build.value?.running) return
  const id = current.value
  if (!id || attempted.has(id)) return
  if (id === 'key') {
    const udev = keyStep.value?.actions.find(a => a.action === 'repair' && a.repair === 'install_udev_rule')
    if (udev) { attempted.add(id); await act('Give this desktop access to your key', udev) }
  } else if (id === 'software' && missing.value.length) {
    attempted.add(id); await act('Install your key\'s software', { action: 'key_software', mode: 'install' })
  } else if (id === 'device' && step('key')?.state === 'complete') {
    attempted.add(id); await act('Create this device\'s keys', { action: 'request_device' })
  }
}

async function buildRoute() {
  if (!routeReady.value || !setup.value?.device_request) return
  error.value = ''
  signedOut.value = null
  attempted.delete('import')
  try {
    await operator.build(chosen.value.map(s => s.name), hours.value, setup.value.device_request.text)
  } catch { error.value = 'The route could not be started.'; return }
  build.value = { running: true, plan: [], step: -1, note: '', installing: false, failed: false }
  const poll = window.setInterval(async () => {
    let result
    try { result = await operator.buildStatus() } catch { return }
    for (const e of result.events) apply(e)
    if (!result.running) {
      window.clearInterval(poll)
      const last = result.events[result.events.length - 1]
      const finished = last?.event === 'done' && last.bundle_base64 && last.operator_base64
      if (build.value) build.value = { ...build.value, running: false, installing: !!finished, note: '', step: finished ? build.value.plan.length : build.value.step }
      if (finished) {
        const ok = await act(INSTALL, { action: 'import_bundle', bundle_base64: last.bundle_base64!, operator_key_base64: last.operator_base64!, replace: !!props.status?.enrolled })
        if (build.value) build.value = { ...build.value, installing: false, failed: !ok, step: ok ? build.value.plan.length + 1 : build.value.step }
        if (ok) { await loadOperator(); build.value = null }
      } else {
        if (build.value) build.value.failed = true
        if (last?.error === 'signed_out' && last.server) signedOut.value = { server: last.server, profile: last.profile ?? '' }
        error.value = last?.message || last?.error || 'The route could not be built.'
      }
    }
  }, 1000)
}

function apply(e: BuildEvent) {
  if (!build.value || e.event !== 'progress') return
  if (e.plan) build.value.plan = e.plan
  if (typeof e.step === 'number') { build.value.step = e.step; build.value.note = e.state === 'wait' ? (e.note ?? '') : '' }
}

async function signIn() {
  if (!signedOut.value) return
  signingIn.value = true
  try {
    const r = await operator.signin(signedOut.value.server)
    if (!r.ready) { error.value = `AWS sign-in did not finish: ${r.why}`; return }
    signedOut.value = null; error.value = ''; build.value = null
    await buildRoute()
  } catch { error.value = 'The AWS sign-in could not be started.' }
  finally { signingIn.value = false }
}

async function connect() { await act('Connect', { action: 'connect', scope: scope.value }) }

async function importFiles() {
  if (!bundle.value || !operatorKey.value) return
  const b64 = async (f: File) => { let raw = ''; for (const x of new Uint8Array(await f.arrayBuffer())) raw += String.fromCharCode(x); return btoa(raw) }
  await act('Install the signed route on this device', { action: 'import_bundle', bundle_base64: await b64(bundle.value), operator_key_base64: await b64(operatorKey.value), replace: !!props.status?.enrolled })
}
function pick(event: Event, kind: 'bundle' | 'operator') {
  const file = (event.target as HTMLInputElement).files?.[0] ?? null
  if (kind === 'bundle') bundle.value = file; else operatorKey.value = file
}
const saved = ref('')
async function saveRequest() {
  if (!setup.value?.device_request) return
  try { saved.value = (await operator.export(setup.value.device_request.text)).path }
  catch { error.value = 'The request could not be saved.' }
}

function start() { started.value = true; open.value = true; attempted.clear(); void refresh() }
watch(() => props.fresh, f => { if (f) void refresh() })
onMounted(() => { void refresh(); void loadOperator(); timer = window.setInterval(refresh, 2000) })
onUnmounted(() => window.clearInterval(timer))
</script>

<template>
  <section class="setup" aria-labelledby="setup-title">
    <div v-if="!started && !connected" class="intro">
      <h2 id="setup-title">Set up your private network</h2>
      <p>Setup checks your security key, installs what it needs, makes this device's keys and builds your route on your own servers. Your system asks for your password, PIN and a touch on the key when it needs them.</p>
      <button class="btn wide" :disabled="!fresh" @click="start">Start setup</button>
    </div>

    <div v-else class="card">
      <button class="head" :aria-expanded="open" @click="open = !open">
        <span class="title"><span class="mark" aria-hidden="true">☰</span>Setup</span>
        <span class="count">{{ complete }} of {{ stages.length }} complete <span class="chev" :class="{ up: open }" aria-hidden="true">⌄</span></span>
      </button>
      <ol v-show="open" class="stages">
        <li v-for="s in stages" :key="s.id" :class="{ done: s.done, current: current === s.id }">
          <span class="tick" :class="{ spin: !s.done && current === s.id && working, ring: !s.done && current === s.id && !working }" aria-hidden="true">{{ s.done ? '✓' : '' }}</span>
          <div class="body">
            <span class="name">{{ s.title }}<template v-if="s.id === 'providers' && ops"> · {{ ops.profile.name }}</template></span>
            <span v-if="s.id === 'key' && deviceLine" class="sub">{{ deviceLine }}</span>
            <span v-if="s.id === 'software' && software.length" class="sub">{{ software.map(r => `${r.package} ${r.installed ?? (r.state === 'unavailable' ? 'not offered' : 'not installed')}`).join(' · ') }}</span>

            <!-- Security key -->
            <div v-if="s.id === 'key' && current === 'key'" class="detail">
              <p>{{ keyStep?.say || 'Checking for a security key…' }}</p>
              <template v-for="a in keyStep?.actions ?? []" :key="JSON.stringify(a)">
                <button v-if="a.action === 'repair'" class="btn secondary small" :disabled="busy" @click="act('Repair the key', a)">{{ a.repair === 'install_udev_rule' ? 'Give this desktop access' : 'Switch on FIDO2' }}</button>
              </template>
              <p class="usable">Keys that work: {{ USABLE_KEYS.join(', ') }}. Open-firmware keys come first.</p>
            </div>

            <!-- Key software -->
            <div v-if="s.id === 'software' && (current === 'software' || upgrades.length)" class="detail">
              <p v-if="missing.length">Needed: {{ missing.map(r => r.package).join(', ') }}.</p>
              <p v-for="r in software.filter(r => r.state === 'unavailable')" :key="r.package">{{ r.package }} is not offered by this system's package sources.</p>
              <div v-if="upgrades.length" class="upgrade">
                <p>Newer versions: {{ upgrades.map(r => `${r.package} ${r.installed} → ${r.candidate}`).join(', ') }}. Keep yours if you use an older or custom version on purpose.</p>
                <button class="btn quiet small" :disabled="busy" @click="act('Upgrade your key\'s software', { action: 'key_software', mode: 'upgrade' })">Upgrade</button>
              </div>
              <button v-if="missing.length && current === 'software'" class="btn secondary small" :disabled="busy" @click="attempted.delete('software'); act('Install your key\'s software', { action: 'key_software', mode: 'install' })">Install</button>
            </div>

            <!-- Device keys -->
            <div v-if="s.id === 'device' && current === 'device'" class="detail">
              <p>Creates this device's VPN keys, sealed to your security key. Enter the PIN when asked, then touch the key.</p>
              <button class="btn secondary small" :disabled="busy" @click="act('Create this device\'s keys', { action: 'request_device' })">Create device keys</button>
              <button class="link" @click="mode = mode === 'own' ? 'join' : 'own'">{{ mode === 'own' ? 'Joining someone else\'s network?' : 'Use my own servers instead' }}</button>
            </div>

            <!-- Cloud providers -->
            <div v-if="s.id === 'providers' && ops && (current === 'providers' || current === 'route')" class="detail">
              <p>Profile <strong>{{ ops.profile.name }}</strong> · {{ ops.profile.active_providers }} active provider{{ ops.profile.active_providers === 1 ? '' : 's' }}</p>
              <div class="chips">
                <span v-for="k in ops.profile.providers" :key="k" class="chip"><ProviderLogo :provider="k" :name="providerName(k)" :size="18" />{{ providerName(k) }}<small>{{ ops.servers.filter(x => x.provider === k).length }}</small></span>
              </div>
              <button class="btn secondary small" @click="sheet = true">Add providers</button>
              <p v-if="ops.profile.providers.length && !ops.profile.active_providers" class="note">A provider becomes active when it has a server. Creating servers from the app comes in the next version; servers you already run are listed here.</p>
            </div>

            <!-- Route -->
            <div v-if="s.id === 'route' && current === 'route' && ops" class="detail">
              <label class="row">Hops
                <span class="seg"><button v-for="n in [1, 2, 3]" :key="n" :class="{ on: hops === n }" :disabled="n > usable.length || !!build?.running" @click="hops = n">{{ n }}</button></span>
              </label>
              <label v-for="i in hops" :key="i" class="row">{{ role(i - 1) }}
                <select v-model="order[i - 1]" :disabled="!!build?.running">
                  <option v-for="srv in options(i - 1)" :key="srv.name" :value="srv.name">{{ providerName(srv.provider) }} · {{ srv.region || srv.name }} · {{ SPHERES[srv.sphere ?? ''] ?? srv.sphere }} law</option>
                </select>
              </label>
              <label class="row">Daily use
                <select v-model.number="hours" :disabled="!!build?.running"><option v-for="h in [2, 4, 6, 8, 12, 16, 24]" :key="h" :value="h">{{ h }} hours</option></select>
              </label>
              <p class="note" v-if="chosen.length">Jurisdictions: {{ chosen.map(x => SPHERES[x.sphere ?? ''] ?? x.sphere).join(' → ') }}.
                <template v-if="spheres.length === 1 && chosen.length > 1">Every hop is under one legal system, so one court can reach both ends.</template>
                <template v-if="sameProvider">The entry and exit share a provider, which then sees both your address and your destinations.</template>
              </p>
              <p v-if="!ops.chain.operator_vault" class="warn">No operator key vault is recorded on this computer yet.</p>
              <template v-if="build">
                <ol class="progress">
                  <li v-for="(r, i) in buildRows" :key="i" :class="{ done: r.done, now: r.working, failed: r.failed }">
                    <span class="tick" :class="{ spin: r.working }" aria-hidden="true">{{ r.done ? '✓' : r.failed ? '✕' : '' }}</span><span>{{ r.title }}</span>
                  </li>
                </ol>
                <div v-if="signedOut" class="signin">
                  <p class="note">{{ signingIn ? 'Finish signing in to AWS in the browser window that opened. The route builds by itself afterwards.' : `Your AWS sign-in for ${signedOut.server} (profile ${signedOut.profile}) has run out.` }}</p>
                  <button class="btn small" :disabled="signingIn" @click="signIn">{{ signingIn ? 'Waiting for the browser…' : 'Sign in to AWS' }}</button>
                </div>
                <p v-if="build.note" class="hint">{{ build.note }}</p>
              </template>
              <button v-if="!build?.running" class="btn secondary small" :disabled="!routeReady || busy" @click="buildRoute">Build my route</button>
              <p class="warn">Building reinstalls these servers with fresh keys and signs the route for this device only.<template v-if="ops.chain.hops.length"> Any other device using your current route ({{ ops.chain.hops.join(' → ') }}) stops connecting until it is set up again.</template></p>
              <p class="note">It takes a few minutes. Your security key asks for its PIN and a touch once.</p>
            </div>

            <!-- Join with an operator's file -->
            <div v-if="s.id === 'join' && current === 'join'" class="detail">
              <p>Send your operator this device's public request, then open the signed file they send back.</p>
              <button class="btn quiet small" :disabled="!setup?.device_request" @click="saveRequest">Save my device request</button>
              <p v-if="saved" class="note">Saved to {{ saved }}. It holds public keys only.</p>
              <label class="file">Signed device file<input type="file" accept=".cpvpn" @change="pick($event, 'bundle')"></label>
              <label class="file">Operator public key<input type="file" @change="pick($event, 'operator')"></label>
              <button class="btn secondary small" :disabled="!bundle || !operatorKey || busy" @click="importFiles">Install route</button>
              <button class="link" @click="mode = 'own'">Use my own servers instead</button>
            </div>

            <!-- Connect -->
            <div v-if="s.id === 'connect' && current === 'connect'" class="detail">
              <label class="row">Protect
                <select v-model="scope"><option value="applications">VPN applications only</option><option value="whole-device">Whole device</option></select>
              </label>
              <button class="btn small" :disabled="busy" @click="connect">Connect</button>
            </div>
          </div>
        </li>
      </ol>
      <div v-if="activity" class="activity" role="status"><strong>{{ activity.title }}</strong><p>{{ activity.message }}</p><ul><li v-for="e in activity.effects" :key="e">{{ e }}</li></ul></div>
      <p v-if="error" class="error" role="alert">{{ error }}</p>
    </div>
    <ProviderSheet v-if="sheet && ops" :state="ops" :busy="busy" @close="sheet = false" @add="k => loadOperator(operator.add(k))" @remove="k => loadOperator(operator.remove(k))" @check="k => operator.check(k).then(() => loadOperator())" />
  </section>
</template>

<style scoped>
.setup { padding: 20px 20px 4px; }
.intro h2 { font-size: 19px; margin: 0 0 10px; }
.intro p, .detail p { font-size: 12px; color: var(--muted); line-height: 1.6; margin: 6px 0; }
.wide { display: block; width: 100%; margin-top: 14px; }
.card { border: 1px solid var(--line); border-radius: 16px; background: var(--panel); }
.head { width: 100%; display: flex; align-items: center; justify-content: space-between; padding: 13px 15px; border: 0; background: none; color: var(--text); }
.title { display: flex; align-items: center; gap: 9px; font-size: 14px; font-weight: 600; }
.mark { color: var(--muted); font-size: 13px; }
.count { font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 8px; }
.chev { display: inline-block; transition: transform .15s; }
.chev.up { transform: rotate(180deg); }
.stages { list-style: none; margin: 0; padding: 0 15px 10px; }
.stages > li { display: flex; gap: 11px; padding: 7px 0; }
.tick { flex: none; width: 17px; height: 17px; margin-top: 1px; border-radius: 50%; border: 1.5px solid var(--faint); display: grid; place-items: center; font-size: 10px; font-weight: 700; color: var(--ok-text); }
.done .tick { border-color: var(--ok); }
.body { min-width: 0; flex: 1; }
.name { font-size: 13px; }
.done > .body > .name { color: var(--muted); }
.current > .body > .name { font-weight: 600; }
.detail { margin: 8px 0 4px; display: grid; gap: 8px; justify-items: start; }
.usable, .note { font-size: 11px !important; }
.warn { color: var(--warn) !important; }
.upgrade { display: grid; gap: 6px; justify-items: start; }
.small { padding: 6px 13px; font-size: 12px; }
.link { border: 0; background: none; padding: 0; color: var(--primary-text); font-size: 11px; text-decoration: underline; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 8px 4px 4px; border: 1px solid var(--line); border-radius: 999px; font-size: 11px; }
.chip small { color: var(--muted); }
.row { width: 100%; display: grid; gap: 5px; font-size: 11px; color: var(--muted); }
.row select { width: 100%; min-width: 0; font-size: 12px; color: var(--text); background: var(--panel); border: 1px solid var(--line); border-radius: 7px; padding: 7px 8px; }
.sub { display: block; margin-top: 3px; font-size: 11px; color: var(--muted); line-height: 1.5; }
.tick.ring { border: 2px solid var(--text); }
.tick.spin { border: 2px solid var(--line); border-top-color: var(--muted); animation: spin .9s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .tick.spin { animation-duration: 2.5s; } }
.seg { justify-self: start; display: inline-flex; border: 1px solid var(--line); border-radius: 7px; overflow: hidden; }
.seg button { border: 0; padding: 5px 12px; background: var(--panel); color: var(--text); }
.seg button.on { background: var(--primary); color: var(--on-primary); }
.seg button:disabled { color: var(--faint); }
.progress { margin: 0; padding: 0; list-style: none; display: grid; gap: 7px; font-size: 12px; color: var(--muted); }
.progress li { display: flex; align-items: center; gap: 9px; }
.progress .tick { width: 15px; height: 15px; margin-top: 0; font-size: 9px; }
.progress .now { color: var(--text); font-weight: 600; }
.progress .failed { color: var(--bad); }
.progress .failed .tick { border-color: var(--bad); color: var(--bad); }
.signin { display: grid; gap: 6px; justify-items: start; }
.hint { color: var(--primary-text) !important; }
.file { display: grid; gap: 4px; font-size: 11px; width: 100%; }
.activity { margin: 0 15px 12px; padding: 10px 12px; border-radius: 9px; background: var(--primary-soft); font-size: 12px; }
.activity p { margin: 4px 0; color: var(--text); }
.activity ul { margin: 4px 0 0; padding-left: 16px; color: var(--muted); font-size: 11px; line-height: 1.6; }
.error { margin: 0 15px 12px; color: var(--bad); font-size: 12px; }
</style>
