<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import BrandMark from './components/BrandMark.vue'
import MapPane from './components/MapPane.vue'
import ProviderSearch from './components/ProviderSearch.vue'
import { controller } from './controller/real'
import type { ActionPlan, ActionRequest, Operation, SetupBranch, SetupSnapshot, Status } from './controller/types'

const status = ref<Status | null>(null)
const setup = ref<SetupSnapshot | null>(null)
const branch = ref<SetupBranch | null>(null)
const plan = ref<ActionPlan | null>(null)
const operation = ref<Operation | null>(null)
const error = ref('')
const available = ref(false)
const now = ref(Date.now() / 1000)
const working = ref(false)
const dialog = ref<HTMLElement | null>(null)
const bundle = ref<File | null>(null)
const operatorKey = ref<File | null>(null)
const scope = ref<'applications' | 'whole-device'>('applications')
let polling = false
let timer = 0
let opener: HTMLElement | null = null
const fresh = computed(() => available.value && !!status.value && now.value - status.value.observed_at >= -1 && now.value - status.value.observed_at <= 3)
const protectedNow = computed(() => fresh.value && status.value?.state === 'connected' && status.value.protection === 'protected' && status.value.kill_switch === 'active')
const verdict = computed(() => protectedNow.value ? 'Connected' : !fresh.value || status.value?.protection === 'unknown' ? 'Status unknown' : status.value?.protection === 'blocked' ? 'Traffic blocked' : 'Unprotected')
const scopeLabel = computed(() => status.value?.scope === 'whole-device' ? 'Whole device' : status.value?.scope === 'applications' ? 'VPN applications only' : 'Scope unverified')
const activeOperation = computed(() => !!operation.value && ['running', 'waiting_for_user', 'waiting_for_hardware'].includes(operation.value.state))

async function poll() {
  now.value = Date.now() / 1000
  if (polling) return
  polling = true
  try {
    status.value = await controller.snapshot()
    available.value = true
    if (branch.value) {
      try { setup.value = await controller.setup(branch.value) }
      catch { setup.value = null }
    }
    if (activeOperation.value && operation.value) operation.value = await controller.operation(operation.value.id)
  } catch {
    available.value = false
  } finally { polling = false }
}

async function preview(request: ActionRequest) {
  working.value = true
  error.value = ''
  try {
    plan.value = await controller.preview(request)
    opener = document.activeElement as HTMLElement
    await nextTick()
    dialog.value?.focus()
  } catch { error.value = 'The controller could not prepare this action. Refresh the checks and try again.' }
  finally { working.value = false }
}

function closePlan() { plan.value = null; opener?.focus() }

async function apply() {
  if (!plan.value || plan.value.expires_at <= now.value) return
  working.value = true
  try {
    operation.value = await controller.apply(plan.value.id)
    closePlan()
    await poll()
  } catch {
    closePlan()
    error.value = 'The action was refused or could not finish. Refresh the checks before preparing another plan.'
  } finally { working.value = false }
}

async function cancel() {
  if (!operation.value) return
  try { operation.value = await controller.cancel(operation.value.id) }
  catch { error.value = 'Cancellation could not be confirmed. Check the operation status before retrying.' }
}

function selectFile(event: Event, kind: 'bundle' | 'operator') {
  const file = (event.target as HTMLInputElement).files?.[0] ?? null
  if (file && file.size > (kind === 'bundle' ? 1024 * 1024 : 8192)) { error.value = 'This file exceeds the supported size.'; return }
  if (kind === 'bundle') bundle.value = file
  else operatorKey.value = file
}

async function bytes(file: File): Promise<string> {
  const value = new Uint8Array(await file.arrayBuffer())
  let raw = ''
  for (const byte of value) raw += String.fromCharCode(byte)
  return btoa(raw)
}

async function importBundle() {
  if (!bundle.value || !operatorKey.value) return
  await preview({ action: 'import_bundle', bundle_base64: await bytes(bundle.value), operator_key_base64: await bytes(operatorKey.value), replace: status.value?.enrolled ?? false })
}

function trap(event: KeyboardEvent) {
  if (event.key === 'Escape' && !working.value) { closePlan(); return }
  if (event.key !== 'Tab') return
  const controls = dialog.value?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')
  if (!controls?.length) return
  const first = controls[0], last = controls[controls.length - 1]
  if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog.value)) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
}

async function copyRequest() {
  if (!setup.value?.device_request) return
  try { await navigator.clipboard.writeText(setup.value.device_request.text) }
  catch { error.value = 'Select and copy the public request below, then send it to your operator.' }
}

onMounted(() => { void poll(); timer = window.setInterval(poll, 1000) })
onUnmounted(() => window.clearInterval(timer))
</script>

<template>
  <div class="application">
    <header class="header"><BrandMark /><span class="caption">Private by design.</span></header>
    <main class="workspace">
      <section class="controls" aria-label="Connection and setup">
        <div class="connection" aria-live="polite">
          <span class="eyebrow">Your connection</span>
          <h1 :class="{ protected: protectedNow }">{{ verdict }}</h1>
          <p v-if="!fresh">The controller's current protection state could not be verified.</p>
          <p v-else-if="protectedNow">{{ scopeLabel }} · verified by the controller.</p>
          <p v-else-if="status?.protection === 'blocked'">The controller reports that traffic in this scope is blocked.</p>
          <p v-else>Protection has not been established for this scope.</p>
          <p class="scope">{{ fresh ? scopeLabel : 'Scope unverified' }}</p>
          <div class="buttons" v-if="fresh && status?.enrolled">
            <button class="btn" :disabled="working || activeOperation" @click="preview(protectedNow ? { action: 'disconnect' } : { action: 'connect', scope })">{{ protectedNow ? 'Disconnect' : 'Connect' }}</button>
            <button v-if="status.state === 'locked'" class="btn secondary" :disabled="working || activeOperation" @click="preview({ action: 'unlock' })">Open trusted unlock prompt</button>
          </div>
          <label v-if="fresh && status?.enrolled && !protectedNow" class="mode">Connect scope<select v-model="scope"><option value="applications">VPN applications only</option><option value="whole-device">Whole device</option></select></label>
          <p class="hint">Unlocking uses your device or a trusted system dialog.</p>
        </div>

        <div v-if="fresh && !branch" class="onboarding">
          <h2>Set up your private network</h2>
          <p>Choose whether you manage the servers or received a signed device file from an operator.</p>
          <button class="btn wide" @click="branch = 'create'; poll()">Create my network</button>
          <button class="btn secondary wide" @click="branch = 'join'; poll()">Join an existing network</button>
        </div>

        <div v-if="branch" class="onboarding">
          <details open>
            <summary><strong>Setup</strong><span>{{ fresh && setup ? `${setup.complete} of ${setup.total} checked` : 'Checks unavailable' }}</span></summary>
            <ol v-if="setup && fresh" class="steps">
              <li v-for="step in setup.steps" :key="step.id" :class="step.state" :aria-current="setup.current === step.id ? 'step' : undefined">
                <span class="step-mark" aria-hidden="true">{{ step.state === 'complete' ? '✓' : step.state === 'running' ? '◌' : '○' }}</span>
                <div><strong>{{ step.title }}</strong><span class="step-state">{{ step.state.replace(/_/g, ' ') }}</span><p v-if="setup.current === step.id">{{ step.say }}</p>
                  <button v-for="action in step.actions" :key="JSON.stringify(action)" class="btn secondary" :disabled="working || activeOperation" @click="preview(action)">Review action</button>
                </div>
              </li>
            </ol>
          </details>
          <ProviderSearch v-if="branch === 'create' && fresh" />
          <div v-if="branch === 'join'" class="import">
            <div v-if="fresh && setup?.device_request">
              <h3>Your public device request</h3>
              <p>Send this request to your operator. It contains public keys for this device.</p>
              <button class="btn secondary" @click="copyRequest">Copy public request</button>
              <details><summary>View public request</summary><textarea readonly aria-label="Public device request" :value="setup.device_request.text" /></details>
            </div>
            <h3>Signed device file</h3>
            <p>Verify the operator key fingerprint through a trusted channel before approving import.</p>
            <label>Device file<input type="file" @change="selectFile($event, 'bundle')"></label>
            <label>Trusted operator public key<input type="file" @change="selectFile($event, 'operator')"></label>
            <button class="btn secondary" :disabled="!bundle || !operatorKey || working || activeOperation || !fresh" @click="importBundle">Review import</button>
          </div>
          <button class="btn quiet" :disabled="activeOperation" @click="branch = null; setup = null">Change setup path</button>
        </div>

        <div v-if="operation" class="operation" role="status"><strong>{{ operation.state.replace(/_/g, ' ') }}</strong><p>{{ operation.message }}</p><button v-if="activeOperation" class="btn secondary" @click="cancel">Cancel safely</button></div>
        <p v-if="error" class="error" role="alert">{{ error }}</p>
        <button class="btn quiet refresh" :disabled="polling" @click="poll">Refresh checks</button>
      </section>
      <MapPane :status="status" :unavailable="!fresh" />
    </main>
    <footer class="footer">cypherpunk_vpn <span>Protection state comes from the controller</span></footer>
    <div v-if="plan" class="backdrop">
      <section ref="dialog" class="review" role="dialog" aria-modal="true" aria-labelledby="plan-title" tabindex="-1" @keydown="trap">
        <h2 id="plan-title">{{ plan.summary }}</h2>
        <ul><li v-for="effect in plan.effects" :key="effect">{{ effect }}</li></ul>
        <p v-if="plan.expires_at <= now" role="alert">This plan has expired. Refresh the checks and review a new plan.</p>
        <div class="buttons"><button class="btn secondary" :disabled="working" @click="closePlan">Cancel</button><button class="btn" :disabled="working || plan.expires_at <= now" @click="apply">Approve these changes</button></div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.application { display: grid; grid-template-rows: 54px minmax(0,1fr) 30px; height: 100%; }
.header { display: flex; align-items: center; gap: 18px; padding: 0 22px; background: var(--panel); border-bottom: 1px solid var(--line); }
.caption, .footer, .hint, .step-state { color: var(--muted); font-size: 11px; }
.workspace { display: flex; min-height: 0; overflow: hidden; }
.controls { width: 360px; flex: none; overflow-y: auto; border-right: 1px solid var(--line); background: var(--panel); }
.connection, .onboarding, .operation { padding: 24px; border-bottom: 1px solid var(--line); }
h1 { font-size: 29px; letter-spacing: -.8px; margin: 13px 0 8px; }
h1.protected { color: var(--ok-text); }
h2 { font-size: 19px; line-height: 1.4; margin: 0 0 12px; }
h3 { font-size: 14px; }
p { font-size: 12px; color: var(--muted); line-height: 1.7; }
.scope { color: var(--primary-text); font-weight: 600; }
.buttons { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 18px; }
.wide { display: block; width: 100%; margin-top: 12px; }
.mode, .import label { display: grid; gap: 8px; margin: 15px 0; font-size: 12px; }
select, input, textarea { max-width: 100%; font: inherit; color: var(--text); background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 9px; }
textarea { width: 100%; min-height: 100px; font-family: monospace; font-size: 10px; }
summary { display: flex; align-items: center; justify-content: space-between; gap: 12px; cursor: pointer; font-size: 14px; }
summary span { font-size: 11px; color: var(--muted); }
.steps { list-style: none; padding: 12px 0 0; margin: 0; }
.steps li { display: flex; gap: 12px; padding: 11px 0; }
.steps strong { font-size: 12px; }
.step-state { display: block; margin-top: 4px; }
.step-mark { flex: none; color: var(--muted); width: 18px; }
.complete .step-mark { color: var(--ok-text); }
.blocked .step-mark, .failed .step-mark, .error { color: var(--bad); }
.steps p { margin: 6px 0 10px; }
.steps .pending { opacity: .65; }
.import { border-top: 1px solid var(--line); padding-top: 10px; margin-top: 18px; }
.footer { display: flex; align-items: center; justify-content: space-between; padding: 0 20px; border-top: 1px solid var(--line); background: var(--panel); }
.refresh, .error { margin: 16px 24px; }
.backdrop { position: fixed; inset: 0; display: grid; place-items: center; padding: 20px; background: #17102655; z-index: 20; }
.review { width: min(460px, 100%); max-height: 90vh; overflow: auto; padding: 28px; border-radius: 14px; border: 1px solid var(--line); background: var(--panel); box-shadow: 0 24px 90px #20133230; }
.review li { margin: 10px 0; font-size: 13px; line-height: 1.6; }
@media (max-width: 680px) { .workspace :deep(.map) { display: none; } .controls { width: 100%; } .caption, .footer span { display: none; } }
</style>
