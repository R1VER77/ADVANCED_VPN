<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, shallowRef, watch } from 'vue'
import AppIcon from './components/AppIcon.vue'
import BrandMark from './components/BrandMark.vue'
import { MockController, type Fault, type MockOptions } from './controller/mock'
import type { Rate, Status } from './controller/types'
import DemoPanel from './components/DemoPanel.vue'
import EnrollFlow from './components/EnrollFlow.vue'
import MapPane from './components/MapPane.vue'
import PinDialog from './components/PinDialog.vue'
import StatusPanel from './components/StatusPanel.vue'

// The prototype runs on the simulated controller; the real adapter replaces this line.
const start = (new URLSearchParams(location.search).get('start') ?? 'fresh') as 'fresh' | 'disconnected' | 'connected'
const ctl = shallowRef(new MockController(start))

const status = ref<Status | null>(null)
const unavailable = ref(false)
const nowSec = ref(Math.floor(Date.now() / 1000))
const pinAnswer = ref<((ok: boolean) => void) | null>(null)
const sheet = ref<'' | 'fix' | 'settings'>('')
// The enrolment flow stays up until the user leaves it (its success step comes after
// the controller already reports enrolled).
const enrolling = ref(false)
const session = ref(0) // a new controller starts a new enrolment flow
const demo = reactive({ networkUp: true, unavailable: false, pinOutcome: 'ok' as MockOptions['pinOutcome'] })
const route = ref<string[]>(['sto', 'fra'])
const routeNames = computed(() => status.value?.chain.map((hop) => hop.city).join(' → ') || 'Your signed route')
const theme = ref<'light' | 'dark'>('light')
const dialog = ref<HTMLElement | null>(null)
try {
  theme.value = localStorage.getItem('avpn-prototype-theme') === 'dark' || (!localStorage.getItem('avpn-prototype-theme') && matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light'
} catch { /* Private browsing can disable storage; the local default remains usable. */ }
watch(theme, (value) => {
  document.documentElement.dataset.theme = value
  try { localStorage.setItem('avpn-prototype-theme', value) } catch { /* Optional preference. */ }
}, { immediate: true })
let sheetOpener: HTMLElement | null = null
watch(sheet, async (value) => {
  if (value) { sheetOpener = document.activeElement as HTMLElement; await nextTick(); dialog.value?.focus() }
  else if (sheetOpener?.isConnected) sheetOpener.focus()
})
function trapDialog(event: KeyboardEvent) {
  if (event.key === 'Escape') { sheet.value = ''; return }
  if (event.key !== 'Tab') return
  const items = dialog.value?.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input, select, [tabindex="0"]')
  if (!items?.length) return
  const first = items[0], last = items[items.length - 1]
  if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog.value)) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
}


function wire() {
  ctl.value.onPinRequest = (answer) => {
    pinAnswer.value = (ok: boolean) => {
      pinAnswer.value = null
      answer(ok)
    }
  }
}
wire()

async function poll() {
  nowSec.value = Math.floor(Date.now() / 1000)
  try {
    status.value = await ctl.value.status()
    unavailable.value = false
  } catch {
    unavailable.value = true // never guess: the GUI shows "Status unknown"
  }
  Object.assign(demo, ctl.value.demo)
}

let timer = 0
onMounted(() => {
  poll()
  timer = window.setInterval(poll, 500)
})
onUnmounted(() => clearInterval(timer))

async function run(f: () => Promise<unknown>) {
  await f()
  await poll()
}

const connect = () => run(() => ctl.value.connect())
const disconnect = () => run(() => ctl.value.disconnect())
const retry = () => run(() => ctl.value.retry())
const startService = () => run(() => ctl.value.startService())
const setRate = (r: Rate) => run(() => ctl.value.setRate(r))
const enroll = (file: string) => ctl.value.enroll(file)

function enrolled(connectNow: boolean) {
  enrolling.value = false
  poll().then(() => {
    if (connectNow) connect()
  })
}

function fault(f: Fault) {
  ctl.value.inject(f)
  poll()
}
function restore() {
  ctl.value.restoreNetwork()
  poll()
}
function setRoute(ids: string[]) {
  route.value = ids
  ctl.value.setRoute(ids)
  poll()
}
function setPin(p: MockOptions['pinOutcome']) {
  ctl.value.options.pinOutcome = p
  demo.pinOutcome = p
}
function reset(to: 'fresh' | 'disconnected' | 'connected') {
  ctl.value = new MockController(to)
  ctl.value.options.pinOutcome = demo.pinOutcome
  ctl.value.setRoute(route.value)
  wire()
  sheet.value = ''
  enrolling.value = false
  session.value += 1
  poll()
}
</script>

<template>
  <div class="app">
    <header class="app-header">
      <div class="brand"><BrandMark /><span class="brand-divider" /><span class="brand-caption">Private by design.</span></div>
      <div class="header-actions"><span class="preview-badge">Interactive preview</span><span class="header-divider" /><button class="icon-button" :aria-label="theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme'" :title="theme === 'light' ? 'Dark theme' : 'Light theme'" @click="theme = theme === 'light' ? 'dark' : 'light'"><AppIcon :name="theme === 'light' ? 'moon' : 'sun'" :size="16" /></button><button class="icon-button" aria-label="Settings" title="Settings" @click="sheet = 'settings'"><AppIcon name="settings" :size="16" /></button></div>
    </header>
    <main class="workspace">
    <template v-if="status && (enrolling || !status.enrolled) && !unavailable">
      <EnrollFlow :key="session" :route="status.chain" :enroll="enroll" :demo="ctl.kind === 'mock'" @hold="enrolling = true" @done="enrolled" />
    </template>
    <StatusPanel
      v-else
      :status="status"
      :unavailable="unavailable"
      :now-sec="nowSec"
      @connect="connect"
      @disconnect="disconnect"
      @retry="retry"
      @start-service="startService"
      @rate="setRate"
      @resign="sheet = 'fix'"
      @settings="sheet = 'settings'"
    />
    <MapPane :status="status" :unavailable="unavailable" />

    </main>
    <footer class="app-footer"><span class="preview-caption"><span class="preview-dot" /> Simulated connection <span class="footer-separator">·</span><span class="prototype-scope">No live traffic is routed</span></span>
    <DemoPanel
      v-if="ctl.kind === 'mock'"
      :network-up="demo.networkUp"
      :unavailable="demo.unavailable"
      :pin-outcome="demo.pinOutcome"
      :route="route"
      @route="setRoute"
      @fault="fault"
      @restore="restore"
      @pin="setPin"
      @reset="reset"
    />

    </footer>

    <PinDialog v-if="pinAnswer" @answer="pinAnswer" />

    <transition name="fade">
      <div v-if="sheet" class="sheet-backdrop" @click.self="sheet = ''">
        <div ref="dialog" class="sheet" role="dialog" aria-modal="true" :aria-label="sheet === 'fix' ? 'Connection recovery' : 'Settings'" tabindex="-1" @keydown="trapDialog">
          <button class="icon-button sheet-close" aria-label="Close dialog" @click="sheet = ''"><AppIcon name="close" :size="18" /></button>
          <span class="sheet-icon"><AppIcon :name="sheet === 'fix' ? 'shield' : 'settings'" :size="24" /></span>
          <template v-if="sheet === 'fix'">
            <h2>Why AVPN stopped</h2>
            <p>
              Before sending anything, the first server must prove it holds your device's key. It didn't.
              Either someone is pretending to be your server, or your device file was made for an older
              version of AVPN.
            </p>
            <p><strong>Your traffic stayed blocked. Nothing was sent.</strong></p>
            <h3>What to do</h3>
            <ol>
              <li>If you recently updated AVPN, ask your operator for a new device file and add it in Settings.</li>
              <li>If you didn't, tell your operator: this can mean an attack on your connection.</li>
            </ol>

          </template>
          <template v-else>
            <h2>Settings</h2>
            <div class="setting">
              <div><strong>Kill switch</strong><p class="muted">Always on. The controller keeps the traffic guard in place when the VPN disconnects or cannot be verified.</p></div>
            </div>
            <div class="setting">
              <div><strong>Device file</strong><p class="muted">{{ routeNames }}. Signed by your operator; replace your device file to change it.</p></div>
              <button class="btn secondary" @click="reset('fresh')">Replace…</button>
            </div>
            <div class="setting">
              <div><strong>Nitrokey</strong><p class="muted">Asked for on every connect: PIN, then a touch.</p></div>
            </div>
            <div class="setting">
              <div><strong>About</strong><p class="muted">Interactive prototype. Connection states, addresses and checks are simulated. No live VPN is controlled.</p></div>
            </div>
          </template>
          <div class="sheet-buttons"><button class="btn" @click="sheet = ''">Close</button></div>
        </div>
      </div>
    </transition>
  </div>
</template>

<style scoped>
.app { display: grid; grid-template-rows: 51px minmax(0, 1fr) 31px; height: 100%; min-width: 320px; overflow: hidden; }
.app-header { display: flex; align-items: center; justify-content: space-between; padding: 0 19px; background: var(--panel); border-bottom: 1px solid var(--line); z-index: 4; gap: 10px; }
.brand { display: flex; align-items: center; gap: 8px; }


.brand-caption { font-size: 11px; color: var(--muted); }
.brand-divider, .header-divider { width: 1px; height: 15px; background: var(--line); margin: 0 3px; }
.header-actions { display: flex; align-items: center; gap: 6px; }
.preview-badge { color: var(--muted); font-size: 10px; }
.workspace { display: flex; min-height: 0; overflow: hidden; }
.app-footer { position: relative; display: flex; align-items: center; justify-content: space-between; background: var(--panel); border-top: 1px solid var(--line); padding: 0 14px 0 20px; z-index: 7; }
.preview-caption { display: flex; align-items: center; gap: 6px; font-size: 10px; color: var(--muted); }
.preview-dot { width: 5px; height: 5px; border-radius: 50%; background: var(--warn); }
.footer-separator { color: var(--faint); }
.sheet-backdrop { position: fixed; inset: 0; background: #17102635; backdrop-filter: blur(3px); display: grid; place-items: center; z-index: 10; padding: 16px; }
.sheet { position: relative; width: min(440px, 100%); max-height: calc(100% - 30px); overflow-y: auto; background: var(--panel); border: 1px solid var(--line); border-radius: 14px; box-shadow: 0 24px 90px #20133230; padding: 28px; }
.sheet-close { position: absolute; top: 13px; right: 13px; }
.sheet-icon { display: grid; place-items: center; width: 43px; height: 43px; border-radius: 12px; color: var(--primary); background: var(--primary-soft); margin-bottom: 19px; }
.sheet h2 { margin: 0 0 12px; font-weight: 600; font-size: 22px; letter-spacing: -.6px; }
.sheet h3 { margin: 20px 0 5px; font-size: 13px; font-weight: 600; }
.sheet p, .sheet li { font-size: 13px; line-height: 1.8; color: var(--muted); }
.sheet ol { padding-left: 18px; }
.sheet p strong { color: var(--text); font-weight: 550; }
.muted { color: var(--muted); font-size: 12px; margin: 5px 0; }
.setting { display: flex; gap: 14px; align-items: center; justify-content: space-between; padding: 16px 0; border-bottom: 1px solid var(--line); }
.setting strong { font-size: 13px; font-weight: 600; }
.sheet-buttons { display: flex; justify-content: flex-end; margin-top: 24px; }
@media (max-width: 620px) { .workspace :deep(.map) { display: none; } .brand-caption, .brand-divider, .preview-badge { display: none; } .preview-caption { font-size: 9px; gap: 4px; } .app-header { padding: 0 17px; } }
@media (max-width: 480px) { .prototype-scope, .footer-separator { display: none; } }
</style>
