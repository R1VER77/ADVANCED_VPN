<script setup lang="ts">
import { ref } from 'vue'
import AppIcon from './AppIcon.vue'
import type { CommandResult, Hop } from '../controller/types'

const props = defineProps<{ enroll: (file: string) => Promise<CommandResult>; demo: boolean; route: Hop[] }>()
// `hold`: keep this flow on screen through its result, although the controller already
// reports enrolled by then.
const emit = defineEmits<{ done: [connectNow: boolean]; hold: [] }>()

type Step = 'welcome' | 'choose' | 'checking' | 'success' | 'error'
const step = ref<Step>('welcome')
const file = ref('')
const error = ref('')

const demoFiles = [
  ['laptop.cpvpn', 'a valid device file'],
  ['laptop-corrupt.cpvpn', 'damaged in transfer'],
  ['laptop-other-operator.cpvpn', 'signed by someone else'],
  ['laptop-expired.cpvpn', 'too old'],
]

const errors: Record<string, [string, string]> = {
  bundle_invalid: ["This isn't a valid CYPHERPUNK device file", 'It may have been damaged when it was copied. Ask your operator to send it again.'],
  bundle_wrong_operator: ['This file was signed by a different operator', "CYPHERPUNK only installs files signed by the operator this computer trusts. If you didn't expect this, don't use the file and tell your operator."],
  bundle_expired: ['This device file has expired', 'Ask your operator for a new one.'],
  controller_unavailable: ["The CYPHERPUNK service isn't responding", 'Start the service, then try again.'],
}

async function pick(name: string) {
  file.value = name
  emit('hold')
  step.value = 'checking'
  const r = await props.enroll(name)
  if (r.ok) step.value = 'success'
  else {
    error.value = r.reason
    step.value = 'error'
  }
}
</script>

<template>
  <section class="panel">
    <header class="top"><span class="eyebrow">Getting started</span><span class="setup-step">{{ step === 'welcome' || step === 'choose' ? '01' : '02' }} / 02</span></header>

    <transition name="fade" mode="out-in">
      <div v-if="step === 'welcome'" key="w" class="body">
        <div class="welcome-icon"><AppIcon name="shield" :size="29" /></div><h1>Your privacy.<br>Your control.</h1>
        <p>To set up CYPHERPUNK on this computer you need two things from your operator:</p>
        <ol>
          <li><strong>A device file</strong> ending in <code>.cpvpn</code></li>
          <li><strong>Your Nitrokey</strong>, which unlocks your keys</li>
        </ol>
        <p class="muted">Until you connect, CYPHERPUNK changes nothing on this computer.</p>
        <button class="btn wide" @click="step = 'choose'">Add device file…</button>
      </div>

      <div v-else-if="step === 'choose'" key="c" class="body">
        <h1>Choose your device file</h1>
        <p class="muted">In the app this opens your system's file chooser.</p>
        <div v-if="demo" class="picker" role="listbox" aria-label="Device files (demo)">
          <div class="picker-head">Demo files</div>
          <button v-for="[name, what] in demoFiles" :key="name" class="file" @click="pick(name)">
            <span class="fname"><AppIcon name="file" :size="15" /> {{ name }}</span>
            <span class="what">{{ what }}</span>
          </button>
        </div>
        <button class="btn quiet" @click="step = 'welcome'">Back</button>
      </div>

      <div v-else-if="step === 'checking'" key="k" class="body center">
        <div class="spinner" aria-hidden="true" />
        <h2>Checking {{ file }}</h2>
        <p class="muted">Verifying your operator's signature</p>
      </div>

      <div v-else-if="step === 'success'" key="s" class="body">
        <div class="badge ok">✓</div>
        <h1>Device added</h1>
        <p>Your operator's signature checks out. Your signed route: <strong>{{ props.route.map((hop) => hop.city).join(' → ') || 'Ready to connect' }}</strong>.</p>
        <p class="muted">Connecting asks for your Nitrokey PIN in a system dialog, then a touch on the key.</p>
        <button class="btn wide" @click="emit('done', true)">Connect now</button>
        <button class="btn quiet wide" @click="emit('done', false)">Later</button>
      </div>

      <div v-else key="e" class="body">
        <div class="badge bad">!</div>
        <h1>{{ errors[error]?.[0] ?? 'This file could not be installed' }}</h1>
        <p>{{ errors[error]?.[1] ?? error }}</p>
        <p class="muted">Nothing was installed.</p>
        <button class="btn wide" @click="step = 'choose'">Choose another file</button>
      </div>
    </transition>
  </section>
</template>

<style scoped>
.panel {
  width: 306px;
  flex: none;
  height: 100%;
  background: var(--panel);
  border-right: 1px solid var(--line);
  display: flex;
  flex-direction: column;
  z-index: 2;
}
.top {
  padding: 24px 24px 8px;
  display: flex; align-items: center; justify-content: space-between;
}
.brand {
  font-weight: 700;
  letter-spacing: 0.08em;
  font-size: 11px;
  color: var(--muted);
}
.mark {
  color: var(--primary-text);
}
.body {
  padding: 21px 24px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.body.center {
  align-items: center;
  text-align: center;
  padding-top: 80px;
}
h1 {
  font-size: 28px;
  letter-spacing: -1px;
  font-weight: 600;
  margin: 8px 0 8px;
}
h2 {
  font-size: 17px;
  font-weight: 600;
  margin: 16px 0 4px;
}
p {
  font-size: 12px;
  color: var(--muted);
  line-height: 1.7;
  margin: 6px 0;
}
ol {
  font-size: 11px;
  margin: 4px 0 8px;
  padding-left: 20px;
  line-height: 1.7;
}
code {
  background: var(--bg);
  padding: 1px 5px;
  border-radius: 4px;
}
.muted {
  color: var(--muted);
  font-size: 11px;
}
.wide {
  width: 100%;
  margin-top: 10px;
  padding: 11px;
}
.picker {
  margin: 12px 0 6px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  overflow: hidden;
}
.picker-head {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  padding: 8px 12px;
  background: var(--bg);
}
.file {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  width: 100%;
  border: 0;
  border-top: 1px solid var(--line);
  background: var(--panel);
  color: var(--text);
  padding: 9px 12px;
  text-align: left;
}
.file:hover {
  background: var(--primary-soft);
}
.fname {
  display: flex; align-items: center; gap: 8px;
  font-size: 11px;
  font-weight: 500;
}
.what {
  font-size: 12px;
  color: var(--muted);
}
.badge {
  width: 44px;
  height: 44px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  font-size: 22px;
  font-weight: 700;
  color: #fff;
}
.badge.ok {
  background: var(--ok);
}
.badge.bad {
  background: var(--bad);
}
.spinner {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  border: 3px solid var(--line);
  border-top-color: var(--primary);
  animation: spin 0.9s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
.welcome-icon { width: 58px; height: 58px; border-radius: 17px; display: grid; place-items: center; color: var(--primary); background: var(--primary-soft); margin: 17px 0 13px; }
.setup-step { font-size: 9px; color: var(--faint); font-variant-numeric: tabular-nums; }
@media (max-width: 620px) { .panel { width: 100%; overflow-y: auto; } }
</style>
