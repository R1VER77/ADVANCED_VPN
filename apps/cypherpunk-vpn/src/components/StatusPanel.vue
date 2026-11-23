<script setup lang="ts">
import { computed, ref } from 'vue'
import AppIcon from './AppIcon.vue'
import { countryName } from '../controller/locations'
import type { Rate, Status } from '../controller/types'
import CountryFlag from './CountryFlag.vue'
import ToggleSwitch from './ToggleSwitch.vue'

const props = defineProps<{ status: Status | null; unavailable: boolean; nowSec: number }>()
const emit = defineEmits<{
  connect: []
  disconnect: []
  retry: []
  startService: []
  settings: []
  rate: [Rate]
  resign: []
}>()

type Tone = 'ok' | 'warn' | 'bad' | 'neutral'

// One place maps the controller's verdict to words. "Connected" only for "protected".
const view = computed(() => {
  const s = props.status
  if (props.unavailable || !s) {
    return {
      title: 'Status unknown', tone: 'neutral' as Tone, on: false, busy: false,
      line: "This window can't reach the CYPHERPUNK service.",
    }
  }
  switch (s.state) {
    case 'connected':
      if (s.protection !== 'protected') return { title: 'Status unknown', tone: 'neutral' as Tone, on: false, busy: false, line: 'Connection protection could not be verified.' }
      return { title: 'Connected', tone: 'ok' as Tone, on: true, busy: false, line: 'Your traffic is protected.' }
    case 'connecting':
      return { title: 'Connecting…', tone: 'warn' as Tone, on: true, busy: true, line: 'Traffic is blocked until the connection is verified.' }
    case 'locked':
      return { title: 'Unlocking…', tone: 'warn' as Tone, on: true, busy: true, line: 'Traffic is blocked until the connection is verified.' }
    case 'reconnecting':
      return { title: 'Reconnecting…', tone: 'warn' as Tone, on: true, busy: true, line: 'Traffic stays blocked while we reconnect.' }
    case 'failed':
      return { title: 'Not connected', tone: 'bad' as Tone, on: false, busy: false, line: 'Your VPN traffic is blocked.' }
    case 'cleartext_allowed':
      return { title: 'Unprotected', tone: 'bad' as Tone, on: false, busy: false, line: 'You allowed traffic without the VPN. It is visible to your network.' }
    case 'disconnected':
      return { title: 'Disconnected', tone: 'neutral' as Tone, on: false, busy: false, line: 'Your VPN traffic is blocked until you connect.' }
    default:
      return { title: 'Status unknown', tone: 'neutral' as Tone, on: false, busy: false, line: '' }
  }
})

const verifiedAgo = computed(() => {
  const e = props.status?.evidence
  if (!e) return null
  const s = Math.max(0, props.nowSec - e.path_probe_at)
  return s < 2 ? 'just now' : `${s} s ago`
})

const notice = computed(() => {
  const s = props.status
  if (props.unavailable || !s) {
    return {
      tone: 'neutral' as Tone,
      title: "The CYPHERPUNK service isn't responding",
      text: "If it was running, its firewall still blocks your traffic: it stays in place after a crash. This window just can't check right now.",
      actions: [['Start the service', 'startService'], ['Try again', 'retry']] as const,
    }
  }
  if (s.state === 'failed' || s.state === 'reconnecting') {
    const map: Record<string, { title: string; text: string; actions: readonly (readonly [string, string])[] }> = {
      network_down: {
        title: 'No network connection',
        text: 'Your computer is offline. CYPHERPUNK reconnects by itself when the network is back; your traffic stays blocked until then.',
        actions: [['Try now', 'retry']],
      },
      relay_unreachable: {
        title: 'The first server is not answering',
        text: 'It may be down or blocked on this network. Your traffic stays blocked.',
        actions: [['Try again', 'retry']],
      },
      server_auth_failed: {
        title: "The server couldn't prove who it is",
        text: s.detail ?? 'CYPHERPUNK stopped before sending anything. Your traffic stays blocked.',
        actions: [['How to fix this', 'resign'], ['Try again', 'retry']],
      },
      chain_outdated: {
        title: 'Your connection settings are out of date',
        text: 'They were made for an older CYPHERPUNK version. Ask your operator for a new device file.',
        actions: [['How to fix this', 'resign']],
      },
      nitrokey_pin_rejected: {
        title: 'Wrong Nitrokey PIN',
        text: s.detail ? `The PIN was not accepted. ${s.detail}.` : 'The PIN was not accepted.',
        actions: [['Enter the PIN again', 'connect']],
      },
      nitrokey_missing: {
        title: 'Plug in your Nitrokey',
        text: 'CYPHERPUNK needs your Nitrokey to unlock your keys.',
        actions: [["It's plugged in", 'connect']],
      },
    }
    const m = s.reason ? map[s.reason] : undefined
    if (m) return { tone: s.state === 'failed' ? ('bad' as Tone) : ('warn' as Tone), ...m }
  }
  return null
})

const tab = ref<'connection' | 'details'>('connection')
const elapsed = computed(() => {
  if (!props.status || props.status.protection !== 'protected' || props.unavailable) return null
  const seconds = Math.max(0, props.nowSec - props.status.since)
  return `${Math.floor(seconds / 3600).toString().padStart(2, '0')}:${Math.floor(seconds / 60 % 60).toString().padStart(2, '0')}:${(seconds % 60).toString().padStart(2, '0')}`
})
const rates: { id: Rate; name: string; hint: string }[] = [
  { id: 'metered', name: 'Metered', hint: 'Light messaging' },
  { id: 'standard', name: 'Standard', hint: 'Everyday browsing' },
  { id: 'fast', name: 'Fast', hint: 'Streaming & downloads' },
  { id: 'line', name: 'Line', hint: 'Highest cover bandwidth' },
]

function act(a: string) {
  if (a === 'retry') emit('retry')
  else if (a === 'startService') emit('startService')
  else if (a === 'connect') emit('connect')
  else if (a === 'resign') emit('resign')
}

function toggle() {
  if (view.value.on) emit('disconnect')
  else emit('connect')
}
</script>

<template>
  <section class="panel" aria-label="Connection controls">
    <div class="status" aria-live="polite">
      <div class="status-top"><span class="eyebrow">Your connection</span><span v-if="elapsed" class="elapsed"><span />{{ elapsed }}</span></div>
      <div class="status-main">
        <h1 :class="view.tone">{{ view.title }}</h1>
        <ToggleSwitch :on="view.on" :busy="view.busy" :disabled="unavailable || !status?.enrolled" :label="view.on ? 'Disconnect' : 'Connect'" @toggle="toggle" />
      </div>
      <p class="line">{{ view.line }}</p>
      <p v-if="status?.detail && view.busy" class="detail">{{ status.detail }}</p>
      <span v-if="verifiedAgo && !unavailable && status?.protection === 'protected'" class="verified"><AppIcon name="shield" :size="13" /> Connection verified <span class="verified-time">· {{ verifiedAgo }}</span></span>
      <span v-else-if="!view.busy && !unavailable" class="blocked-label"><AppIcon name="lock" :size="12" /> Kill switch active</span>
    </div>

    <transition name="fade">
      <div v-if="notice" class="notice" :class="notice.tone" role="alert">
        <div class="notice-heading"><AppIcon name="info" :size="15" /><strong>{{ notice.title }}</strong></div>
        <p>{{ notice.text }}</p>
        <div class="actions"><button v-for="([label, a], i) in notice.actions" :key="a" class="btn" :class="{ secondary: i > 0 }" @click="act(a)">{{ label }}</button></div>
      </div>
    </transition>

    <div class="tabs" role="tablist" aria-label="Connection information">
      <button id="connection-tab" role="tab" :aria-selected="tab === 'connection'" aria-controls="connection-view" :class="{ active: tab === 'connection' }" @click="tab = 'connection'">Connection</button>
      <button id="details-tab" role="tab" :aria-selected="tab === 'details'" aria-controls="details-view" :class="{ active: tab === 'details' }" @click="tab = 'details'">Details</button>
    </div>
    <div v-if="tab === 'connection'" id="connection-view" class="connection-view" role="tabpanel" aria-labelledby="connection-tab">
      <div class="rows">
        <div class="row">
          <span class="row-icon"><AppIcon name="shield" :size="18" /></span>
          <div class="row-copy"><div class="name">Kill switch</div><div class="sub">Blocks traffic outside the VPN</div></div>
          <span class="locked" :class="{ stale: unavailable }"><AppIcon :name="unavailable ? 'info' : 'lock'" :size="11" /> {{ unavailable ? 'Unknown' : 'Always on' }}</span>
        </div>
        <div class="row">
          <span class="row-icon"><AppIcon name="bolt" :size="18" /></span>
          <div class="row-copy"><div class="name">Speed</div><div class="sub">{{ rates.find((r) => r.id === (status?.rate ?? 'fast'))?.hint }}</div></div>
          <div class="rate-wrap"><select class="rate" :value="status?.rate ?? 'fast'" :disabled="unavailable || !status?.enrolled" aria-label="Speed" @change="$emit('rate', ($event.target as HTMLSelectElement).value as Rate)"><option v-for="r in rates" :key="r.id" :value="r.id">{{ r.name }}</option></select><AppIcon name="down" :size="12" /></div>
        </div>
      </div>
      <div class="servers">
        <div class="servers-head"><span class="eyebrow">Your route</span><span class="hops">{{ status?.chain.length ?? 0 }}-hop connection</span></div>
        <div class="route-stack">
          <button v-for="(h, i) in status?.chain ?? []" :key="i" class="server" title="View signed route settings" @click="$emit('settings')">
            <CountryFlag :code="h.country" />
            <span class="server-copy"><span class="label">{{ (status?.chain.length ?? 0) === 1 ? 'VPN server' : i === 0 ? 'Entry server' : i === (status?.chain.length ?? 0) - 1 ? 'Exit server' : 'Middle server' }}</span><span class="where"><span class="city">{{ h.city }}</span><span class="country">{{ countryName(h.country) }}</span></span></span>
            <span class="server-right"><span class="provider">{{ h.provider }}</span><AppIcon name="chevron" :size="14" /></span>
          </button>
        </div>
        <div class="servers-note"><AppIcon name="lock" :size="11" /> Route signed by your operator</div>
      </div>
    </div>
    <div v-else id="details-view" class="details-view" role="tabpanel" aria-labelledby="details-tab">
      <div class="detail-heading"><AppIcon name="shield" :size="18" /><strong>Protection details</strong></div>
      <p class="detail-intro">Reported by the simulated controller.</p>
      <dl><div><dt>Key exchange</dt><dd>{{ status?.crypto?.kex ?? 'Not available' }}</dd></div><div><dt>Server authentication</dt><dd>{{ status?.crypto?.auth ?? 'Not available' }}</dd></div><div><dt>Cloak protocol</dt><dd>{{ status?.crypto?.cloak ?? 'Not available' }} · mutual key confirmation</dd></div><div><dt>Traffic protection</dt><dd>{{ unavailable ? 'Unknown' : status?.protection ?? 'Unknown' }}</dd></div></dl>
      <p class="detail-intro">These are prototype values. Live verification is not connected.</p>
    </div>
    <footer class="panel-footer"><span class="device-icon"><AppIcon name="key" :size="17" /></span><div><strong>Nitrokey secured</strong><span>{{ unavailable ? 'Last known device configuration' : 'This device · Enrolled' }}</span></div><AppIcon name="check" :size="15" /></footer>
  </section>
</template>

<style scoped>
.panel { width: 306px; flex: none; min-height: 0; height: 100%; background: var(--panel); border-right: 1px solid var(--line); display: flex; flex-direction: column; z-index: 2; overflow: hidden; }
.status { padding: 21px 23px 20px; }
.status-top { display: flex; justify-content: space-between; align-items: center; min-height: 13px; }
.elapsed { display: flex; gap: 5px; align-items: center; font-size: 10px; font-variant-numeric: tabular-nums; color: var(--muted); }
.elapsed > span { width: 4px; height: 4px; border-radius: 50%; background: var(--ok); }
.status-main { display: flex; align-items: center; justify-content: space-between; margin-top: 9px; gap: 10px; }
h1 { font-size: 29px; font-weight: 550; letter-spacing: -1.1px; line-height: 1.25; margin: 0; transition: color .18s ease; }
h1.ok { color: var(--ok-text); }
h1.warn { color: var(--warn); font-size: 25px; }
h1.bad { color: var(--bad); }
h1.neutral { font-size: 27px; }
.line { color: var(--muted); font-size: 12px; line-height: 1.65; margin: 9px 0 11px; max-width: 230px; }
.verified, .blocked-label { display: flex; align-items: center; gap: 5px; font-size: 10px; color: var(--ok-text); }
.verified-time { color: var(--muted); }
.blocked-label { color: var(--muted); }
.detail { color: var(--muted); font-size: 12px; line-height: 1.5; }
.tabs { display: flex; padding: 0 23px; border-bottom: 1px solid var(--line); gap: 23px; }
.tabs button { border: 0; border-bottom: 2px solid transparent; background: transparent; padding: 11px 0 12px; color: var(--muted); font-size: 12px; font-weight: 550; }
.tabs button.active { color: var(--primary-text); border-bottom-color: var(--primary); }
.connection-view { flex: 1; min-height: 0; overflow-y: auto; }
.rows { padding: 5px 23px 7px; border-bottom: 1px solid var(--line); }
.row { display: flex; align-items: center; gap: 10px; padding: 11px 0; }
.row-icon { color: var(--muted); display: grid; place-items: center; }
.row-copy { flex: 1; min-width: 0; }
.name { font-size: 13px; font-weight: 550; }
.sub { font-size: 10px; line-height: 1.6; color: var(--muted); margin-top: 3px; }
.locked { display: flex; gap: 3px; align-items: center; font-size: 10px; white-space: nowrap; color: var(--primary-text); }
.locked.stale { color: var(--muted); }
.rate-wrap { display: flex; position: relative; align-items: center; }
.rate-wrap > svg { position: absolute; right: 7px; pointer-events: none; color: var(--muted); }
.rate { appearance: none; border: 1px solid var(--line); border-radius: 5px; background: var(--bg); color: var(--text); font-size: 11px; padding: 6px 24px 6px 9px; max-width: 100px; }
.servers { padding: 19px 23px 10px; }
.servers-head { display: flex; align-items: center; justify-content: space-between; }
.hops { padding: 3px 6px; background: var(--bg); border-radius: 4px; font-size: 10px; color: var(--muted); }
.route-stack { position: relative; margin-top: 14px; }
.route-stack::before { content: ''; position: absolute; left: 12px; top: 26px; bottom: 26px; border-left: 1px dashed var(--line); }
.server { display: flex; align-items: center; gap: 12px; position: relative; width: 100%; padding: 10px 0; text-align: left; color: var(--text); background: transparent; border: 0; border-radius: 5px; }
.server:hover { background: var(--bg); }
.server :deep(.flag) { z-index: 1; }
.server-copy { display: flex; flex-direction: column; gap: 4px; flex: 1; }
.label { color: var(--muted); font-size: 10px; }
.where { display: flex; flex-direction: column; gap: 3px; }
.city { font-size: 13px; font-weight: 600; }
.country { font-size: 10px; color: var(--muted); }
.server-right { display: flex; align-items: center; gap: 8px; color: var(--faint); }
.provider { font-size: 8px; }
.servers-note { display: flex; align-items: center; gap: 5px; margin-top: 8px; font-size: 10px; color: var(--muted); }
.panel-footer { display: flex; align-items: center; gap: 10px; margin-top: auto; padding: 12px 23px; border-top: 1px solid var(--line); min-height: 57px;
  flex-shrink: 0; }
.panel-footer > svg { margin-left: auto; color: var(--ok); }
.device-icon { display: grid; place-items: center; border: 1px solid var(--line); border-radius: 7px; width: 30px; height: 30px; color: var(--primary-text); }
.panel-footer strong, .panel-footer span:not(.device-icon) { display: block; }
.panel-footer strong { font-size: 11px; font-weight: 550; }
.panel-footer div > span { font-size: 10px; color: var(--muted); margin-top: 4px; }
.notice { margin: 0 16px 16px; padding: 12px; background: var(--bg); border: 1px solid var(--line); border-radius: 7px; }
.notice.warn { background: var(--warn-soft); }
.notice.bad { background: var(--bad-soft); }
.notice-heading { display: flex; align-items: flex-start; gap: 7px; }
.notice strong { font-size: 12px; line-height: 1.5; }
.notice p { font-size: 11px; line-height: 1.7; color: var(--muted); margin: 8px 0 12px; }
.actions { display: flex; gap: 6px; flex-wrap: wrap; }
.actions .btn { font-size: 11px; min-height: 29px; padding: 5px 8px; }
.details-view { padding: 22px 23px; flex: 1; min-height: 0; overflow-y: auto; }
.detail-heading { display: flex; align-items: center; gap: 8px; font-size: 13px; }
.detail-intro { color: var(--muted); font-size: 11px; line-height: 1.7; }
dl { margin: 24px 0; }
dl div { padding: 11px 0; border-bottom: 1px solid var(--line); }
dt { font-size: 10px; color: var(--muted); }
dd { margin: 5px 0 0; font-size: 12px; overflow-wrap: anywhere; user-select: text; }
@media (max-width: 620px) { .panel { width: 100%; border-right: 0; } }
</style>
