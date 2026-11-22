<script setup lang="ts">
// Demo controls. Visible only with the simulated controller; never in the real app.
import { ref } from 'vue'
import AppIcon from './AppIcon.vue'
import { SITES } from '../controller/locations'
import type { Fault, MockOptions } from '../controller/mock'

const props = defineProps<{
  networkUp: boolean
  unavailable: boolean
  pinOutcome: MockOptions['pinOutcome']
  route: string[]
}>()
const emit = defineEmits<{
  fault: [Fault]
  restore: []
  pin: [MockOptions['pinOutcome']]
  reset: ['fresh' | 'disconnected' | 'connected']
  route: [string[]]
}>()
const open = ref(false)

const continents = [...new Set(SITES.map((s) => s.continent))]
const label = (i: number, n: number) => (n === 1 ? 'Server' : i === 0 ? 'Entry' : i === n - 1 ? 'Exit' : 'Middle ' + (n > 3 ? i : ''))
// Spare sites for added hops, spread around the world so the map has to travel.
const SPARE = ['tyo', 'nyc', 'sin', 'sao', 'syd', 'jnb', 'rek', 'tor']

function setHops(n: number) {
  const r = [...props.route]
  while (r.length > n) r.splice(r.length - 2 >= 0 ? r.length - 2 : 0, 1) // drop middles first, keep the exit
  for (const id of SPARE) {
    if (r.length >= n) break
    if (!r.includes(id)) r.splice(Math.max(1, r.length - 1), 0, id) // add as a middle hop
  }
  emit('route', r.slice(0, n))
}

function setSite(i: number, id: string) {
  const r = [...props.route]
  r[i] = id
  emit('route', r)
}
</script>

<template>
  <aside class="demo" :class="{ open }">
    <button class="head" :aria-expanded="open" @click="open = !open"><span class="pill">DEMO</span> Preview controls <AppIcon name="down" :size="11" :class="{ flipped: open }" /></button>
    <div v-if="open" class="body" @keydown.esc="open = false">
      <p class="note">Nothing here touches a network, firewall or key.</p>
      <div class="group">
        <span>Simulate</span>
        <button v-if="props.networkUp" @click="emit('fault', 'network_down')">Lose network</button>
        <button v-else class="on" @click="emit('restore')">Restore network</button>
        <button @click="emit('fault', 'server_auth_failed')">Server fails its proof</button>
        <button :disabled="props.unavailable" @click="emit('fault', 'controller_unavailable')">Service stops</button>
      </div>
      <div class="group">
        <span>Next PIN</span>
        <button :class="{ on: pinOutcome === 'ok' }" @click="emit('pin', 'ok')">correct</button>
        <button :class="{ on: pinOutcome === 'wrong' }" @click="emit('pin', 'wrong')">wrong</button>
        <button :class="{ on: pinOutcome === 'no_key' }" @click="emit('pin', 'no_key')">no key</button>
      </div>
      <div class="group route">
        <span>Route (as a new device file would set it)</span>
        <div class="hops">
          <button v-for="n in 4" :key="n" :class="{ on: route.length === n }" @click="setHops(n)">
            {{ n }} {{ n === 1 ? 'hop' : 'hops' }}
          </button>
        </div>
        <label v-for="(id, i) in route" :key="i" class="hop">
          <em>{{ label(i, route.length) }}</em>
          <select :value="id" @change="setSite(i, ($event.target as HTMLSelectElement).value)">
            <optgroup v-for="c in continents" :key="c" :label="c">
              <option v-for="s in SITES.filter((x) => x.continent === c)" :key="s.id" :value="s.id">
                {{ s.city }}, {{ s.countryName }}
              </option>
            </optgroup>
          </select>
        </label>
      </div>
      <div class="group">
        <span>Start over</span>
        <button @click="emit('reset', 'fresh')">First use</button>
        <button @click="emit('reset', 'disconnected')">Enrolled</button>
      </div>
    </div>
  </aside>
</template>

<style scoped>
.demo { position: relative; font-size: 11px; }
.head { display: flex; align-items: center; gap: 6px; border: 0; background: transparent; color: var(--muted); padding: 4px 2px; font-size: 10px; }
.head:hover { color: var(--primary-text); }
.head svg { transform: rotate(180deg); }
.head .flipped { transform: rotate(0); }
.pill { color: var(--warn); font-size: 8px; font-weight: 650; letter-spacing: .05em; }
.body { position: absolute; right: -2px; bottom: 30px; width: 300px; max-height: calc(100vh - 100px); overflow-y: auto; padding: 17px; border: 1px solid var(--line); background: var(--panel); border-radius: 11px; box-shadow: 0 12px 48px #00000022; }
.note {
  margin: 0 0 8px;
  color: var(--muted);
}
.group {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  align-items: center;
  margin-top: 6px;
}
.group span {
  width: 100%;
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.group button {
  border: 1px solid var(--line);
  background: var(--bg);
  color: var(--text);
  border-radius: 6px;
  padding: 4px 8px;
  font-size: 12px;
}
.group button.on {
  border-color: var(--primary);
  background: var(--primary-soft);
}
.group button:disabled {
  opacity: 0.5;
}
.route .hops {
  display: flex;
  gap: 5px;
  width: 100%;
}
.hop {
  display: flex;
  align-items: center;
  gap: 6px;
  width: 100%;
}
.hop em {
  font-style: normal;
  color: var(--muted);
  width: 52px;
  flex: none;
}
.hop select {
  flex: 1;
  min-width: 0;
  font: inherit;
  font-size: 12px;
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 3px 4px;
  background: var(--bg);
  color: var(--text);
}
</style>
