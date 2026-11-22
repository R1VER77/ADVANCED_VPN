<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import catalogJson from '../controller/providers.json'
import { controller } from '../controller/real'
import ProviderLogo from './ProviderLogo.vue'
import type { CatalogProvider, OperatorState, ProviderCatalog, ProviderSearchPage } from '../controller/types'

const catalog = catalogJson as ProviderCatalog
const props = defineProps<{ state: OperatorState; busy: boolean }>()
const emit = defineEmits<{ close: []; add: [key: string]; remove: [key: string]; check: [key: string] }>()
const query = ref('')
const sheet = ref<HTMLElement | null>(null)
const tiers: Record<number, string> = { 1: 'Privacy hosts', 2: 'Outside the US', 3: 'US companies' }

const rows = computed(() => {
  const q = query.value.trim().toLowerCase()
  return catalog.providers.filter(p => !q || `${p.service} ${p.company} ${p.key} ${p.parent}`.toLowerCase().includes(q))
})
const servers = (key: string) => props.state.servers.filter(s => s.provider === key).length
const added = (key: string) => props.state.profile.providers.includes(key)

function data(p: CatalogProvider) {
  if (p.egress_gb === 'unmetered') return 'Unmetered data'
  if (p.egress_gb === null) return 'Data allowance not published'
  if (p.egress_gb === 0) return 'Data billed per GB'
  return p.egress_gb >= 1000 ? `${Math.round(p.egress_gb / 1000)} TB a month included` : `${p.egress_gb} GB a month included`
}
function cost(p: CatalogProvider) {
  if (p.month_usd === null) return 'Price not checked'
  return p.month_usd === 0 ? 'Free' : `≈ $${p.month_usd.toFixed(2)}`
}
// The OpenTofu registry (4,000+ providers) is searched inside the controller's local
// copy: nothing leaves this computer. Listed is not reviewed: the app cannot set them up yet.
const registry = ref<ProviderSearchPage | null>(null)
const registryTotal = ref<number | null>(null)
const registryBusy = ref(false)
let generation = 0, debounce = 0
async function searchRegistry(cursor: string | null = null) {
  const q = query.value.trim(), mine = ++generation
  if (q.length < 2) { registry.value = null; return }
  registryBusy.value = true
  try {
    const page = await controller.providers(q, cursor)
    if (mine === generation) registry.value = cursor && registry.value ? { ...page, results: [...registry.value.results, ...page.results] } : page
  } catch { if (mine === generation) registry.value = null }
  finally { if (mine === generation) registryBusy.value = false }
}
watch(query, () => { window.clearTimeout(debounce); debounce = window.setTimeout(() => searchRegistry(), 250) })
onMounted(async () => {
  sheet.value?.focus()
  try { registryTotal.value = (await controller.providers('', null)).total_matches } catch { registryTotal.value = null }
})
</script>

<template>
  <div class="backdrop" @click.self="emit('close')">
    <section ref="sheet" class="sheet" role="dialog" aria-modal="true" aria-labelledby="sheet-title" tabindex="-1" @keydown.esc="emit('close')">
      <header>
        <div><h2 id="sheet-title">Cloud providers</h2>
          <p>Privacy hosts first, then the most data for the money. Cost is one server carrying {{ catalog.plan_gb }} GB in a month, prices as of {{ catalog.checked }}. Check the provider's page before you buy.</p></div>
        <button class="close" aria-label="Close" @click="emit('close')">✕</button>
      </header>
      <input v-model="query" type="search" class="search" placeholder="Search providers, including the OpenTofu registry" aria-label="Search providers">
      <div class="list">
        <template v-for="(p, i) in rows" :key="p.key">
          <h3 v-if="i === 0 || rows[i - 1].tier !== p.tier">{{ tiers[p.tier] }}</h3>
          <div class="row" :class="{ added: added(p.key) }">
            <ProviderLogo :provider="p.key" :name="p.service" :size="34" />
            <div class="what">
              <strong>{{ p.service }}</strong>
              <span>{{ p.parent }} · {{ data(p) }}<template v-if="p.note"> · {{ p.note }}</template></span>
              <span v-if="state.profile.checked[p.key]" :class="state.profile.checked[p.key].ready ? 'ok' : 'warn'">{{ state.profile.checked[p.key].why }}</span>
              <span v-if="servers(p.key)" class="ok">{{ servers(p.key) }} server{{ servers(p.key) > 1 ? 's' : '' }} recorded</span>
            </div>
            <div class="side">
              <span class="cost">{{ cost(p) }}<small v-if="p.month_usd">/mo</small></span>
              <button v-if="!added(p.key)" class="btn secondary small" :disabled="busy" @click="emit('add', p.key); emit('check', p.key)">Add</button>
              <button v-else class="btn quiet small" :disabled="busy" @click="emit('remove', p.key)">Remove</button>
            </div>
          </div>
        </template>
        <p v-if="!rows.length && !registry?.results.length" class="empty">No provider matches.</p>
        <h3>OpenTofu registry<template v-if="registryTotal"> · {{ registryTotal.toLocaleString() }} providers</template></h3>
        <p v-if="query.trim().length < 2" class="empty">Type a name to search every provider in the OpenTofu registry.</p>
        <p v-else-if="registryBusy && !registry" class="empty">Searching…</p>
        <template v-else-if="registry">
          <p class="empty">{{ registry.total_matches.toLocaleString() }} matching. Listed in the registry, not yet reviewed for setup in this app.</p>
          <div v-for="r in registry.results" :key="r.id" class="row registry">
            <ProviderLogo :provider="r.id" :name="r.name" :size="34" />
            <div class="what"><strong>{{ r.id }}</strong><span>{{ r.reviewed_recipe_candidate ? 'Recipe under review' : 'Listed only' }}</span></div>
          </div>
          <button v-if="registry.next_cursor" class="btn quiet small" :disabled="registryBusy" @click="searchRegistry(registry.next_cursor)">More results</button>
        </template>
      </div>
      <footer><span>{{ state.profile.providers.length }} in profile <strong>{{ state.profile.name }}</strong> · {{ state.profile.active_providers }} active</span><button class="btn" @click="emit('close')">Done</button></footer>
    </section>
  </div>
</template>

<style scoped>
.backdrop { position: fixed; inset: 0; display: grid; place-items: center; padding: 20px; background: #00000059; z-index: 30; }
.sheet { width: min(640px, 100%); max-height: 88vh; display: flex; flex-direction: column; border-radius: 14px; border: 1px solid var(--line); background: var(--panel); box-shadow: 0 24px 90px #00000030; outline: none; }
header { display: flex; gap: 16px; padding: 22px 22px 8px; }
h2 { margin: 0 0 6px; font-size: 18px; }
header p { margin: 0; font-size: 12px; color: var(--muted); line-height: 1.6; }
.close { flex: none; align-self: flex-start; border: 0; background: none; color: var(--muted); font-size: 15px; }
.search { margin: 8px 22px 6px; padding: 9px 11px; border: 1px solid var(--line); border-radius: 8px; background: var(--bg); color: var(--text); }
.list { overflow-y: auto; padding: 0 22px 10px; }
h3 { margin: 16px 0 6px; font-size: 10px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }
.row { display: flex; align-items: center; gap: 12px; padding: 10px; border-radius: 10px; }
.row:hover { background: var(--bg); }
.row.added { background: var(--primary-soft); }
.what { flex: 1; min-width: 0; display: grid; gap: 3px; }
.what strong { font-size: 13px; }
.what span { font-size: 11px; color: var(--muted); }
.what .ok { color: var(--ok-text); }
.what .warn { color: var(--warn); }
.side { display: grid; justify-items: end; gap: 6px; }
.cost { font-size: 13px; font-weight: 600; white-space: nowrap; }
.cost small { font-weight: 400; color: var(--muted); }
.small { padding: 5px 12px; font-size: 12px; }
.empty { color: var(--muted); font-size: 12px; }
footer { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 14px 22px; border-top: 1px solid var(--line); font-size: 12px; color: var(--muted); }
</style>
