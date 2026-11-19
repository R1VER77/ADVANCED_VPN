<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { controller } from '../controller/real'
import type { ProviderSearchPage } from '../controller/types'

const query = ref('')
const page = ref<ProviderSearchPage | null>(null)
const busy = ref(false)
const error = ref(false)
const selected = ref('')
let generation = 0

async function search(cursor: string | null = null) {
  const current = ++generation
  busy.value = true
  error.value = false
  if (!cursor) { page.value = null; selected.value = '' }
  try {
    const result = await controller.providers(query.value, cursor)
    if (current === generation) page.value = result
  } catch { if (current === generation) { error.value = true; page.value = null } }
  finally { if (current === generation) busy.value = false }
}

onMounted(() => search())
onUnmounted(() => { generation++ })
</script>

<template>
  <section class="provider-search" aria-labelledby="provider-heading">
    <h3 id="provider-heading">Find your cloud provider</h3>
    <p>Search the local directory. Listings include tools for services other than servers.</p>
    <form @submit.prevent="search()">
      <label for="provider-query">Provider name</label>
      <div class="search-row">
        <input id="provider-query" v-model="query" type="search" maxlength="256" autocomplete="off" placeholder="For example, Hetzner" @input="generation++; page = null; selected = ''; error = false; busy = false">
        <button class="btn secondary" type="submit" :disabled="busy">Search</button>
      </div>
    </form>
    <p v-if="busy" role="status">Searching…</p>
    <p v-else-if="error" role="alert">The provider directory could not be read. Try again after refreshing the controller.</p>
    <template v-else-if="page">
      <p role="status">{{ page.total_matches.toLocaleString() }} matching listings</p>
      <ul aria-label="Provider listings">
        <li v-for="provider in page.results" :key="provider.id">
          <button type="button" :aria-pressed="selected === provider.id" @click="selected = provider.id">
            <strong>{{ provider.id }}</strong>
            <span>{{ provider.reviewed_recipe_candidate ? 'Guided setup under review' : 'Listed · setup not yet reviewed' }}</span>
          </button>
        </li>
      </ul>
      <button v-if="page.next_cursor" class="btn secondary" :disabled="busy" @click="search(page.next_cursor)">Next results</button>
    </template>
    <p v-if="selected" class="selected" role="status">Selected: {{ selected }}. Guided provisioning is not available yet. No server has been created.</p>
    <p class="privacy">Search stays on this device. No provider sign-in is requested here.</p>
  </section>
</template>

<style scoped>
.provider-search { margin-top: 20px; padding-top: 12px; border-top: 1px solid var(--line); }
h3 { font-size: 14px; margin: 8px 0; }
p, label { font-size: 12px; color: var(--muted); line-height: 1.6; }
label { display: block; margin: 10px 0 6px; }
.search-row { display: flex; gap: 8px; }
input { min-width: 0; flex: 1; width: 100%; border: 1px solid var(--line); border-radius: 6px; padding: 9px; color: var(--text); background: var(--bg); font: inherit; font-size: 12px; }
ul { list-style: none; margin: 8px 0 12px; padding: 0; max-height: 260px; overflow: auto; border: 1px solid var(--line); border-radius: 7px; }
li + li { border-top: 1px solid var(--line); }
li button { width: 100%; text-align: left; padding: 10px; background: transparent; border: 0; color: var(--text); cursor: pointer; }
li button[aria-pressed="true"] { background: var(--bg); box-shadow: inset 3px 0 var(--primary-text); }
strong { display: block; overflow-wrap: anywhere; font-size: 12px; }
li span, .privacy { display: block; font-size: 10px; color: var(--muted); margin-top: 4px; }
.selected { color: var(--primary-text); overflow-wrap: anywhere; }
</style>
