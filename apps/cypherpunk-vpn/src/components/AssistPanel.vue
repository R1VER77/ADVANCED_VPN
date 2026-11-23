<script setup lang="ts">
import { ref } from 'vue'
import { operator } from '../controller/real'
import type { Assist, Fix, FixResult } from '../controller/types'

// Shown under a failed build. The diagnosis and the fixes come from fixed rules
// (tools/troubleshoot.py); the local assistant only adds plain words, labelled as such.
const emit = defineEmits<{ retry: []; signin: [server: string] }>()

const LABEL: Record<string, string> = {
  retry_build: 'Build the route again',
  sign_in_aws: 'Sign in to AWS',
  host_update: 'Update the server first',
  unlock_server: 'Unlock the server',
  check_health: 'Check the servers',
  open_docs: '',
}
const NOTE: Record<string, string> = {
  pin_blocked: 'Unplug the security key and plug it in again, then build the route again. Too many more wrong PINs lock the key for good.',
  fly_token_missing: 'Set the Fly.io deploy token again (see the Fly exit guide), then build the route again.',
  capped: 'The server starts carrying traffic again on the 1st of the month.',
}

// Why the installed assistant could not add its words (tools/assistant.py reasons).
const UNAVAILABLE: Record<string, string> = {
  no_network_isolation: 'this system did not allow its network-less sandbox',
  model_did_not_start: 'its model did not start (this processor may lack AVX2)',
  model_not_verified: 'its model file is not the pinned one, so it was not run',
  model_error: 'its model did not answer',
  answer_too_large: 'its model did not answer',
  answer_refused: 'its answer could not be used',
}

const result = ref<Assist | null>(null)
const asking = ref(false)
const running = ref<string | null>(null)
const ran = ref<FixResult | null>(null)
const error = ref('')

async function ask() {
  asking.value = true
  error.value = ''
  try { result.value = await operator.assist() }
  catch { error.value = 'The build\'s record could not be read.' }
  finally { asking.value = false }
}

async function run(fix: Fix) {
  error.value = ''
  ran.value = null
  if (fix.action === 'retry_build') { emit('retry'); return }
  if (fix.action === 'sign_in_aws' && fix.server) { emit('signin', fix.server); return }
  if (fix.action !== 'host_update' && fix.action !== 'unlock_server' && fix.action !== 'check_health') return
  running.value = fix.action
  try { ran.value = await operator.fix(fix.action, fix.server ?? null) }
  catch { error.value = 'That fix could not be run.' }
  finally { running.value = null }
}
</script>

<template>
  <div class="assist">
    <button v-if="!result" class="btn secondary small" :disabled="asking" @click="ask">
      {{ asking ? 'Looking at what happened…' : 'Why did this fail?' }}
    </button>
    <template v-else>
      <strong class="title">{{ result.finding.title }}</strong>
      <p class="meaning">{{ result.finding.meaning }}</p>
      <p v-if="result.reply.source === 'assistant'" class="words">
        <span class="label">In other words (local assistant; may be imprecise):</span> {{ result.reply.explanation }}
      </p>
      <p v-else-if="UNAVAILABLE[result.reply.why ?? '']" class="meaning">
        The local assistant is installed but could not help: {{ UNAVAILABLE[result.reply.why ?? ''] }}.
      </p>
      <p v-if="NOTE[result.finding.code]" class="meaning">{{ NOTE[result.finding.code] }}</p>
      <div class="fixes">
        <template v-for="(f, i) in result.finding.fixes" :key="f.action + (f.server ?? '')">
          <button v-if="LABEL[f.action]" class="btn small" :class="{ secondary: i > 0 }" :disabled="!!running" @click="run(f)">
            {{ running === f.action ? 'Working… (your key may ask for its PIN and a touch)' : LABEL[f.action] }}
          </button>
        </template>
      </div>
      <details v-if="result.finding.evidence.length">
        <summary>What the build said</summary>
        <ul><li v-for="e in result.finding.evidence" :key="e"><code>{{ e }}</code></li></ul>
      </details>
      <div v-if="ran" class="ran" :class="{ bad: !ran.ok }">
        <p>{{ ran.ok ? 'Done.' : 'That did not finish.' }}<template v-if="ran.ok && ran.action !== 'check_health'"> Build the route again when you are ready.</template></p>
        <ul v-if="ran.output.length"><li v-for="(o, i) in ran.output" :key="i"><code>{{ o }}</code></li></ul>
      </div>
    </template>
    <p v-if="error" class="bad">{{ error }}</p>
  </div>
</template>

<style scoped>
.assist { margin: 12px 0; padding: 12px 14px; border: 1px solid var(--line); border-radius: 8px; background: var(--bg); }
.title { display: block; font-size: 13px; }
.meaning, .words, .ran p { font-size: 12px; line-height: 1.6; color: var(--muted); margin: 6px 0; }
.words { color: var(--text); }
.label { color: var(--muted); }
.fixes { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0 4px; }
details { margin-top: 8px; font-size: 11px; }
summary { cursor: pointer; color: var(--muted); }
ul { margin: 6px 0 0; padding-left: 16px; }
code { font-size: 10.5px; word-break: break-all; }
.bad { color: var(--bad); }
</style>
