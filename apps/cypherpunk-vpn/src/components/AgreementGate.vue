<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from 'vue'
import agreement from '../controller/agreement.json'
import { operator } from '../controller/real'
import AppIcon from './AppIcon.vue'

// The first-launch agreement: the risks first, then the terms and privacy notice in full.
// Acceptance is recorded by the helper, as this user, with the version (a hash of the
// documents) and the time; nothing leaves the computer. New documents ask again.
const emit = defineEmits<{ accepted: [] }>()

type Block = { k: 'p' | 'li'; t: string }
type Section = { heading: string; blocks: Block[] }
type Document = { title: string; sections: Section[] }
const documents = agreement.documents as Document[]

const page = ref<'risks' | 'terms'>('risks')
const understood = ref(false)
const responsible = ref(false)
const accepted = ref(false)
const working = ref(false)
const error = ref('')
const heading = ref<HTMLElement | null>(null)

const risks = [
  { icon: 'eye-off', title: 'What a VPN hides, and what it does not',
    text: 'Your network sees only encrypted traffic to your first server, and no single server sees both your address and where you go. Websites still see what you send them and anything you sign in to, and your exit\'s provider sees the traffic that leaves it.' },
  { icon: 'server', title: 'Your servers, your accounts, your bills',
    text: 'The servers run in your own cloud accounts, under your providers\' terms. The app keeps each server inside its free allowance where one exists, but the accounts and any charges are yours, and so is the traffic that leaves your exit.' },
  { icon: 'key', title: 'Nobody can recover your keys',
    text: 'Your security key and its PIN protect everything. There is no company, no account and no reset: a lost key means setting up again with new servers.' },
]

const canAccept = computed(() => accepted.value && !working.value)

async function show(next: 'risks' | 'terms') {
  page.value = next
  await nextTick()
  heading.value?.focus()
}

async function accept() {
  if (!canAccept.value) return
  working.value = true
  error.value = ''
  try {
    await operator.acceptAgreement(agreement.version)
    emit('accepted')
  } catch {
    error.value = 'Your acceptance could not be saved, so the app cannot start yet. Try again; if it keeps failing, reinstall the app.'
  } finally { working.value = false }
}

async function reject() {
  working.value = true
  try { await operator.quit() } finally { working.value = false }
}

onMounted(() => heading.value?.focus())
</script>

<template>
  <div class="gate">
    <section v-if="page === 'risks'" class="sheet" aria-labelledby="risks-title">
      <span class="eyebrow">Step 1 of 2</span>
      <h1 id="risks-title" ref="heading" tabindex="-1">Understand the risks</h1>
      <p class="lead">Before you use cypherpunk_vpn, please read how it works and what it cannot do.</p>
      <ul class="risks">
        <li v-for="risk in risks" :key="risk.title">
          <AppIcon :name="risk.icon" class="icon" />
          <div><strong>{{ risk.title }}</strong><p>{{ risk.text }}</p></div>
        </li>
      </ul>
      <label class="check"><input v-model="understood" type="checkbox" /> I understand what this VPN hides and what it does not.</label>
      <label class="check"><input v-model="responsible" type="checkbox" /> I understand that my servers, accounts, costs and keys are my responsibility.</label>
      <div class="buttons"><button class="btn" :disabled="!understood || !responsible" @click="show('terms')">Next</button></div>
    </section>

    <section v-else class="sheet terms" aria-labelledby="terms-title">
      <span class="eyebrow">Step 2 of 2</span>
      <h1 id="terms-title" ref="heading" tabindex="-1">Terms and privacy</h1>
      <div class="scroll" tabindex="0" aria-label="Terms of service and privacy notice">
        <article v-for="doc in documents" :key="doc.title">
          <h2>{{ doc.title }}</h2>
          <section v-for="(section, n) in doc.sections" :key="n">
            <h3 v-if="section.heading">{{ section.heading }}</h3>
            <template v-for="(block, m) in section.blocks" :key="m">
              <p v-if="block.k === 'p'">{{ block.t }}</p>
              <p v-else class="item">{{ block.t }}</p>
            </template>
          </section>
        </article>
      </div>
      <label class="check"><input v-model="accepted" type="checkbox" /> I have read and accept these terms.</label>
      <p v-if="error" class="error" role="alert">{{ error }}</p>
      <div class="buttons">
        <button class="btn quiet" :disabled="working" @click="show('risks')">Back</button>
        <span class="spacer" />
        <button class="btn secondary" :disabled="working" @click="reject">Reject and quit</button>
        <button class="btn" :disabled="!canAccept" @click="accept">Accept</button>
      </div>
    </section>
  </div>
</template>

<style scoped>
.gate { display: grid; place-items: center; height: 100%; padding: 24px; overflow: auto; background: var(--bg); }
.sheet { display: flex; flex-direction: column; width: min(640px, 100%); max-height: 100%; padding: 32px; border: 1px solid var(--line); border-radius: 14px; background: var(--panel); }
.terms { height: min(760px, 100%); }
.eyebrow { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .8px; }
h1 { font-size: 26px; letter-spacing: -.6px; margin: 10px 0 8px; outline: none; }
.lead, .risks p, .scroll p { font-size: 13px; line-height: 1.65; color: var(--muted); }
.risks { list-style: none; padding: 0; margin: 14px 0 8px; }
.risks li { display: flex; gap: 14px; padding: 14px 0; border-top: 1px solid var(--line); }
.risks strong { font-size: 14px; }
.risks p { margin: 4px 0 0; }
.icon { flex: none; width: 22px; height: 22px; margin-top: 2px; color: var(--text); }
.scroll { flex: 1; min-height: 0; overflow-y: auto; padding: 4px 18px 4px 4px; margin: 8px 0 14px; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
.scroll h2 { font-size: 18px; margin: 18px 0 6px; }
.scroll h3 { font-size: 14px; margin: 16px 0 4px; }
.scroll p { margin: 6px 0; color: var(--text); }
.scroll .item { padding-left: 16px; position: relative; }
.scroll .item::before { content: '–'; position: absolute; left: 2px; color: var(--muted); }
.check { display: flex; align-items: flex-start; gap: 10px; margin: 10px 0 0; font-size: 13px; line-height: 1.5; cursor: pointer; }
.check input { margin-top: 3px; accent-color: var(--text); }
.buttons { display: flex; align-items: center; gap: 10px; margin-top: 20px; }
.spacer { flex: 1; }
.error { color: var(--bad); font-size: 12px; margin: 10px 0 0; }
@media (max-width: 560px) { .sheet { padding: 20px; } .buttons { flex-wrap: wrap; } .spacer { display: none; } }
</style>
