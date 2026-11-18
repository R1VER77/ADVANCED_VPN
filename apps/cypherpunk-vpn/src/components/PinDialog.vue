<script setup lang="ts">
// Prototype only. Production PIN entry belongs to the system dialog, never this UI.
import { onMounted, onUnmounted, ref } from 'vue'
import AppIcon from './AppIcon.vue'
const emit = defineEmits<{ answer: [entered: boolean] }>()
const pin = ref('')
const touch = ref(false)
const input = ref<HTMLInputElement | null>(null)
const dialog = ref<HTMLElement | null>(null)
let timer = 0
const opener = document.activeElement as HTMLElement | null
onMounted(() => input.value?.focus())
onUnmounted(() => { clearTimeout(timer); if (opener?.isConnected) opener.focus() })
function ok() {
  if (!pin.value || touch.value) return
  pin.value = ''
  touch.value = true
  timer = window.setTimeout(() => emit('answer', true), 1100)
}
function keydown(event: KeyboardEvent) {
  if (event.key === 'Escape') { event.preventDefault(); emit('answer', false); return }
  if (event.key !== 'Tab') return
  const items = dialog.value?.querySelectorAll<HTMLElement>('button:not(:disabled), input')
  if (!items?.length) return
  const first = items[0], last = items[items.length - 1]
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
}
</script>
<template>
  <div class="backdrop" @keydown="keydown">
    <div ref="dialog" class="dialog" role="dialog" aria-modal="true" aria-labelledby="pin-title">
      <span class="key-icon"><AppIcon name="key" :size="25" /></span>
      <span class="eyebrow">Simulated system dialog</span>
      <template v-if="!touch">
        <h2 id="pin-title">Unlock your connection</h2>
        <p>The real app asks for your Nitrokey PIN in a system dialog. Use any test value here.</p>
        <label for="demo-pin">Demo Nitrokey PIN</label>
        <input id="demo-pin" ref="input" v-model="pin" type="password" placeholder="Enter a test PIN" autocomplete="off" @keyup.enter="ok" />
        <div class="buttons"><button class="btn secondary" @click="emit('answer', false)">Cancel</button><button class="btn" :disabled="!pin" @click="ok">OK <AppIcon name="arrow" :size="14" /></button></div>
      </template>
      <template v-else>
        <h2 id="pin-title">Touch your Nitrokey</h2><p>Confirm with a touch when the light flashes.</p><div class="key"><span class="led" /></div><p class="touch-note">Touch simulated automatically in this preview.</p>
      </template>
    </div>
  </div>
</template>
<style scoped>
.backdrop { position: fixed; inset: 0; background: #17102635; backdrop-filter: blur(3px); display: grid; place-items: center; z-index: 20; padding: 18px; }
.dialog { width: 370px; max-width: 100%; background: var(--panel); border: 1px solid var(--line); border-radius: 14px; box-shadow: 0 24px 90px #20133230; padding: 29px; }
.key-icon { display: grid; place-items: center; width: 48px; height: 48px; background: var(--primary-soft); color: var(--primary); border-radius: 14px; margin-bottom: 22px; }
.eyebrow { color: var(--warn); font-size: 9px; }
h2 { margin: 11px 0 10px; font-weight: 600; font-size: 23px; line-height: 1.3; letter-spacing: -.6px; }
p { margin: 0 0 20px; color: var(--muted); font-size: 12px; line-height: 1.8; }
label { display: block; font-size: 11px; font-weight: 550; margin-bottom: 9px; }
input { width: 100%; font: inherit; padding: 11px 13px; border: 1px solid var(--line); border-radius: 7px; background: var(--bg); color: var(--text); }
input::placeholder { font-size: 11px; color: var(--faint); }
.buttons { display: flex; justify-content: flex-end; gap: 8px; margin-top: 23px; }
.key { margin: 30px auto; width: 95px; height: 32px; border-radius: 7px; background: #36313e; display: grid; place-items: center; box-shadow: inset 0 0 0 1px #ffffff20; }
.led { width: 7px; height: 7px; border-radius: 50%; background: #67d6a8; box-shadow: 0 0 10px #67d6a860; animation: blink .6s ease-in-out infinite; }
.touch-note { text-align: center; font-size: 10px; margin: 0; }
@keyframes blink { 50% { opacity: .2; } }
</style>
