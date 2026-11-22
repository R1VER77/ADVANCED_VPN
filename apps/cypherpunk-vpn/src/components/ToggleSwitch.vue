<script setup lang="ts">
defineProps<{ on: boolean; busy?: boolean; disabled?: boolean; label: string }>()
defineEmits<{ toggle: [] }>()
</script>
<template>
  <button class="switch" :class="{ on, busy }" role="switch" :aria-checked="on" :aria-label="label" :disabled="disabled" @click="$emit('toggle')"><span class="knob"><svg viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 2v5M4.4 4.4a5 5 0 1 0 7.2 0" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" /></svg></span></button>
</template>
<style scoped>
.switch { width: 56px; height: 31px; position: relative; flex: none; border: 1px solid var(--line); padding: 0; border-radius: 20px; background: var(--line); transition: background .25s; }
.switch.on { background: var(--primary); border-color: var(--primary); }
.switch:disabled { opacity: .4; }
.knob { display: grid; place-items: center; position: absolute; top: 3px; left: 3px; width: 23px; height: 23px; border-radius: 50%; background: white; color: #a3a3a3; box-shadow: 0 1px 4px #00000025; transition: transform .3s cubic-bezier(.22,.8,.25,1), color .25s; }
.knob svg { width: 14px; height: 14px; }
.on .knob { transform: translateX(25px); color: var(--primary); }
.busy .knob svg { visibility: hidden; }
.busy .knob::after { content: ''; position: absolute; inset: 5px; border: 1.5px solid var(--primary); border-top-color: transparent; border-radius: 50%; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
