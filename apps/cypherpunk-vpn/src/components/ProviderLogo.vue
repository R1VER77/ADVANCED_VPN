<script setup lang="ts">
import { computed } from 'vue'

// Logos ship inside the app (tools/provider_logos.py); none is ever fetched. A provider
// without a shipped logo gets a lettered tile.
const files = import.meta.glob('../assets/providers/*.svg', { eager: true, query: '?url', import: 'default' }) as Record<string, string>
const props = defineProps<{ provider: string; name?: string; size?: number }>()
const WORDMARKS = ['aws', 'ionos']
const url = computed(() => files[`../assets/providers/${props.provider}.svg`])
const letters = computed(() => (props.name ?? props.provider).replace(/[^A-Za-z0-9 ]/g, '').split(' ').filter(Boolean).slice(0, 2).map(w => w[0]).join('').toUpperCase() || '?')
</script>

<template>
  <span class="logo" :style="{ width: `${size ?? 36}px`, height: `${size ?? 36}px` }" aria-hidden="true">
    <img v-if="url" :src="url" alt="" :class="{ wide: WORDMARKS.includes(provider) }">
    <span v-else class="letters">{{ letters }}</span>
  </span>
</template>

<style scoped>
.logo { flex: none; display: grid; place-items: center; border-radius: 8px; background: #fff; border: 1px solid var(--line); overflow: hidden; }
img { width: 76%; height: 76%; object-fit: contain; }
img.wide { width: 92%; height: 92%; }
.letters { font-size: 11px; font-weight: 700; color: #4c4a57; letter-spacing: .02em; }
</style>
