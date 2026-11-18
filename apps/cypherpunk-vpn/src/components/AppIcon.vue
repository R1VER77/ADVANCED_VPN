<script setup lang="ts">
withDefaults(defineProps<{ name: string; size?: number }>(), { size: 20 })
const paths: Record<string, string> = {
  shield: 'M12 3 4 6v5c0 5 8 10 8 10s8-5 8-10V6l-8-3Zm-4 9 3 3 5-6',
  lock: 'M7 10V7a5 5 0 0 1 10 0v3M6 10h12v11H6V10Zm6 4v3',
  settings: 'm9.5 3-.7 2.5-2 .9-2.3-.6L2 10l1.7 1.8v2.3L2 16l2.5 4.2 2.4-.6 2 .9.6 2.5h5l.7-2.5 2-.9 2.3.6L22 16l-1.7-1.9v-2.3L22 10l-2.5-4.2-2.4.6-2-.9L14.5 3h-5ZM15.5 13a3.5 3.5 0 1 1-7 0 3.5 3.5 0 0 1 7 0Z',
  chevron: 'm9 5 7 7-7 7',
  down: 'm6 9 6 6 6-6',
  check: 'm5 12 4 4L19 6',
  close: 'm6 6 12 12M6 18 18 6',
  moon: 'M20.5 14.3A8.8 8.8 0 0 1 9.7 3.5a9 9 0 1 0 10.8 10.8Z',
  sun: 'M12 2v2m0 16v2M2 12h2m16 0h2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z',
  bolt: 'm13 2-8 12h6l-1 8 9-13h-7l1-7Z',
  route: 'M6 7a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm12 16a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM6 7v7a4 4 0 0 0 4 4h5M9 4h7a4 4 0 0 1 4 4v7',
  key: 'M14 13a6 6 0 1 0-3-4L3 17v4h4v-3h3l4-5ZM16 6h.01',
  info: 'M12 11v6m0-10h.01M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0Z',
  globe: 'M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0ZM2 12h20M12 2c5 5 5 15 0 20-5-5-5-15 0-20Z',
  copy: 'M9 9h12v12H9V9ZM15 5V3H3v12h2',
  plus: 'M12 5v14M5 12h14',
  minus: 'M5 12h14',
  locate: 'M12 2v4m0 12v4M2 12h4m12 0h4M19 12a7 7 0 1 1-14 0 7 7 0 0 1 14 0ZM12 10v4m-2-2h4',
  file: 'M14 2H5v20h14V7l-5-5ZM14 2v6h5M8 13h8m-8 4h6',
  computer: 'M3 3h18v13H3V3Zm5 18h8m-4-5v5',
  arrow: 'M4 12h16m-6-6 6 6-6 6',
}
</script>
<template>
  <svg :width="size" :height="size" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path :d="paths[name] ?? paths.info" /></svg>
</template>
