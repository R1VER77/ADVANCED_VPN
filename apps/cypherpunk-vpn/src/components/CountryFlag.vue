<script setup lang="ts">
import { countryName } from '../controller/locations'
defineProps<{ code: string }>()
</script>
<template>
  <svg class="flag" viewBox="0 0 24 16" role="img" :aria-label="countryName(code)">
    <template v-if="['SE', 'FI', 'NO', 'IS'].includes(code)">
      <rect width="24" height="16" :fill="({ SE: '#086fa9', FI: '#fff', NO: '#c62035', IS: '#0d529a' } as Record<string,string>)[code]" />
      <path d="M9 0v16M0 8h24" :stroke="code === 'SE' ? '#ffcf38' : code === 'FI' ? '#155b9b' : '#fff'" :stroke-width="code === 'SE' || code === 'FI' ? 3 : 5" />
      <path v-if="code === 'NO' || code === 'IS'" d="M9 0v16M0 8h24" :stroke="code === 'NO' ? '#173b78' : '#d53643'" stroke-width="2.4" />
    </template>
    <template v-else-if="['DE', 'NL', 'IN'].includes(code)">
      <rect width="24" height="5.34" :fill="code === 'DE' ? '#191919' : code === 'NL' ? '#b82b3d' : '#ed993e'" /><rect y="5.33" width="24" height="5.34" :fill="code === 'DE' ? '#dc3b38' : '#fff'" /><rect y="10.66" width="24" height="5.34" :fill="code === 'DE' ? '#ffd345' : code === 'NL' ? '#254e9a' : '#298543'" />
      <circle v-if="code === 'IN'" cx="12" cy="8" r="1.9" fill="none" stroke="#214f94" stroke-width=".6" />
    </template>
    <template v-else-if="code === 'FR' || code === 'RO'"><rect width="8" height="16" fill="#244894" /><rect x="8" width="8" height="16" :fill="code === 'FR' ? '#fff' : '#f5cf3d'" /><rect x="16" width="8" height="16" fill="#d33b49" /></template>
    <template v-else-if="code === 'JP'"><rect width="24" height="16" fill="#fff" /><circle cx="12" cy="8" r="4.3" fill="#c62946" /></template>
    <template v-else-if="code === 'CH'"><rect width="24" height="16" fill="#d5323f" /><path d="M12 3v10M7 8h10" stroke="white" stroke-width="3" /></template>
    <template v-else-if="code === 'US'"><rect width="24" height="16" fill="white" /><path v-for="n in 7" :key="n" :d="`M0 ${(n - 1) * 2.46 + .62}h24`" stroke="#b8384b" stroke-width="1.24" /><rect width="10" height="8.7" fill="#334c87" /><g fill="white"><circle v-for="n in 9" :key="n" :cx="1.7 + (n - 1) % 3 * 3" :cy="1.6 + Math.floor((n - 1) / 3) * 2.6" r=".4" /></g></template>
    <template v-else-if="code === 'GB' || code === 'AU'"><rect width="24" height="16" fill="#244679" /><g :transform="code === 'AU' ? 'scale(.5)' : ''"><path d="m0 0 24 16M0 16 24 0" stroke="white" stroke-width="3.8" /><path d="m0 0 24 16M0 16 24 0" stroke="#c63e4b" stroke-width="1.5" /><path d="M12 0v16M0 8h24" stroke="white" stroke-width="5.5" /><path d="M12 0v16M0 8h24" stroke="#c63e4b" stroke-width="2.8" /></g><g v-if="code === 'AU'" fill="white"><circle cx="6" cy="12" r="1.2" /><circle cx="18" cy="4" r=".8" /><circle cx="16" cy="9" r=".8" /><circle cx="21" cy="8" r=".8" /><circle cx="19" cy="13" r="1" /></g></template>
    <template v-else-if="code === 'CA'"><rect width="24" height="16" fill="white" /><path d="M0 0h6v16H0ZM18 0h6v16h-6Z" fill="#d63e4b" /><path d="m12 3 1.2 3 1.6-1-.3 2.4 2 .1-1.1 1.6.9 1-3.7.8.4 2.1h-1l.3-2.1-3.7-.8.9-1-1.1-1.6 2-.1-.3-2.4 1.6 1Z" fill="#d63e4b" /></template>
    <template v-else-if="code === 'BR'"><rect width="24" height="16" fill="#299251" /><path d="m12 2 9 6-9 6-9-6Z" fill="#f7d44d" /><circle cx="12" cy="8" r="3.7" fill="#29539a" /><path d="M8.5 7c3-1 5 .3 7 2" fill="none" stroke="white" stroke-width=".9" /></template>
    <template v-else-if="code === 'SG'"><rect width="24" height="8" fill="#da4a56" /><rect y="8" width="24" height="8" fill="white" /><circle cx="6" cy="4" r="2.7" fill="white" /><circle cx="7.3" cy="3.6" r="2.3" fill="#da4a56" /><g fill="white"><circle cx="11" cy="2" r=".45" /><circle cx="13" cy="3.5" r=".45" /><circle cx="12.3" cy="5.5" r=".45" /><circle cx="9.7" cy="5.5" r=".45" /><circle cx="9" cy="3.5" r=".45" /></g></template>
    <template v-else-if="code === 'KR'"><rect width="24" height="16" fill="white" /><circle cx="12" cy="8" r="3.5" fill="#c84654" /><path d="M8.5 8c0-3 3.5-1.5 3.5 0s3.5 3 3.5 0a3.5 3.5 0 0 1-7 0" fill="#315b97" /><path d="m4 3 2-1m-1 3 2-1m10 8 2-1m-1 3 2-1M4 12l2 1m-1 1 2 1m10-12 2 1m-1-3 2 1" stroke="#252525" stroke-width="1" /></template>
    <template v-else-if="code === 'ZA'"><rect width="24" height="8" fill="#cb4650" /><rect y="8" width="24" height="8" fill="#315694" /><path d="m0 0 11 8L0 16" fill="#222" /><path d="m0 0 11 8L0 16" fill="none" stroke="#f6c644" stroke-width="3" /><path d="m0-2 13 10h11M0 18 13 8" fill="none" stroke="white" stroke-width="6" /><path d="m0-2 13 10h11M0 18 13 8" fill="none" stroke="#328765" stroke-width="3.5" /></template>
    <template v-else-if="code === 'IL'"><rect width="24" height="16" fill="white" /><path d="M0 3h24M0 13h24" stroke="#3975b8" stroke-width="2" /><path d="m12 5 3 5H9Zm0 6 3-5H9Z" stroke="#3975b8" stroke-width=".7" fill="none" /></template>
    <template v-else><rect width="24" height="16" fill="var(--line)" /><text x="12" y="11.5" font-size="8" text-anchor="middle" fill="var(--muted)">{{ code }}</text></template>
  </svg>
</template>
<style scoped>
.flag { width: 24px; height: 16px; border-radius: 2px; box-shadow: 0 0 0 1px #19152a12; flex: none; }
</style>
