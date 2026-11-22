<script setup lang="ts">
import logo from '../assets/cypherpunk-vpn-logo.png'
</script>
<template>
  <span class="wordmark"><img :src="logo" alt="Cypherpunk VPN" width="1672" height="941" draggable="false" /></span>
</template>
<style scoped>
/* Preserve the GitHub PNG exactly. Clip only its transparent canvas padding. */
.wordmark { display: block; position: relative; width: 214px; aspect-ratio: 1504 / 377; overflow: hidden; flex-shrink: 0; }
.wordmark img { display: block; position: absolute; width: 111.1702%; height: auto; max-width: none; left: -8.7766%; top: -65.7825%; filter: var(--logo-filter); }

</style>
