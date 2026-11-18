import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

// https://vite.dev/config/
export default defineConfig(({ mode }) => ({
  plugins: [vue()],
  // The offline world map (Natural Earth 1:50m, ~750 KB) is bundled on purpose.
  build: {
    chunkSizeWarningLimit: 1500,
    rollupOptions: { input: fileURLToPath(new URL(mode === 'demo' ? './demo.html' : './index.html', import.meta.url)) },
  },
}))
