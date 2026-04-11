import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  base: '/notify/',
  build: {
    outDir: '../../server/web/static/notify',
    emptyOutDir: true,
  },
})
