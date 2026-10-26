import { fileURLToPath, URL } from 'node:url'

import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [vue()],
  build: {
    emptyOutDir: true,
    modulePreload: {
      polyfill: false,
    },
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
      pinia: fileURLToPath(new URL('./node_modules/pinia/dist/pinia.esm-browser.prod.js', import.meta.url)),
    },
  },
  clearScreen: false,
  server: {
    // The port must match `devUrl` in src-tauri/tauri.conf.json. Without an explicit port Vite
    // listens on its own default and `tauri dev` waits forever for a dev server that never
    // appears.
    //
    // The host is the literal 127.0.0.1 while `devUrl` stays `http://localhost:1420`, and the
    // asymmetry is deliberate. Binding the name `localhost` can leave Vite on ::1 only, and a
    // webview that resolves the name to 127.0.0.1 then loads a blank page; binding the literal
    // removes that failure. `devUrl` cannot use the literal in return — Tauri leaves the window
    // on about:blank when it does — so the name stays on that side, resolving to the address
    // Vite is actually bound to. Loopback either way; nothing is exposed to the network.
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
  },
})
