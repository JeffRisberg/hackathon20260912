import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api/red': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        timeout: 180_000,
        proxyTimeout: 180_000,
        rewrite: (path) => path.replace(/^\/api\/red/, ''),
      },
      '/api/blue': {
        target: 'http://127.0.0.1:8001',
        changeOrigin: true,
        timeout: 180_000,
        proxyTimeout: 180_000,
        rewrite: (path) => path.replace(/^\/api\/blue/, ''),
      },
    },
  },
})
