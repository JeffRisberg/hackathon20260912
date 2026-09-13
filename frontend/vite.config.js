import dgram from 'node:dgram'

import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'

const FRONTEND_COMM_PORT = Number(
  loadEnv('development', process.cwd(), '').FRONTEND_COMM_PORT || 8766,
)

// Listens on FRONTEND_COMM_PORT (UDP) for messages from agent_red — a
// separate port from AGENT_COMM_PORT (used between agent_red/agent_blue) so
// the two listeners don't race to bind the same UDP port — and prints them
// to the terminal running the Vite dev server.
function agentCommLoggerPlugin() {
  return {
    name: 'agent-comm-logger',
    configureServer(server) {
      const socket = dgram.createSocket('udp4')
      socket.on('message', (msg) => {
        const text = msg.toString()
        console.log(`[agent-comm:${FRONTEND_COMM_PORT}] ${text}`)
        server.ws.send({ type: 'custom', event: 'agent-comm-message', data: { text } })
      })
      socket.on('error', (err) => {
        console.error(`[agent-comm:${FRONTEND_COMM_PORT}] error:`, err)
      })
      socket.bind(FRONTEND_COMM_PORT, '127.0.0.1')
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), agentCommLoggerPlugin()],
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
