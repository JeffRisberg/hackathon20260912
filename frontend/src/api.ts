export interface ReplayResult {
  session_bind_refused_while_locked: boolean
  forwarded_channel_opened: boolean
  provider_accepted: boolean
  provider_helper_started: boolean
  provider_initialized: boolean
  reproduced: boolean
  narrative: string
  log: string[]
}

export interface RunRedAgentOptions {
  socketId?: string
  sessionId?: string
  providerPath?: string
  password?: string
}

// Proxied by vite.config.js to the agent_red FastAPI server (RED_AGENT_PORT, default 8000).
const RED_AGENT_RUN_URL = '/api/red/run'

export async function runRedAgent(options: RunRedAgentOptions = {}): Promise<ReplayResult> {
  const body: Record<string, string> = {}
  if (options.socketId) body.socket_id = options.socketId
  if (options.sessionId) body.session_id = options.sessionId
  if (options.providerPath) body.provider_path = options.providerPath
  if (options.password) body.password = options.password

  const res = await fetch(RED_AGENT_RUN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  if (!res.ok) {
    throw new Error(`Red agent run failed (${res.status})`)
  }

  return res.json() as Promise<ReplayResult>
}
