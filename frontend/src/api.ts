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

export interface DefenseReport {
  attack_blocked: boolean
  blocking_reason: string
  log_pattern_detected: boolean
  recommendation: string
  narrative: string
  log: string[]
}

export interface RunAgentOptions {
  socketId?: string
  sessionId?: string
  providerPath?: string
  password?: string
  /** Prior Blue defense report text for Red to verify against. */
  blueContext?: string
  /** When true, Red replays against the hardened agent (post-fix). */
  expectBlocked?: boolean
}

async function readError(res: Response, label: string): Promise<never> {
  let detail = ''
  try {
    const data = await res.json()
    detail =
      typeof data?.detail === 'string'
        ? data.detail
        : JSON.stringify(data?.detail ?? data)
  } catch {
    detail = await res.text().catch(() => '')
  }
  throw new Error(
    detail ? `${label} failed (${res.status}): ${detail}` : `${label} failed (${res.status})`,
  )
}

// Proxied by vite.config.js → agent_red FastAPI (default 8000).
const RED_AGENT_RUN_URL = '/api/red/run'
// Proxied by vite.config.js → agent_blue FastAPI (default 8001).
const BLUE_AGENT_RUN_URL = '/api/blue/run'

export async function runBlueAgent(
  options: RunAgentOptions = {},
): Promise<DefenseReport> {
  const body: Record<string, string> = {}
  if (options.socketId) body.socket_id = options.socketId
  if (options.sessionId) body.session_id = options.sessionId
  if (options.providerPath) body.provider_path = options.providerPath
  if (options.password) body.password = options.password

  const res = await fetch(BLUE_AGENT_RUN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) await readError(res, 'Blue agent run')
  return res.json() as Promise<DefenseReport>
}

export async function runRedAgent(
  options: RunAgentOptions = {},
): Promise<ReplayResult> {
  const body: Record<string, unknown> = {}
  if (options.socketId) body.socket_id = options.socketId
  if (options.sessionId) body.session_id = options.sessionId
  if (options.providerPath) body.provider_path = options.providerPath
  if (options.password) body.password = options.password
  if (options.blueContext) body.blue_context = options.blueContext
  if (options.expectBlocked != null) body.expect_blocked = options.expectBlocked

  const res = await fetch(RED_AGENT_RUN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) await readError(res, 'Red agent run')
  return res.json() as Promise<ReplayResult>
}
