import { useRef, useState } from 'react'
import { runRedAgent } from '../api'
import './SecWeave.css'

function cellLabel(status) {
  if (status === 'rejected') return 'rejected'
  if (status === 'accepted') return 'accepted'
  return status || '—'
}

const initialResult = {
  weaveLine: 'Weave: secweave',
  statusLine: 'Idle — subject starts vulnerable',
  activeRole: null,
  flow: null,
  redDetail: 'Waiting',
  blueDetail: 'Waiting',
  iterBadge: '—',
  reqPane: '—',
  resPane: '—',
  resClass: '',
  wireMeta: 'No calls yet',
  subjectPane: '—',
  diffPane: '—',
  isFixed: false,
  greenVisible: false,
  greenDetail: '',
  running: false,
}

function SecWeave() {
  const [ui, setUi] = useState(initialResult)
  const [eventLog, setEventLog] = useState([])

  const matrixRef = useRef({ rows: [], iters: [], cells: {}, activeCell: null })
  const logKeyRef = useRef(0)

  function appendLog(role, text) {
    logKeyRef.current += 1
    setEventLog((prev) => [{ id: logKeyRef.current, role, text }, ...prev])
  }

  async function startLoop() {
    setUi((prev) => ({
      ...prev,
      running: true,
      activeRole: 'red',
      flow: 'flow-up',
      statusLine: 'Calling Red agent (port 8000)…',
      redDetail: 'Running forwarded-agent lock bypass replay…',
    }))
    appendLog('red', 'POST /run → agent_red')

    try {
      const result = await runRedAgent()
      appendLog('red', result.reproduced ? 'Bypass reproduced' : 'Bypass not reproduced')
      setUi((prev) => ({
        ...prev,
        running: false,
        activeRole: null,
        flow: null,
        statusLine: result.reproduced
          ? 'Red agent run complete — bypass reproduced'
          : 'Red agent run complete — bypass not reproduced',
        redDetail: result.narrative,
        resPane: JSON.stringify(result, null, 2),
        wireMeta: 'Red agent /run response',
      }))
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      appendLog('system', `Red agent call failed: ${message}`)
      setUi((prev) => ({
        ...prev,
        running: false,
        activeRole: null,
        flow: null,
        statusLine: `Red agent call failed: ${message}`,
        redDetail: 'Waiting',
      }))
    }
  }

  const m = matrixRef.current

  return (
    <div className={`secweave${ui.isFixed ? ' is-fixed' : ''}`}>
      <div className="atmosphere" aria-hidden="true"></div>

      <header className="hero">
        <p className="tagline">
          Progressive tests: simple first. Complex only after pass. Blue LLM fixes gaps.
        </p>
        <div className="cta-row">
          <button
            type="button"
            className="run-btn"
            onClick={startLoop}
            disabled={ui.running}
          >
            {ui.running ? 'Looping…' : eventLog.length ? 'Run loop again' : 'Run loop'}
          </button>
          <p className="status-line" aria-live="polite">
            {ui.statusLine}
          </p>
        </div>
        <p className="weave-line">{ui.weaveLine}</p>
      </header>

      <main className="stage">
        <section id="redBox" className={`agent-box red${ui.activeRole === 'red' ? ' active' : ''}`} aria-label="Red verify agent">
          <div className="agent-label">Red</div>
          <h2>Verify</h2>
          <p className="agent-job">
            Calls <code>format_custom_rcpt</code> and records each response.
          </p>
          <p className="agent-detail">{ui.redDetail}</p>
        </section>

        <div className={`loop-rail${ui.flow ? ` ${ui.flow}` : ''}`} aria-hidden="true">
          <div className="loop-pulse"></div>
          <svg className="loop-arrows" viewBox="0 0 120 200" preserveAspectRatio="none">
            <path id="arrowDown" className="arrow-path" d="M60 28 C60 70 60 90 60 120" />
            <path id="arrowUp" className="arrow-path" d="M60 172 C60 130 60 110 60 80" />
          </svg>
          <div className="iter-badge">{ui.iterBadge}</div>
        </div>

        <section id="blueBox" className={`agent-box blue${ui.activeRole === 'blue' ? ' active' : ''}`} aria-label="Blue fix agent">
          <div className="agent-label">Blue</div>
          <h2>Fix</h2>
          <p className="agent-job">
            LLM proposes a CR/LF reject patch (Weave-traced). Falls back if no key.
          </p>
          <p className="agent-detail">{ui.blueDetail}</p>
        </section>
      </main>

      <section className="wire-panel" aria-label="Live request response wire">
        <div className="wire-head">
          <h3>Live wire</h3>
          <p className="wire-meta">{ui.wireMeta}</p>
        </div>
        <div className="wire-grid">
          <div className="wire-col">
            <div className="wire-col-label request">Request</div>
            <pre className="wire-pane">{ui.reqPane}</pre>
          </div>
          <div className="wire-col">
            <div className="wire-col-label response">Response</div>
            <pre className={`wire-pane${ui.resClass ? ` ${ui.resClass}` : ''}`}>{ui.resPane}</pre>
          </div>
        </div>
      </section>

      <section className="matrix-panel" aria-label="Iteration results matrix">
        <div className="wire-head">
          <h3>Iteration matrix</h3>
          <p className="wire-meta">
            Rows = request · Columns = iteration · Cells = pass/fail · tiers escalate only after pass
          </p>
        </div>
        <div className="matrix-scroll">
          <table className="iter-matrix">
            <thead>
              <tr>
                <th scope="col">Sent</th>
                {m.iters.map((iter) => (
                  <th scope="col" key={iter}>
                    Iter {iter}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {m.rows.length === 0 ? (
                <tr className="matrix-empty">
                  <td colSpan={Math.max(1, m.iters.length + 1)}>Waiting for probes…</td>
                </tr>
              ) : (
                m.rows.map((row) => (
                  <tr key={row.key}>
                    <td className="matrix-sent">
                      <div className="matrix-sent-label">{row.label}</div>
                      <code>{row.call}</code>
                    </td>
                    {m.iters.map((iter) => {
                      const cell = m.cells[row.key]?.[iter]
                      const isLive = m.activeCell?.key === row.key && m.activeCell?.iter === iter
                      const classes = ['matrix-cell']
                      if (cell) classes.push(cell.pass ? 'pass' : 'fail')
                      if (isLive) classes.push('live')
                      return (
                        <td
                          key={iter}
                          className={classes.join(' ')}
                          title={cell ? (cell.pass ? `expected outcome · ${cell.status}` : `unexpected · ${cell.status}`) : undefined}
                        >
                          {cell ? cellLabel(cell.status) : '—'}
                        </td>
                      )
                    })}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="code-panel" aria-label="Subject and patch">
        <div className="code-grid">
          <div>
            <div className="wire-col-label">Subject under test</div>
            <pre className="wire-pane code">{ui.subjectPane}</pre>
          </div>
          <div>
            <div className="wire-col-label">Blue patch diff</div>
            <pre className="wire-pane code">{ui.diffPane}</pre>
          </div>
        </div>
      </section>

      {ui.greenVisible && (
        <section className="green-banner">
          <div className="green-inner">
            <p className="green-kicker">Exit condition</p>
            <h2>GREEN — Fixed</h2>
            <p>{ui.greenDetail}</p>
          </div>
        </section>
      )}

      <section className="log-panel">
        <h3>Loop trace</h3>
        <ol className="event-log">
          {eventLog.map((entry) => (
            <li key={entry.id}>
              <span className={`role ${entry.role}`}>{entry.role}</span>
              <span>{entry.text}</span>
            </li>
          ))}
        </ol>
      </section>
    </div>
  )
}

export default SecWeave
