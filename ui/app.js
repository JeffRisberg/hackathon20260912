const runBtn = document.getElementById("runBtn");
const statusLine = document.getElementById("statusLine");
const redBox = document.getElementById("redBox");
const blueBox = document.getElementById("blueBox");
const redDetail = document.getElementById("redDetail");
const blueDetail = document.getElementById("blueDetail");
const loopRail = document.querySelector(".loop-rail");
const iterBadge = document.getElementById("iterBadge");
const greenBanner = document.getElementById("greenBanner");
const greenDetail = document.getElementById("greenDetail");
const eventLog = document.getElementById("eventLog");
const reqPane = document.getElementById("reqPane");
const resPane = document.getElementById("resPane");
const wireMeta = document.getElementById("wireMeta");
const subjectPane = document.getElementById("subjectPane");
const diffPane = document.getElementById("diffPane");
const iterMatrix = document.getElementById("iterMatrix");

const weaveLine = document.getElementById("weaveLine");

let source = null;
let probeCount = 0;

/** @type {{ key: string, label: string, call: string }[]} */
let matrixRows = [];
/** @type {number[]} */
let matrixIters = [];
/** @type {Record<string, Record<number, { status: string, pass: boolean }>>} */
let matrixCells = {};
let activeCell = null;

function setActive(role) {
  redBox.classList.toggle("active", role === "red");
  blueBox.classList.toggle("active", role === "blue");
  loopRail.classList.remove("flow-down", "flow-up");
  if (role === "red") loopRail.classList.add("flow-up");
  if (role === "blue") loopRail.classList.add("flow-down");
}

function clearActive() {
  redBox.classList.remove("active");
  blueBox.classList.remove("active");
  loopRail.classList.remove("flow-down", "flow-up");
}

function appendLog(role, text) {
  const li = document.createElement("li");
  const roleEl = document.createElement("span");
  roleEl.className = `role ${role}`;
  roleEl.textContent = role;
  const msg = document.createElement("span");
  msg.textContent = text;
  li.append(roleEl, msg);
  eventLog.prepend(li);
}

function summarize(event) {
  const p = event.payload || {};
  switch (event.type) {
    case "weave_status":
      return `Weave project ${p.project} · llm=${p.llm_enabled ? p.model : "fallback"}`;
    case "reset":
      return "Subject restored to vulnerable baseline";
    case "loop_start":
      return `Goal: ${p.goal}`;
    case "iteration":
      return `Iteration ${p.n} · ${p.tier_name || p.tier_id || "tier"} (${p.tier_level || "?"})`;
    case "tier_escalate":
      return `Escalate ${p.from_tier?.id} → ${p.to_tier?.id} (complex unlocked)`;
    case "agent_active":
      return event.role === "red"
        ? `Red verifying ${p.tier?.name || ""} (iteration ${p.iteration})`
        : `Blue fixing ${p.tier?.name || ""} (iteration ${p.iteration})`;
    case "probe": {
      const status = p.response?.status || "?";
      return `iter ${p.iteration} · ${p.label}: ${status}`;
    }
    case "verify_result":
      if (p.fixed) return `Iter ${p.iteration}: all tiers green`;
      if (p.tier_passed) return `Iter ${p.iteration}: ${p.tier?.id} passed — escalate`;
      return `Iter ${p.iteration}: ${p.tier?.id} failed — fix before complex`;
    case "fix_applied":
      return p.changed
        ? `Applied: ${p.summary}`
        : "Fix already present";
    case "handoff":
      return `Handoff ${p.from} → ${p.to}`;
    case "fixed":
      return p.message || "Fixed";
    case "done":
      return p.fixed
        ? `Done in ${p.iterations} iteration(s)`
        : "Done without green";
    case "error":
      return p.error || "Error";
    default:
      return event.type;
  }
}

function formatRequest(probe) {
  const r = probe.request;
  return [
    `fn:      ${r.fn}`,
    `custom:  ${JSON.stringify(r.custom)}`,
    `rcpt:    ${r.rcpt.repr}`,
    `escaped: ${r.rcpt.escaped}`,
    `hex:     ${r.rcpt.hex}`,
    ``,
    `>>> ${r.call}`,
  ].join("\n");
}

function formatResponse(probe) {
  const r = probe.response;
  const lines = [
    `status:   ${r.status}`,
    `rejected: ${r.rejected}`,
    `elapsed:  ${probe.elapsed_ms} ms`,
    `pass:     ${probe.pass}`,
  ];
  if (r.smtp_line != null) {
    lines.push(``, `smtp_line:`, `  ${JSON.stringify(r.smtp_line)}`);
  }
  if (r.error) {
    lines.push(``, `error:`, `  ${r.error.type}: ${r.error.message}`);
  }
  return lines.join("\n");
}

function cellLabel(status) {
  if (status === "rejected") return "rejected";
  if (status === "accepted") return "accepted";
  return status || "—";
}

function renderMatrix() {
  const thead = iterMatrix.querySelector("thead");
  const tbody = iterMatrix.querySelector("tbody");
  thead.innerHTML = "";
  tbody.innerHTML = "";

  const headRow = document.createElement("tr");
  const sentTh = document.createElement("th");
  sentTh.scope = "col";
  sentTh.textContent = "Sent";
  headRow.append(sentTh);
  for (const iter of matrixIters) {
    const th = document.createElement("th");
    th.scope = "col";
    th.textContent = `Iter ${iter}`;
    headRow.append(th);
  }
  thead.append(headRow);

  if (!matrixRows.length) {
    const empty = document.createElement("tr");
    empty.className = "matrix-empty";
    const td = document.createElement("td");
    td.colSpan = Math.max(1, matrixIters.length + 1);
    td.textContent = "Waiting for probes…";
    empty.append(td);
    tbody.append(empty);
    return;
  }

  for (const row of matrixRows) {
    const tr = document.createElement("tr");
    const sentTd = document.createElement("td");
    sentTd.className = "matrix-sent";
    const label = document.createElement("div");
    label.className = "matrix-sent-label";
    label.textContent = row.label;
    const call = document.createElement("code");
    call.textContent = row.call;
    sentTd.append(label, call);
    tr.append(sentTd);

    for (const iter of matrixIters) {
      const td = document.createElement("td");
      const cell = matrixCells[row.key]?.[iter];
      const status = cell?.status;
      td.className = "matrix-cell";
      if (cell) {
        td.classList.add(cell.pass ? "pass" : "fail");
      }
      if (
        activeCell &&
        activeCell.key === row.key &&
        activeCell.iter === iter
      ) {
        td.classList.add("live");
      }
      td.textContent = cell ? cellLabel(status) : "—";
      if (cell) {
        td.title = cell.pass
          ? `expected outcome · ${status}`
          : `unexpected · ${status}`;
      }
      tr.append(td);
    }
    tbody.append(tr);
  }
}

function recordProbeInMatrix(probe) {
  const key = probe.label;
  const iter = probe.iteration;
  if (!matrixRows.some((r) => r.key === key)) {
    matrixRows.push({
      key,
      label: probe.label,
      call: probe.request.call,
    });
  }
  if (!matrixIters.includes(iter)) {
    matrixIters.push(iter);
    matrixIters.sort((a, b) => a - b);
  }
  if (!matrixCells[key]) matrixCells[key] = {};
  matrixCells[key][iter] = {
    status: probe.response.rejected
      ? "rejected"
      : probe.response.status || "accepted",
    pass: !!probe.pass,
  };
  activeCell = { key, iter };
  renderMatrix();
}

function renderProbe(probe) {
  probeCount += 1;
  reqPane.textContent = formatRequest(probe);
  resPane.textContent = formatResponse(probe);
  resPane.classList.toggle("is-reject", probe.pass === false);
  resPane.classList.toggle("is-accept", probe.pass === true);
  wireMeta.textContent = `Probe ${probeCount} · ${probe.label} · iter ${probe.iteration}`;
  recordProbeInMatrix(probe);

  redDetail.textContent = probe.response.rejected
    ? `Rejected: ${probe.response.error.message}`
    : `Accepted line: ${probe.response.smtp_line}`;
}

function onEvent(event) {
  const role = event.role || "system";
  appendLog(role, summarize(event));

  if (event.type === "weave_status") {
    const p = event.payload || {};
    const llm = p.llm_enabled
      ? `LLM ${p.model}`
      : "deterministic fallback";
    weaveLine.textContent = `Weave: ${p.project} · ${llm}${
      p.initialized ? "" : " · weave init pending/failed"
    }`;
  }

  if (event.type === "iteration") {
    const p = event.payload;
    iterBadge.textContent = `ITER ${p.n}`;
    statusLine.textContent = `Iteration ${p.n}: ${p.tier_name} (${p.tier_level})`;
  }

  if (event.type === "tier_escalate") {
    const p = event.payload;
    statusLine.textContent = `Tier passed → unlock ${p.to_tier?.name || "next"}`;
  }

  if (event.type === "reset" && event.payload?.preview) {
    subjectPane.textContent = event.payload.preview;
  }

  if (event.type === "agent_active") {
    setActive(event.role);
    statusLine.textContent =
      event.role === "red"
        ? "Red issuing live format_custom_rcpt calls…"
        : "Blue writing patch to subject file…";
    if (event.role === "red") {
      redDetail.textContent = "Calling subject…";
      reqPane.textContent = "awaiting call…";
      resPane.textContent = "—";
      resPane.classList.remove("is-reject", "is-accept");
    } else {
      blueDetail.textContent = "Diffing and writing smtp_rcpt.py…";
    }
  }

  if (event.type === "probe") {
    setActive("red");
    renderProbe(event.payload);
  }

  if (event.type === "verify_result") {
    const p = event.payload;
    if (p.fixed) {
      redDetail.textContent = `All tiers passed (${p.tier?.name})`;
    } else if (p.tier_passed) {
      redDetail.textContent = `${p.tier?.name} passed — escalating`;
    } else {
      redDetail.textContent = `${p.tier?.name} failed — send to Blue`;
    }
    if (p.subject_preview) {
      subjectPane.textContent = p.subject_preview;
    }
    wireMeta.textContent = p.reason || wireMeta.textContent;
  }

  if (event.type === "fix_applied") {
    const p = event.payload;
    const mode = p.mode || "unknown";
    const model = p.llm?.model;
    blueDetail.textContent = model
      ? `${p.summary} · ${mode} · ${model}`
      : `${p.summary} · ${mode}`;
    if (p.after_preview) subjectPane.textContent = p.after_preview;
    const header =
      `# mode=${mode} model=${model || "n/a"}\n` +
      `# fallback=${p.llm?.fallback || "none"}\n` +
      `# weave=${p.weave_project || "secweave"}\n\n`;
    diffPane.textContent = header + (p.diff || "(no diff — already patched)");
  }

  if (event.type === "fixed" || (event.type === "done" && event.payload?.fixed)) {
    clearActive();
    activeCell = null;
    renderMatrix();
    document.body.classList.add("is-fixed");
    greenBanner.hidden = false;
    greenDetail.textContent =
      event.payload?.message ||
      `Hardening check passed after ${event.payload?.iterations ?? "?"} iteration(s). Loop exited.`;
    statusLine.textContent = "GREEN — fixed. Loop exited.";
  }

  if (event.type === "done") {
    clearActive();
    runBtn.disabled = false;
    runBtn.textContent = "Run loop again";
    if (!event.payload?.fixed) {
      statusLine.textContent = "Loop finished without green";
    }
  }

  if (event.type === "error") {
    clearActive();
    runBtn.disabled = false;
    statusLine.textContent = "Loop error — see trace";
  }
}

function resetUi() {
  document.body.classList.remove("is-fixed");
  greenBanner.hidden = true;
  eventLog.innerHTML = "";
  probeCount = 0;
  matrixRows = [];
  matrixIters = [];
  matrixCells = {};
  activeCell = null;
  renderMatrix();
  redDetail.textContent = "Waiting";
  blueDetail.textContent = "Waiting";
  iterBadge.textContent = "—";
  reqPane.textContent = "—";
  resPane.textContent = "—";
  resPane.classList.remove("is-reject", "is-accept");
  wireMeta.textContent = "No calls yet";
  subjectPane.textContent = "—";
  diffPane.textContent = "—";
  clearActive();
}

function startLoop() {
  if (source) {
    source.close();
    source = null;
  }
  resetUi();
  runBtn.disabled = true;
  runBtn.textContent = "Looping…";
  statusLine.textContent = "Connecting to loop stream…";
  weaveLine.textContent = "Weave: secweave · connecting…";

  source = new EventSource("/api/loop/stream");

  source.onmessage = (msg) => {
    let event;
    try {
      event = JSON.parse(msg.data);
    } catch {
      return;
    }
    onEvent(event);
    if (event.type === "done" || event.type === "error") {
      source.close();
      source = null;
    }
  };

  source.onerror = () => {
    statusLine.textContent = "Stream closed or failed";
    runBtn.disabled = false;
    runBtn.textContent = "Run loop";
    if (source) {
      source.close();
      source = null;
    }
  };
}

runBtn.addEventListener("click", startLoop);
