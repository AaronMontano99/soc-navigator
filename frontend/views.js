import { api } from "./api.js";
import {
  escapeHtml,
  severityLabel,
  statusLabel,
  techniqueChips,
  confidenceBar,
  relativeTime,
  formatTime,
  copyToClipboard,
  loadingState,
  emptyState,
  errorState,
} from "./helpers.js";

// Short, honest descriptions of what each scenario's synthetic telemetry
// actually contains — mirrors the real event sequence in
// app/data/telemetry/<id>.json, not invented marketing copy.
const SCENARIO_META = {
  "account-compromise": { tags: "IDENTITY · ENDPOINT · NETWORK", steps: ["Unusual Login", "Encoded PowerShell", "Credential Access", "SMB Pivot"], color: "var(--high)" },
  ransomware: { tags: "EMAIL · ENDPOINT · IDENTITY", steps: ["Phishing", "PowerShell", "Credential Access", "Lateral Movement", "Encryption"], color: "var(--critical)" },
  "credential-stuffing": { tags: "IDENTITY", steps: ["400+ Failed Attempts", "Successful Login", "Privileged Activity"], color: "var(--high)" },
  "insider-threat": { tags: "IDENTITY · CLOUD", steps: ["Off-hours Access", "Mass Download", "Personal Cloud Upload"], color: "var(--low)" },
  "false-positive": { tags: "IT ADMINISTRATION", steps: ["Encoded PowerShell", "Known Script", "Approved Maintenance Window"], color: "var(--good)" },
};

const ARCHITECTURE_MODULES = [
  { title: "SYNTHETIC TELEMETRY", path: "app/data/telemetry/*.json", desc: "Fabricated identity, endpoint, email, and cloud events — no real customer or production data anywhere in this repo." },
  { title: "DETECTION ENGINE", path: "app/detection/sigma_engine.py", desc: "A practical subset of the Sigma rule spec: selections, string/numeric modifiers, and/or/and-not conditions matched against events." },
  { title: "CONFIDENCE SCORING", path: "detections/sigma/*.yml", desc: "Each rule declares base confidence plus named factors that raise or lower it based on real event context — never a black box." },
  { title: "CORRELATION ENGINE", path: "app/correlation/correlator.py", desc: "Clusters related alerts (shared user/host, time window) into one incident instead of N disconnected alerts." },
  { title: "INCIDENT", path: "app/models.py", desc: "The unit everything downstream operates on: risk level, status, and confidence, all derived — never asserted." },
  { title: "MITRE ATT&CK MAPPING", path: "app/mapping/attack.py", desc: "Local, offline lookup of technique names and tactics for every technique this project actually detects." },
  { title: "NIST CSF 2.0 MAPPING", path: "app/mapping/nist_csf.py", desc: "Generates a Govern/Identify/Protect/Detect/Respond/Recover checklist from the incident's own data." },
  { title: "AI INVESTIGATION ASSISTANT", path: "app/ai/assistant.py", desc: "Explains, prioritizes, and suggests next steps — grounded in the already-computed incident. It does not decide the verdict." },
  { title: "ANALYST / SECURITY LEADER", path: "frontend/", desc: "Two views of the same incident: full technical detail for an analyst, plain-language business risk for a leader." },
];

function panel(title, bodyHtml, extraClass) {
  return `<section class="panel ${extraClass || ""}"><h3>${escapeHtml(title)}</h3>${bodyHtml}</section>`;
}

function statTile(label, value, cls) {
  return `<div class="stat-tile ${cls || ""}"><div class="stat-label">${escapeHtml(label)}</div><div class="stat-value">${value}</div></div>`;
}

function miniBars(values) {
  const max = Math.max(1, ...values);
  return `<div class="mini-bars">${values
    .map((v) => `<div class="mini-bar" style="height:${Math.max(4, (v / max) * 100)}%"></div>`)
    .join("")}</div>`;
}

// ---------- Overview ----------

async function runScanFromOverview(container, ctx) {
  const btn = container.querySelector("#overview-scan-btn");
  if (btn) {
    btn.textContent = "SCANNING…";
    btn.disabled = true;
  }
  try {
    await api.liveScan();
  } catch (e) {
    // fall through — renderOverview will just show whatever state resulted
  }
  renderOverview(container, ctx);
}

export async function renderOverview(container, ctx) {
  container.innerHTML = loadingState();
  let data;
  try {
    data = await api.dashboard();
  } catch (e) {
    container.innerHTML = errorState();
    return;
  }

  if (!data.has_scanned) {
    container.innerHTML = `
      <div class="content-header">
        <div>
          <h2>Security Operations</h2>
          <p class="content-subtitle">Your network's real security posture — no scan has been run yet this session.</p>
        </div>
      </div>
      <section class="panel">
        <div class="empty-state">
          <div class="state-title">NO SCAN YET</div>
          <div class="state-subtitle">Run a scan to discover devices on your network and check for exposed services.</div>
          <button class="btn-run" id="overview-scan-btn" style="margin-top:14px;">SCAN MY NETWORK</button>
        </div>
      </section>
    `;
    container.querySelector("#overview-scan-btn").addEventListener("click", () => runScanFromOverview(container, ctx));
    return;
  }

  const deviceBars = data.device_breakdown.map((d) => d.alert_count);

  const rows = data.active_incidents.length
    ? data.active_incidents
        .map(
          (i) => `
      <tr class="clickable-row" data-incident="${i.id}">
        <td>${severityLabel(i.risk_level)}</td>
        <td class="col-title">${escapeHtml(i.title)}</td>
        <td>${i.confidence}%${confidenceBar(i.confidence)}</td>
        <td>${i.alert_count}</td>
        <td>${techniqueChips(i.attack_techniques.map((id) => ({ id })), 3)}</td>
        <td>${statusLabel(i.status)}</td>
        <td class="col-age">${relativeTime(i.generated_at)}</td>
      </tr>`
        )
        .join("")
    : `<tr><td colspan="7">${emptyState("NO ACTIVE INCIDENTS", "Nothing on your network needs attention right now.")}</td></tr>`;

  const biggest = data.active_incidents.reduce((max, i) => Math.max(max, i.alert_count), 0);

  container.innerHTML = `
    <div class="content-header">
      <div>
        <h2>Security Operations</h2>
        <p class="content-subtitle">${escapeHtml(data.subnet)} &middot; last scanned ${relativeTime(data.scanned_at)} ago &middot; ${data.devices_scanned} device(s) found</p>
      </div>
      <button class="btn-run" id="overview-scan-btn">RESCAN</button>
    </div>

    <div class="stat-grid stat-grid-4">
      ${statTile("Devices Scanned", data.devices_scanned)}
      ${statTile("Findings", data.alerts_generated)}
      ${statTile("Incidents", data.incidents_total)}
      ${statTile("Critical", data.risk_counts.critical, "critical")}
    </div>

    ${panel(
      "Signal Funnel — From Noise to Investigation",
      `<div class="funnel">
        <div class="funnel-stage"><div class="funnel-value">${data.devices_scanned}</div><div class="funnel-label">Devices</div></div>
        <div class="funnel-arrow">&rarr;</div>
        <div class="funnel-stage"><div class="funnel-value accent-high">${data.alerts_generated}</div><div class="funnel-label">Findings</div>${miniBars(deviceBars)}</div>
        <div class="funnel-arrow">&rarr;</div>
        <div class="funnel-stage"><div class="funnel-value">${data.signals}</div><div class="funnel-label">Signals</div><div class="funnel-sub">confidence above threshold</div></div>
        <div class="funnel-arrow">&rarr;</div>
        <div class="funnel-stage"><div class="funnel-value">${data.incidents_total}</div><div class="funnel-label">Incidents</div><div class="funnel-sub">correlated</div></div>
        <div class="funnel-arrow">&rarr;</div>
        <div class="funnel-stage funnel-critical"><div class="funnel-value critical">${data.risk_counts.critical}</div><div class="funnel-label critical">Critical</div><div class="funnel-sub">needs review</div></div>
      </div>`
    )}

    <div class="two-col">
      ${panel(
        "Active Incidents",
        `<table class="data-table"><thead><tr><th>Severity</th><th>Incident</th><th>Confidence</th><th>Signals</th><th>ATT&amp;CK</th><th>Status</th><th>Age</th></tr></thead><tbody>${rows}</tbody></table>`
      )}
      ${panel(
        "Why Correlation Matters",
        `<p>${biggest} separate finding(s) may belong to one device.</p>
         <p class="dim">soc-navigator groups related activity around shared identities, endpoints, and time windows so an analyst investigates one coherent incident rather than disconnected alerts.</p>
         <div class="tag-row"><span class="tag">shared identity</span><span class="tag">shared host</span><span class="tag">time window</span></div>`
      )}
    </div>
  `;
  container.querySelector("#overview-scan-btn").addEventListener("click", () => runScanFromOverview(container, ctx));

  container.querySelectorAll("[data-incident]").forEach((row) => {
    row.addEventListener("click", () => ctx.navigate("incident", { id: row.dataset.incident }));
  });
}

// ---------- Incidents ----------

export async function renderIncidents(container, ctx) {
  container.innerHTML = loadingState();
  let incidents;
  try {
    incidents = await api.incidents();
  } catch (e) {
    container.innerHTML = errorState();
    return;
  }

  const state = { severity: "", status: "", search: "" };

  function draw() {
    const filtered = incidents.filter((i) => {
      if (state.severity && i.risk_level !== state.severity) return false;
      if (state.status && i.status !== state.status) return false;
      if (state.search && !i.title.toLowerCase().includes(state.search.toLowerCase())) return false;
      return true;
    });
    const rows = filtered.length
      ? filtered
          .map(
            (i) => `
        <tr class="clickable-row" data-incident="${i.id}">
          <td>${severityLabel(i.risk_level)}</td>
          <td class="col-title">
            <div class="row-title">${escapeHtml(i.title)}</div>
            <div class="row-meta">${escapeHtml(i.id)} · ${escapeHtml(i.users.join(", ") || "—")} · ${escapeHtml(i.hosts.join(", ") || "—")}</div>
          </td>
          <td>${i.alert_count}</td>
          <td>${i.confidence}%${confidenceBar(i.confidence)}</td>
          <td>${techniqueChips(i.attack_techniques.map((id) => ({ id })), 3)}</td>
          <td>${statusLabel(i.status)}</td>
          <td class="col-age">${relativeTime(i.generated_at)}</td>
        </tr>`
          )
          .join("")
      : `<tr><td colspan="7">${emptyState(
          incidents.length === 0 ? "NO SCAN YET" : "NO MATCHING INCIDENTS",
          incidents.length === 0 ? "Run a scan from My Network to populate this view." : undefined
        )}</td></tr>`;
    container.querySelector("#incidents-table-body").innerHTML = rows;
    container.querySelectorAll("[data-incident]").forEach((row) => {
      row.addEventListener("click", () => ctx.navigate("incident", { id: row.dataset.incident }));
    });
  }

  const totalAlerts = incidents.reduce((s, i) => s + i.alert_count, 0);

  container.innerHTML = `
    <div class="content-header">
      <div>
        <h2>Incidents</h2>
        <p class="content-subtitle">${incidents.length} correlated incident(s) from your network · ${totalAlerts} constituent alert(s)</p>
      </div>
      <div class="toolbar">
        <input type="text" id="incidents-search" placeholder="Search incidents…" />
        <select id="incidents-severity"><option value="">SEVERITY</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
        <select id="incidents-status"><option value="">STATUS</option><option value="confirmed_suspicious">Confirmed Suspicious</option><option value="needs_investigation">Needs Investigation</option><option value="likely_benign">Likely Benign</option></select>
      </div>
    </div>
    <section class="panel">
      <table class="data-table"><thead><tr><th>Severity</th><th>Incident</th><th>Signals</th><th>Confidence</th><th>ATT&amp;CK Techniques</th><th>Status</th><th>Time</th></tr></thead><tbody id="incidents-table-body"></tbody></table>
    </section>
    <p class="footnote">&#9632; Rows are grouped by correlation cluster, not by alert.</p>
  `;

  container.querySelector("#incidents-search").addEventListener("input", (e) => {
    state.search = e.target.value;
    draw();
  });
  container.querySelector("#incidents-severity").addEventListener("change", (e) => {
    state.severity = e.target.value;
    draw();
  });
  container.querySelector("#incidents-status").addEventListener("change", (e) => {
    state.status = e.target.value;
    draw();
  });
  draw();
}

// ---------- Alerts ----------

export async function renderAlerts(container, ctx) {
  container.innerHTML = loadingState();
  let data;
  try {
    data = await api.alerts();
  } catch (e) {
    container.innerHTML = errorState();
    return;
  }

  const state = { severity: "", search: "" };

  function draw() {
    const filtered = data.alerts.filter((a) => {
      if (state.severity && a.severity !== state.severity) return false;
      if (state.search && !a.rule_title.toLowerCase().includes(state.search.toLowerCase())) return false;
      return true;
    });
    const rows = filtered.length
      ? filtered
          .slice(0, 200)
          .map(
            (a) => `
        <tr>
          <td class="mono">${formatTime(a.timestamp)}</td>
          <td>${severityLabel(a.severity)}</td>
          <td>${escapeHtml(a.rule_title)}</td>
          <td class="mono">${escapeHtml(a.user || "—")}</td>
          <td class="mono">${escapeHtml(a.host || "—")}</td>
          <td>${techniqueChips(a.attack_techniques, 1)}</td>
          <td><a class="incident-link" data-incident="${a.incident_id}">${escapeHtml(a.incident_id)}</a></td>
        </tr>`
          )
          .join("")
      : `<tr><td colspan="7">${emptyState(
          data.alerts.length === 0 ? "NO SCAN YET" : "NO MATCHING ALERTS",
          data.alerts.length === 0 ? "Run a scan from My Network to populate this view." : undefined
        )}</td></tr>`;
    container.querySelector("#alerts-table-body").innerHTML = rows;
    container.querySelectorAll("[data-incident]").forEach((link) => {
      link.addEventListener("click", () => ctx.navigate("incident", { id: link.dataset.incident }));
    });
  }

  container.innerHTML = `
    <div class="content-header">
      <div>
        <h2>Alerts</h2>
        <p class="content-subtitle">Every finding from your network, before correlation. Most of this is noise.</p>
      </div>
      <div class="toolbar">
        <input type="text" id="alerts-search" placeholder="Search alerts…" />
        <select id="alerts-severity"><option value="">SEVERITY</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
      </div>
    </div>
    <section class="panel">
      <div class="funnel funnel-compact">
        <div class="funnel-stage"><div class="funnel-value accent-high">${data.total_alerts}</div><div class="funnel-label">Alerts</div></div>
        <div class="funnel-arrow">&rarr;</div>
        <div class="funnel-stage"><div class="funnel-value">${data.total_signals}</div><div class="funnel-label">Signals</div></div>
        <div class="funnel-arrow">&rarr;</div>
        <div class="funnel-stage"><div class="funnel-value">${data.total_incidents}</div><div class="funnel-label">Incidents</div></div>
      </div>
    </section>
    <section class="panel">
      <table class="data-table"><thead><tr><th>Time</th><th>Severity</th><th>Detection</th><th>User</th><th>Host</th><th>Technique</th><th>Incident</th></tr></thead><tbody id="alerts-table-body"></tbody></table>
    </section>
    ${data.never_escalated > 0 ? `<p class="footnote">+${data.never_escalated} alert(s) belong to incidents reviewed as benign and were never escalated.</p>` : ""}
  `;

  container.querySelector("#alerts-search").addEventListener("input", (e) => {
    state.search = e.target.value;
    draw();
  });
  container.querySelector("#alerts-severity").addEventListener("change", (e) => {
    state.severity = e.target.value;
    draw();
  });
  draw();
}

// ---------- Rules ----------

export async function renderRules(container, ctx) {
  container.innerHTML = loadingState();
  let rules;
  try {
    rules = await api.detections();
  } catch (e) {
    container.innerHTML = errorState();
    return;
  }

  container.innerHTML = `
    <div class="content-header">
      <div>
        <h2>Detection Rules</h2>
        <p class="content-subtitle">Sigma-subset rules, matched against every event in the pipeline.</p>
      </div>
      <span class="pill pill-status"><span class="dot dot-good"></span>${rules.length} ACTIVE RULES</span>
    </div>
    <section class="panel">
      <table class="data-table"><thead><tr><th>Rule</th><th>Severity</th><th>Technique</th><th>Tactic</th><th>Status</th></tr></thead>
      <tbody>
        ${rules
          .map(
            (r) => `
          <tr class="clickable-row" data-rule="${r.id}">
            <td><div class="row-title">${escapeHtml(r.title)}</div><div class="row-meta mono">${escapeHtml(r.filename)}</div></td>
            <td>${severityLabel(r.severity)}</td>
            <td class="mono">${r.techniques.map((t) => escapeHtml(t.id)).join(", ")}</td>
            <td>${escapeHtml(r.tactics.join(", "))}</td>
            <td><span class="status-active"><span class="dot dot-good"></span>ACTIVE</span></td>
          </tr>
          <tr class="rule-detail-row" id="rule-detail-${r.id}" hidden><td colspan="5"></td></tr>`
          )
          .join("")}
      </tbody></table>
    </section>
  `;

  container.querySelectorAll("[data-rule]").forEach((row) => {
    row.addEventListener("click", async () => {
      const id = row.dataset.rule;
      const detailRow = container.querySelector(`#rule-detail-${id}`);
      const wasOpen = !detailRow.hidden;
      container.querySelectorAll(".rule-detail-row").forEach((r) => (r.hidden = true));
      if (wasOpen) return;
      detailRow.hidden = false;
      const cell = detailRow.querySelector("td");
      cell.innerHTML = loadingState();
      try {
        const rule = await api.detection(id);
        cell.innerHTML = renderRuleDetail(rule);
        cell.querySelector(".copy-btn")?.addEventListener("click", (e) => copyToClipboard(rule.raw_yaml, e.target));
      } catch (e) {
        cell.innerHTML = errorState();
      }
    });
  });

  if (ctx.pendingRuleId) {
    const row = container.querySelector(`[data-rule="${ctx.pendingRuleId}"]`);
    row?.click();
    row?.scrollIntoView({ block: "center" });
  }
}

function renderRuleDetail(rule) {
  const conditions = rule.selections
    .map(
      (s) =>
        `<div class="condition-row"><span class="mono">${escapeHtml(JSON.stringify(s.criteria))}</span><span class="check">&check;</span></div>`
    )
    .join("");
  const fps = rule.falsepositives.map((f) => `<li>${escapeHtml(f)}</li>`).join("");
  return `
    <div class="two-col">
      <div>
        <div class="detail-label">MATCHED CONDITIONS <span class="mono dim">(${escapeHtml(rule.condition)})</span></div>
        ${conditions}
        <div class="detail-label">PURPOSE</div>
        <p>${escapeHtml(rule.description)}</p>
        ${fps ? `<div class="detail-label">FALSE-POSITIVE CONSIDERATIONS</div><ul>${fps}</ul>` : ""}
      </div>
      <div>
        <div class="detail-label">SIGMA RULE <span class="mono dim">detections/sigma/${escapeHtml(rule.filename)}</span> <button class="copy-btn small-btn">COPY YAML</button></div>
        <pre class="code-block">${escapeHtml(rule.raw_yaml)}</pre>
      </div>
    </div>
  `;
}

// ---------- Coverage ----------

export async function renderCoverage(container) {
  container.innerHTML = loadingState();
  let data;
  try {
    data = await api.coverage();
  } catch (e) {
    container.innerHTML = errorState();
    return;
  }

  container.innerHTML = `
    <div class="content-header">
      <div>
        <h2>Detection Coverage</h2>
        <p class="content-subtitle">What this project detects — and, deliberately, what it does not.</p>
      </div>
    </div>
    <div class="stat-grid stat-grid-3">
      ${statTile("Detection Rules", data.rule_count)}
      ${statTile("ATT&CK Techniques Represented", data.technique_count)}
      ${statTile("Attack Scenarios", data.scenario_count)}
    </div>
    <div class="two-col">
      ${panel(
        "Covered Techniques by Tactic",
        data.covered
          .map(
            (group) => `
        <div class="tactic-group">
          <div class="tactic-group-label">${escapeHtml(group.tactic)}</div>
          ${group.techniques
            .map(
              (t) =>
                `<div class="coverage-row"><span class="mono">${escapeHtml(t.id)}</span><span>${escapeHtml(t.name)}</span><span class="check">&check;</span></div>`
            )
            .join("")}
        </div>`
          )
          .join("")
      )}
      ${panel(
        "Not Covered",
        `${data.not_covered.map((t) => `<div class="not-covered-row">&#9632; ${escapeHtml(t)}</div>`).join("")}
        <p class="dim" style="margin-top:14px;">Coverage is intentionally limited to what the synthetic telemetry can honestly support. This is not a claim of comprehensive ATT&amp;CK coverage.</p>`
      )}
    </div>
  `;
}

// ---------- Attack Lab ----------

export async function renderAttackLab(container, ctx) {
  container.innerHTML = loadingState();
  let scenarios;
  try {
    scenarios = await api.scenarios();
  } catch (e) {
    container.innerHTML = errorState();
    return;
  }

  container.innerHTML = `
    <div class="content-header">
      <div>
        <h2>Attack Lab</h2>
        <p class="content-subtitle">Run a synthetic scenario through the full pipeline: telemetry &rarr; detection &rarr; correlation &rarr; incident.</p>
      </div>
      <button class="btn-secondary" id="reset-lab">RESET LAB</button>
    </div>
    <div id="sim-panel"></div>
    <div class="scenario-grid">
      ${scenarios
        .map(
          (s) => `
        <div class="scenario-card" data-scenario="${s.id}">
          <div class="scenario-card-header"><strong>${escapeHtml(s.name)}</strong><span class="scenario-dot" style="background:${(SCENARIO_META[s.id] || {}).color || "var(--low)"}"></span></div>
          <div class="scenario-tags">${escapeHtml((SCENARIO_META[s.id] || {}).tags || "")}</div>
          <ul class="scenario-steps">${((SCENARIO_META[s.id] || {}).steps || []).map((step) => `<li>&rarr; ${escapeHtml(step)}</li>`).join("")}</ul>
          <div class="scenario-card-footer">
            <span class="dim">${((SCENARIO_META[s.id] || {}).steps || []).length} techniques</span>
            <button class="btn-run" data-run="${s.id}">RUN SCENARIO</button>
          </div>
        </div>`
        )
        .join("")}
    </div>
  `;

  container.querySelectorAll("[data-run]").forEach((btn) => {
    btn.addEventListener("click", () => runScenario(container, ctx, btn.dataset.run, scenarios));
  });

  container.querySelector("#reset-lab").addEventListener("click", async () => {
    const btn = container.querySelector("#reset-lab");
    btn.textContent = "RESETTING…";
    btn.disabled = true;
    for (const s of scenarios) {
      await api.runScenario(s.id);
    }
    btn.textContent = "RESET LAB";
    btn.disabled = false;
  });
}

async function runScenario(container, ctx, scenarioId, scenarios) {
  const scenario = scenarios.find((s) => s.id === scenarioId);
  const steps = (SCENARIO_META[scenarioId] || {}).steps || [];
  const simPanel = container.querySelector("#sim-panel");

  simPanel.innerHTML = `
    <section class="panel sim-running">
      <div class="sim-header">
        <div><span class="dot dot-running"></span> SIMULATION RUNNING</div>
        <div class="sim-counters">
          <div><span class="dim">RAW EVENTS</span><strong id="sim-raw">0</strong></div>
          <div><span class="dim">ALERTS</span><strong id="sim-alerts" class="accent-high">0</strong></div>
          <div><span class="dim">INCIDENTS</span><strong id="sim-incidents" class="critical">0</strong></div>
        </div>
      </div>
      <h4>${escapeHtml(scenario.name)}</h4>
      <div id="sim-steps">
        ${steps.map((step, i) => `<div class="sim-step" id="sim-step-${i}"><span class="sim-step-marker"></span>${escapeHtml(step)}</div>`).join("")}
      </div>
      <div id="sim-actions"></div>
    </section>
  `;

  let result;
  try {
    result = await api.runScenario(scenarioId);
  } catch (e) {
    simPanel.innerHTML = errorState("Could not run the scenario — is the backend running?");
    return;
  }

  const totalAlerts = result.incidents.reduce((s, i) => s + i.alert_count, 0);

  for (let i = 0; i < steps.length; i++) {
    await sleep(220);
    const stepEl = container.querySelector(`#sim-step-${i}`);
    if (stepEl) stepEl.classList.add("done");
  }
  await animateCount(container.querySelector("#sim-raw"), result.raw_events);
  await animateCount(container.querySelector("#sim-alerts"), totalAlerts);
  await animateCount(container.querySelector("#sim-incidents"), result.incidents.length);

  const topIncident = [...result.incidents].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return order[a.risk_level] - order[b.risk_level];
  })[0];

  const header = simPanel.querySelector(".sim-header > div:first-child");
  header.innerHTML = `<span class="dot dot-good"></span> SIMULATION COMPLETE`;
  simPanel.querySelector("#sim-actions").innerHTML = topIncident
    ? `<button class="btn-run" id="sim-investigate">INVESTIGATE &rarr;</button>`
    : `<p class="dim">No incident was produced by this run.</p>`;
  if (topIncident) {
    simPanel.querySelector("#sim-investigate").addEventListener("click", () => {
      ctx.navigate("incident", { id: topIncident.id, from: "lab" });
    });
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function animateCount(el, target) {
  if (!el) return;
  const steps = 10;
  for (let i = 1; i <= steps; i++) {
    el.textContent = Math.round((target * i) / steps);
    await sleep(25);
  }
  el.textContent = target;
}

// ---------- Architecture ----------

export function renderArchitecture(container) {
  container.innerHTML = `
    <div class="content-header">
      <div>
        <h2>Architecture</h2>
        <p class="content-subtitle">How a raw event becomes an incident an analyst can act on and a leader can understand.</p>
      </div>
      <span class="dim">CLICK A MODULE TO EXPAND</span>
    </div>
    <div class="arch-list">
      ${ARCHITECTURE_MODULES.map(
        (m, i) => `
        <div class="arch-module">
          <button class="arch-module-header" data-arch="${i}">
            <span class="arch-index">0${i + 1}</span>
            <span class="arch-title">${escapeHtml(m.title)}</span>
            <span class="arch-path mono">${escapeHtml(m.path)}</span>
            <span class="arch-toggle">+</span>
          </button>
          <div class="arch-module-body" id="arch-body-${i}" hidden><p>${escapeHtml(m.desc)}</p></div>
        </div>`
      ).join("")}
    </div>
    <p class="footnote">&#9670; No API keys, no paid services. The pipeline runs fully offline.</p>
  `;

  container.querySelectorAll("[data-arch]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const body = container.querySelector(`#arch-body-${btn.dataset.arch}`);
      body.hidden = !body.hidden;
      btn.querySelector(".arch-toggle").textContent = body.hidden ? "+" : "−";
    });
  });
}

// ---------- About ----------

export function renderAbout(container) {
  const explores = [
    "Security telemetry",
    "Detection engineering concepts",
    "Sigma rules",
    "Alert correlation",
    "Contextual confidence",
    "MITRE ATT&CK",
    "NIST CSF 2.0",
    "AI-assisted investigations",
    "Technical-to-executive communication",
  ];
  const limits = [
    "Synthetic telemetry only",
    "Not a production SIEM",
    "Not an EDR",
    "Not an MDR service",
    "Not a SOAR platform",
    "Not intended for production monitoring",
    "AI does not adjudicate maliciousness",
    "Detection coverage is intentionally limited",
  ];
  container.innerHTML = `
    <div class="content-header"><div><h2>soc<span class="dim">_</span>navigator</h2><p class="content-subtitle">An open-source SOC investigation simulator.</p>
    <p class="dim">MIT licensed · Python 3.10+ · FastAPI · no build step · all telemetry synthetic</p></div></div>
    <div class="two-col">
      ${panel("Built to Explore", `<ul class="plain-list">${explores.map((e) => `<li>${escapeHtml(e)}</li>`).join("")}</ul>`)}
      ${panel("Limitations", `<ul class="plain-list dim">${limits.map((l) => `<li>&minus; ${escapeHtml(l)}</li>`).join("")}</ul>`)}
    </div>
    <a class="btn-run" href="https://github.com/AaronMontano99/soc-navigator" target="_blank" rel="noopener">VIEW SOURCE ON GITHUB &#8599;</a>
    <span class="dim" style="margin-left:12px;">github.com/AaronMontano99/soc-navigator</span>
  `;
}

export { SCENARIO_META };
