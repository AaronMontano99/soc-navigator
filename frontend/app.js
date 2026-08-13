const API = "/api";

const state = {
  view: "dashboard", // "dashboard" | "incident"
  incidentId: null,
  incidentTab: "analyst", // "analyst" | "ciso"
  chatHistory: {}, // incidentId -> [{role, text}]
};

const viewRoot = document.getElementById("view-root");
const scenarioBar = document.getElementById("scenario-bar");
const backLinkContainer = document.getElementById("back-link-container");

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

function riskBadge(level) {
  return `<span class="badge ${level}">${level}</span>`;
}

function techniqueChips(techniques) {
  return techniques
    .map((t) => `<span class="technique-chip">${escapeHtml(t.id)} — ${escapeHtml(t.name)}</span>`)
    .join(" ");
}

// ---------- Scenario bar ----------

async function loadScenarioBar() {
  const scenarios = await fetchJSON(`${API}/scenarios`);
  scenarioBar.innerHTML = scenarios
    .map(
      (s) => `<button class="scenario-btn" data-scenario="${s.id}" title="${escapeHtml(s.narrative)}">
        ▶ Run: ${escapeHtml(s.name)}
      </button>`
    )
    .join("");

  scenarioBar.querySelectorAll(".scenario-btn").forEach((btn) => {
    const label = btn.textContent;
    btn.addEventListener("click", async () => {
      btn.classList.add("active");
      btn.textContent = "Running…";
      await fetchJSON(`${API}/scenarios/${btn.dataset.scenario}/run`, { method: "POST" });
      btn.textContent = label;
      btn.classList.remove("active");
      await goDashboard();
    });
  });
}

// ---------- Dashboard ----------

async function goDashboard() {
  state.view = "dashboard";
  state.incidentId = null;
  backLinkContainer.innerHTML = "";
  viewRoot.innerHTML = `<div class="empty-state">Loading dashboard…</div>`;
  const data = await fetchJSON(`${API}/dashboard`);
  renderDashboard(data);
}

function renderDashboard(data) {
  const rc = data.risk_counts;
  const tiles = [
    { label: "Alerts Generated", value: data.alerts_generated, cls: "" },
    { label: "Incidents", value: data.incidents_total, cls: "" },
    { label: "Critical", value: rc.critical, cls: "critical" },
    { label: "High", value: rc.high, cls: "high" },
    { label: "Medium", value: rc.medium, cls: "medium" },
    { label: "Low", value: rc.low, cls: "low" },
    { label: "Investigated", value: data.investigated, cls: "" },
    { label: "Escalated", value: data.escalated, cls: "" },
  ];

  const incidentCards = data.active_incidents.length
    ? data.active_incidents
        .map(
          (i) => `
      <div class="incident-card ${i.risk_level}" data-id="${i.id}">
        <div class="top-row">
          <div class="title">${riskBadge(i.risk_level)} ${escapeHtml(i.title)}</div>
          <div>${techniqueChips(i.attack_techniques.map((id) => ({ id, name: "" })))}</div>
        </div>
        <div class="meta">
          User(s): ${escapeHtml(i.users.join(", ") || "—")} &nbsp;|&nbsp;
          Asset(s): ${escapeHtml(i.hosts.join(", ") || "—")} &nbsp;|&nbsp;
          ${i.alert_count} correlated alert(s) &nbsp;|&nbsp;
          confidence ${i.confidence}%
        </div>
      </div>`
        )
        .join("")
    : `<div class="empty-state">No active incidents. Run a scenario above to populate the dashboard.</div>`;

  viewRoot.innerHTML = `
    <h2 class="section-title">Security Posture — All Scenarios</h2>
    <div class="stat-grid">
      ${tiles
        .map(
          (t) => `<div class="stat-tile ${t.cls}"><div class="label">${t.label}</div><div class="value">${t.value}</div></div>`
        )
        .join("")}
    </div>
    <h2 class="section-title">Active Incidents</h2>
    ${incidentCards}
  `;

  viewRoot.querySelectorAll(".incident-card").forEach((card) => {
    card.addEventListener("click", () => openIncident(card.dataset.id));
  });
}

// ---------- Incident detail ----------

async function openIncident(id) {
  state.view = "incident";
  state.incidentId = id;
  state.incidentTab = "analyst";
  viewRoot.innerHTML = `<div class="empty-state">Loading incident…</div>`;
  backLinkContainer.innerHTML = `<button class="link-btn" id="back-btn">← Back to dashboard</button>`;
  document.getElementById("back-btn").addEventListener("click", goDashboard);
  const detail = await fetchJSON(`${API}/incidents/${id}`);
  renderIncident(detail);
}

function renderIncident(detail) {
  viewRoot.innerHTML = `
    <div class="panel">
      <div class="top-row" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
        <div>
          <h2 style="margin:0 0 6px;font-size:18px;">${riskBadge(detail.risk_level)} ${escapeHtml(detail.title)}</h2>
          <div class="meta" style="color:var(--text-dim);font-size:12px;">
            Status: ${escapeHtml(detail.status.replace("_", " "))} &nbsp;|&nbsp;
            Confidence: ${detail.confidence}% &nbsp;|&nbsp;
            User(s): ${escapeHtml(detail.users.join(", ") || "—")} &nbsp;|&nbsp;
            Asset(s): ${escapeHtml(detail.hosts.join(", ") || "—")}
          </div>
        </div>
      </div>
      <div style="margin-top:10px;">${techniqueChips(
        detail.attack_techniques.map((id) => {
          const found = detail.alerts.flatMap((a) => a.attack_techniques).find((t) => t.id === id);
          return found || { id, name: "" };
        })
      )}</div>
    </div>

    <div class="view-toggle">
      <button id="tab-analyst" class="${state.incidentTab === "analyst" ? "active" : ""}">SOC ANALYST VIEW</button>
      <button id="tab-ciso" class="${state.incidentTab === "ciso" ? "active" : ""}">CISO VIEW</button>
    </div>

    <div id="tab-content"></div>

    <h2 class="section-title">AI Investigation Assistant</h2>
    <div class="panel">
      <div class="chat-suggestions">
        <button data-q="Why is this critical?">Why is this critical?</button>
        <button data-q="What should I investigate next?">What should I investigate next?</button>
        <button data-q="What's the business impact?">What's the business impact?</button>
      </div>
      <div class="chat-box" id="chat-box"></div>
      <div class="chat-input-row">
        <input id="chat-input" type="text" placeholder="Ask about this incident…" />
        <button id="chat-send">Ask</button>
      </div>
    </div>
  `;

  document.getElementById("tab-analyst").addEventListener("click", () => {
    state.incidentTab = "analyst";
    renderIncident(detail);
  });
  document.getElementById("tab-ciso").addEventListener("click", () => {
    state.incidentTab = "ciso";
    renderIncident(detail);
  });

  document.getElementById("tab-content").innerHTML =
    state.incidentTab === "analyst" ? renderAnalystView(detail) : renderCisoView(detail);

  wireChat(detail);
}

function renderAnalystView(detail) {
  const timeline = detail.timeline
    .map(
      (t) =>
        `<div class="timeline-item"><span class="ts">${escapeHtml(t.timestamp)}</span>${escapeHtml(
          t.summary
        )} <span style="color:var(--text-dim)">(${escapeHtml(t.host || "")} / ${escapeHtml(t.user || "")})</span></div>`
    )
    .join("");

  const whyBlocks = detail.why_did_we_alert
    .map((w) => {
      const up = w.increasing_factors.map((f) => `<div class="factor up">+ ${escapeHtml(f.label)} (${f.weight >= 0 ? "+" : ""}${f.weight})</div>`).join("");
      const down = w.decreasing_factors.map((f) => `<div class="factor down">- ${escapeHtml(f.label)} (${f.weight})</div>`).join("");
      const fps = w.falsepositives.map((f) => `<li>${escapeHtml(f)}</li>`).join("");
      return `
        <div class="evidence-block">
          <strong>${escapeHtml(w.rule_title)}</strong> — confidence ${w.confidence}%
          <p style="color:var(--text-dim);margin:6px 0;">${escapeHtml(w.description)}</p>
          <div>${techniqueChips(w.attack_techniques)}</div>
          <div style="margin-top:8px;"><em>Factors increasing confidence</em>${up || '<div class="factor">none</div>'}</div>
          <div style="margin-top:6px;"><em>Factors decreasing confidence</em>${down || '<div class="factor">none</div>'}</div>
          ${fps ? `<div style="margin-top:8px;color:var(--text-dim);"><em>Known false-positive causes:</em><ul>${fps}</ul></div>` : ""}
          <pre class="raw-fields">${escapeHtml(JSON.stringify(w.event, null, 2))}</pre>
        </div>`;
    })
    .join("");

  const steps = detail.analyst.next_steps.map((s, i) => `<li>${escapeHtml(s)}</li>`).join("");

  return `
    <div class="panel">
      <h3 style="margin-top:0;">Incident Timeline</h3>
      ${timeline}
    </div>
    <div class="panel">
      <h3 style="margin-top:0;">Why Did We Alert?</h3>
      ${whyBlocks}
    </div>
    <div class="panel">
      <h3 style="margin-top:0;">Why This Risk Level</h3>
      <p>${escapeHtml(detail.analyst.why_critical)}</p>
    </div>
    <div class="panel">
      <h3 style="margin-top:0;">Recommended Investigation Steps</h3>
      <ol>${steps || "<li>No further steps generated.</li>"}</ol>
    </div>
    ${nistPanel(detail)}
  `;
}

function renderCisoView(detail) {
  return `
    <div class="panel">
      <h3 style="margin-top:0;">Executive Summary</h3>
      <p style="font-size:15px;line-height:1.6;">${escapeHtml(detail.ciso.summary)}</p>
    </div>
    ${nistPanel(detail)}
  `;
}

function nistPanel(detail) {
  const order = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"];
  const cols = order
    .map((fn) => {
      const items = (detail.nist_csf[fn] || [])
        .map((it) => `<div class="nist-item ${it.status}">${escapeHtml(it.item)}</div>`)
        .join("");
      return `<div class="nist-fn"><h4>${fn}</h4>${items || '<div class="nist-item not_applicable">No items</div>'}</div>`;
    })
    .join("");
  return `
    <div class="panel">
      <h3 style="margin-top:0;">NIST CSF 2.0 Mapping</h3>
      <div class="nist-grid">${cols}</div>
    </div>`;
}

// ---------- Chat ----------

function wireChat(detail) {
  const box = document.getElementById("chat-box");
  const input = document.getElementById("chat-input");
  const sendBtn = document.getElementById("chat-send");

  const history = (state.chatHistory[detail.id] ||= []);
  renderChatHistory(box, history);

  async function send(question) {
    if (!question.trim()) return;
    history.push({ role: "user", text: question });
    renderChatHistory(box, history);
    input.value = "";
    const { answer } = await fetchJSON(`${API}/incidents/${detail.id}/ask`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
    });
    history.push({ role: "ai", text: answer });
    renderChatHistory(box, history);
  }

  sendBtn.addEventListener("click", () => send(input.value));
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") send(input.value);
  });
  document.querySelectorAll(".chat-suggestions button").forEach((b) => {
    b.addEventListener("click", () => send(b.dataset.q));
  });
}

function renderChatHistory(box, history) {
  box.innerHTML = history
    .map((m) => `<div class="chat-msg ${m.role}">${escapeHtml(m.text)}</div>`)
    .join("");
  box.scrollTop = box.scrollHeight;
}

// ---------- Boot ----------

loadScenarioBar();
goDashboard();
