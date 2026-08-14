import { api } from "./api.js";
import { escapeHtml, loadingState, errorState } from "./helpers.js";
import {
  renderOverview,
  renderIncidents,
  renderAlerts,
  renderRules,
  renderCoverage,
  renderAttackLab,
  renderArchitecture,
  renderAbout,
} from "./views.js";
import { renderIncident } from "./incident.js";
import { renderLive } from "./live.js";

const content = document.getElementById("content");
const sidebar = document.getElementById("sidebar");
const drawer = document.getElementById("ai-drawer");
const drawerBody = document.getElementById("ai-drawer-body");
const drawerContext = document.getElementById("ai-drawer-context");

const SUGGESTED_QUESTIONS = [
  "Why is this incident critical?",
  "What happened first?",
  "What evidence supports lateral movement?",
  "Why did confidence increase?",
  "What should an analyst investigate next?",
  "Explain this incident to a security leader.",
];

const state = {
  view: "overview",
  params: {},
  incident: null, // currently open incident detail, for AI grounding
  chatHistory: {}, // incidentId -> [{role, text}]
};

const ctx = {
  navigate,
  setAiContext,
  openAiDrawer,
  setEnvironmentBadge,
  pendingRuleId: null,
};

function setEnvironmentBadge(mode) {
  const pill = document.getElementById("env-pill");
  const dot = document.getElementById("env-footer-dot");
  const title = document.getElementById("env-footer-title");
  const body = document.getElementById("env-footer-body");
  if (mode === "live") {
    pill.innerHTML = '<span class="dot dot-live"></span>LIVE NETWORK — REAL DATA';
    dot.className = "dot dot-live";
    title.textContent = "LIVE DATA";
    body.textContent = "This is a real scan of your local network, not synthetic telemetry.";
  } else {
    pill.innerHTML = '<span class="dot dot-good"></span>SYNTHETIC ENVIRONMENT';
    dot.className = "dot dot-good";
    title.textContent = "SYNTHETIC DATA";
    body.textContent = "All telemetry is generated. Not a production SIEM.";
  }
}

async function navigate(view, params = {}) {
  state.view = view;
  state.params = params;
  ctx.pendingRuleId = params.ruleId || null;

  const incidentParentView = params.from === "live" ? "live" : "incidents";
  sidebar.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.view === view || (view === "incident" && item.dataset.view === incidentParentView));
  });

  if (view !== "incident") {
    setEnvironmentBadge(view === "live" ? "live" : "synthetic");
  } else {
    setEnvironmentBadge(incidentParentView === "live" ? "live" : "synthetic");
  }

  window.scrollTo({ top: 0 });

  switch (view) {
    case "overview":
      return renderOverview(content, ctx);
    case "incidents":
      return renderIncidents(content, ctx);
    case "alerts":
      return renderAlerts(content, ctx);
    case "rules":
      return renderRules(content, ctx);
    case "coverage":
      return renderCoverage(content, ctx);
    case "lab":
      return renderAttackLab(content, ctx);
    case "live":
      return renderLive(content, ctx);
    case "architecture":
      return renderArchitecture(content);
    case "about":
      return renderAbout(content);
    case "incident":
      return renderIncident(content, ctx, params.id);
    default:
      return renderOverview(content, ctx);
  }
}

function setAiContext(incidentDetail) {
  state.incident = incidentDetail;
  drawerContext.textContent = `Grounded in ${incidentDetail.id}`;
  renderDrawerBody();
}

function openAiDrawer() {
  drawer.classList.remove("closed");
}

function closeAiDrawer() {
  drawer.classList.add("closed");
}

function renderDrawerBody() {
  const incident = state.incident;
  const history = incident ? state.chatHistory[incident.id] || [] : [];

  if (!incident) {
    drawerBody.innerHTML = `
      <p class="dim" style="padding:0 16px;">Open an incident to ask questions grounded in its data.</p>
    `;
    return;
  }

  drawerBody.innerHTML = `
    <div class="ai-suggestions">
      ${SUGGESTED_QUESTIONS.map((q) => `<button class="ai-suggestion" data-q="${escapeHtml(q)}">${escapeHtml(q)}</button>`).join("")}
    </div>
    <div class="ai-chat-box" id="ai-chat-box">
      ${history.map((m) => `<div class="ai-msg ai-msg-${m.role}">${escapeHtml(m.text)}</div>`).join("")}
    </div>
    <div class="ai-input-row">
      <input type="text" id="ai-chat-input" placeholder="Ask a follow-up question…" />
      <button id="ai-chat-send">&#9656;</button>
    </div>
  `;

  const box = drawerBody.querySelector("#ai-chat-box");
  box.scrollTop = box.scrollHeight;

  const input = drawerBody.querySelector("#ai-chat-input");
  const send = drawerBody.querySelector("#ai-chat-send");

  async function ask(question) {
    if (!question || !question.trim()) return;
    const list = (state.chatHistory[incident.id] ||= []);
    list.push({ role: "user", text: question });
    renderDrawerBody();
    const newBox = drawerBody.querySelector("#ai-chat-box");
    newBox.innerHTML += `<div class="ai-msg ai-msg-ai ai-msg-loading">Thinking…</div>`;
    newBox.scrollTop = newBox.scrollHeight;
    try {
      const { answer } = await api.ask(incident.id, question);
      list.push({ role: "ai", text: answer });
    } catch (e) {
      list.push({ role: "ai", text: "Couldn't reach the local API — make sure soc-navigator is running." });
    }
    renderDrawerBody();
  }

  drawerBody.querySelectorAll(".ai-suggestion").forEach((btn) => {
    btn.addEventListener("click", () => ask(btn.dataset.q));
  });
  send.addEventListener("click", () => {
    ask(input.value);
    input.value = "";
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      ask(input.value);
      input.value = "";
    }
  });
}

// ---------- Boot ----------

sidebar.querySelectorAll(".nav-item").forEach((item) => {
  item.addEventListener("click", () => navigate(item.dataset.view));
});

document.getElementById("topbar-ask-ai").addEventListener("click", () => {
  drawer.classList.toggle("closed");
});
document.getElementById("ai-drawer-close").addEventListener("click", closeAiDrawer);

renderDrawerBody();
navigate("overview");
