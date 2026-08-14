import { api } from "./api.js";
import {
  escapeHtml,
  severityLabel,
  statusLabel,
  techniqueChips,
  confidenceBar,
  formatTime,
  copyToClipboard,
  loadingState,
  errorState,
} from "./helpers.js";

const BACK_TARGETS = {
  lab: { view: "lab", label: "BACK TO ATTACK LAB" },
  live: { view: "live", label: "BACK TO MY NETWORK" },
  incidents: { view: "incidents", label: "BACK TO INCIDENTS" },
};

export async function renderIncident(container, ctx, incidentId, from) {
  container.innerHTML = loadingState("LOADING INCIDENT…");
  let detail;
  try {
    detail = await api.incident(incidentId);
  } catch (e) {
    container.innerHTML = errorState("This incident could not be loaded.");
    return;
  }

  ctx.setAiContext(detail);

  const back = BACK_TARGETS[from] || BACK_TARGETS.incidents;
  const view = { tab: "summary", presentation: "analyst" };

  function draw() {
    container.innerHTML = `
      <button class="back-link" id="back-to-incidents">&larr; ${back.label}</button>
      <section class="panel incident-header sev-border-${detail.risk_level}">
        <div class="incident-header-top">
          <div>
            ${severityLabel(detail.risk_level)}
            <span class="mono dim">${escapeHtml(detail.id)}</span>
            ${statusLabel(detail.status)}
            <h2>${escapeHtml(detail.title)}</h2>
          </div>
          <div class="presentation-toggle">
            <span class="dim small-caps">PRESENTATION</span>
            <div class="view-toggle">
              <button class="${view.presentation === "analyst" ? "active" : ""}" data-presentation="analyst">ANALYST VIEW</button>
              <button class="${view.presentation === "leader" ? "active" : ""}" data-presentation="leader">SECURITY LEADER VIEW</button>
            </div>
            <button class="btn-run small-btn" id="ask-ai-btn">&#9670; ASK AI</button>
          </div>
        </div>
        <div class="incident-stats">
          <div><span class="dim">CONFIDENCE</span><strong class="critical">${detail.confidence}%</strong>${confidenceBar(detail.confidence)}</div>
          <div><span class="dim">RELATED SIGNALS</span><strong>${detail.alert_count}</strong></div>
          <div><span class="dim">ATT&amp;CK TECHNIQUES</span><strong>${detail.attack_techniques.length}</strong></div>
        </div>
        <div class="incident-entities"><span class="dim">IDENTITY &middot; ASSETS</span> ${escapeHtml(
          [...detail.users, ...detail.hosts].join(" &middot; ".replace("&middot;", "·")) || "—"
        )}</div>
      </section>

      ${
        view.presentation === "analyst"
          ? `<div class="tab-bar">
              ${["summary", "timeline", "evidence", "detection", "attack", "nist"]
                .map((t) => `<button class="${view.tab === t ? "active" : ""}" data-tab="${t}">${t.toUpperCase()}</button>`)
                .join("")}
            </div>
            <div id="tab-content"></div>`
          : `<div id="tab-content"></div>`
      }
    `;

    container.querySelector("#back-to-incidents").addEventListener("click", () => ctx.navigate(back.view));
    container.querySelector("#ask-ai-btn").addEventListener("click", () => ctx.openAiDrawer());
    container.querySelectorAll("[data-presentation]").forEach((btn) => {
      btn.addEventListener("click", () => {
        view.presentation = btn.dataset.presentation;
        draw();
      });
    });
    container.querySelectorAll("[data-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        view.tab = btn.dataset.tab;
        draw();
      });
    });

    const tabContent = container.querySelector("#tab-content");
    if (view.presentation === "leader") {
      tabContent.innerHTML = renderLeaderView(detail);
    } else if (view.tab === "summary") {
      tabContent.innerHTML = renderSummaryTab(detail);
    } else if (view.tab === "timeline") {
      tabContent.innerHTML = renderTimelineTab(detail);
    } else if (view.tab === "evidence") {
      tabContent.innerHTML = renderEvidenceTab(detail);
      wireEvidenceButtons(tabContent);
    } else if (view.tab === "attack") {
      tabContent.innerHTML = renderAttackTab(detail);
    } else if (view.tab === "nist") {
      tabContent.innerHTML = renderNistTab(detail);
      wireNistTabs(tabContent, detail);
    } else if (view.tab === "detection") {
      tabContent.innerHTML = loadingState();
      renderDetectionTab(detail, ctx).then((html) => {
        tabContent.innerHTML = html;
        wireDetectionButtons(tabContent, detail, ctx);
      });
    }
  }

  draw();
}

function renderLeaderView(detail) {
  const ciso = detail.ciso;
  const stateItems = ciso.current_state
    .map(
      (s) => `<div class="current-state-item"><span class="check-box ${s.done ? "done" : "pending"}">${s.done ? "&check;" : "&#9675;"}</span>${escapeHtml(s.label)}</div>`
    )
    .join("");
  return `
    <div class="two-col">
      <section class="panel">
        <div class="detail-label">INCIDENT</div>
        <h3>${escapeHtml(ciso.headline)}</h3>
        <p class="dim mono">${escapeHtml(detail.id)} &middot; detected ${formatTime(detail.created_at)}, correlated ${formatTime(detail.updated_at)}</p>
        <div class="leader-stats">
          <div><strong>${ciso.systems_affected}</strong><span class="dim">SYSTEMS AFFECTED</span></div>
          <div><strong>${ciso.identities_involved}</strong><span class="dim">IDENTITY INVOLVED</span></div>
          <div><strong>${escapeHtml(ciso.environment_reached)}</strong><span class="dim">ENVIRONMENT REACHED</span></div>
        </div>
      </section>
      <section class="panel business-risk-panel sev-border-${detail.risk_level}">
        <div class="detail-label critical">BUSINESS RISK</div>
        <h2 class="critical">${escapeHtml(ciso.business_risk.toUpperCase())}</h2>
        <div class="detail-label" style="margin-top:16px;">RECOMMENDED PRIORITY</div>
        <p class="accent-high"><strong>${escapeHtml(ciso.recommended_priority)}</strong></p>
      </section>
    </div>
    <div class="two-col">
      <section class="panel"><div class="detail-label">WHAT HAPPENED</div><p>${escapeHtml(ciso.what_happened)}</p></section>
      <section class="panel"><div class="detail-label">WHY IT MATTERS</div><p>${escapeHtml(ciso.why_it_matters)}</p></section>
    </div>
    <section class="panel">
      <div class="detail-label">CURRENT STATE</div>
      <div class="current-state-row">${stateItems}</div>
      <p class="footnote">No technical command detail is shown in this presentation. Switch to Analyst View to inspect it.</p>
    </section>
  `;
}

function renderSummaryTab(detail) {
  const progression = detail.timeline
    .map(
      (s) => `
      <div class="progression-step">
        <div class="progression-marker sev-${detail.risk_level}"></div>
        <div>
          <strong>${escapeHtml(s.title)}</strong>
          <div class="dim">${escapeHtml(s.tactic)}${s.technique_id ? ` <span class="technique-chip">${escapeHtml(s.technique_id)}</span>` : ""}</div>
        </div>
        <div class="mono dim">${formatTime(s.timestamp)}</div>
      </div>`
    )
    .join("");

  const upFactors = [];
  const downFactors = [];
  detail.why_did_we_alert.forEach((w) => {
    w.increasing_factors.forEach((f) => upFactors.push(f));
    w.decreasing_factors.forEach((f) => downFactors.push(f));
  });

  const factorRows = (list, sign) =>
    list.map((f) => `<div class="factor-row"><span class="${sign > 0 ? "critical" : "good"}">${sign > 0 ? "+" : ""}${f.weight}</span> ${escapeHtml(f.label)}</div>`).join("");

  return `
    <div class="three-col">
      <section class="panel">
        <div class="detail-label">WHAT HAPPENED</div>
        <p>${escapeHtml(detail.ciso.what_happened)}</p>
        <p><strong>${detail.alert_count}</strong> related alert(s) were correlated into this incident.</p>
        <div class="kv-list dim mono">
          <div>first observed &nbsp; ${formatTime(detail.created_at)}</div>
          <div>last observed &nbsp;&nbsp; ${formatTime(detail.updated_at)}</div>
          <div>scenario &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;${escapeHtml(detail.scenario_id)}</div>
        </div>
      </section>
      <section class="panel">
        <div class="detail-label">ATTACK PROGRESSION</div>
        ${progression}
      </section>
      <section class="panel">
        <div class="detail-label">CONFIDENCE SCORE <span class="critical" style="float:right;">${detail.confidence}%</span></div>
        ${confidenceBar(detail.confidence)}
        ${upFactors.length ? `<div class="detail-label small-caps" style="margin-top:14px;">INCREASED CONFIDENCE</div>${factorRows(upFactors, 1)}` : ""}
        ${downFactors.length ? `<div class="detail-label small-caps" style="margin-top:14px;">REDUCED CONFIDENCE</div>${factorRows(downFactors, -1)}` : ""}
        <p class="footnote">Incident confidence is the highest-scoring constituent alert. Every factor above is declared in the rule, not inferred by a model.</p>
      </section>
    </div>
  `;
}

function renderTimelineTab(detail) {
  const first = detail.timeline[0]?.timestamp;
  const last = detail.timeline[detail.timeline.length - 1]?.timestamp;
  const items = detail.timeline
    .map((s) => {
      const fields = Object.entries(s.fields || {})
        .slice(0, 6)
        .map(([k, v]) => `<div><span class="dim">${escapeHtml(k)}</span>${escapeHtml(String(v))}</div>`)
        .join("");
      return `
      <div class="forensic-item">
        <div class="forensic-time mono">${formatTime(s.timestamp)}</div>
        <div class="forensic-marker sev-${detail.risk_level}"></div>
        <div class="forensic-body">
          <div class="forensic-tag">${escapeHtml((s.tactic || "").toUpperCase())} ${s.technique_id ? `<span class="technique-chip">${escapeHtml(s.technique_id)}</span>` : ""}</div>
          <strong>${escapeHtml(s.title)}</strong>
          <div class="field-grid">${fields}</div>
          ${s.annotation ? `<p class="dim annotation">${escapeHtml(s.annotation)}</p>` : ""}
        </div>
      </div>`;
    })
    .join("");
  return `
    <section class="panel">
      <div class="detail-label">FORENSIC TIMELINE <span class="dim" style="float:right;">${formatTime(first)} &rarr; ${formatTime(last)}</span></div>
      ${items}
    </section>
  `;
}

function renderEvidenceTab(detail) {
  return `
    ${detail.alerts
      .map(
        (a, idx) => `
      <section class="panel">
        <div class="evidence-header">
          <div class="detail-label">${escapeHtml((a.event.event_type || "").replace(/_/g, " ").toUpperCase())}</div>
          <div>
            <button class="small-btn" data-view-json="${idx}">VIEW RAW JSON</button>
            <button class="small-btn copy-btn" data-copy-json="${idx}">COPY EVENT</button>
          </div>
        </div>
        <div class="field-grid field-grid-3">
          <div><span class="dim">HOST</span>${escapeHtml(a.event.host || "—")}</div>
          <div><span class="dim">USER</span>${escapeHtml(a.event.user || "—")}</div>
          <div><span class="dim">TIMESTAMP</span>${formatTime(a.event.timestamp)}</div>
          ${Object.entries(a.event.fields)
            .map(([k, v]) => `<div><span class="dim">${escapeHtml(k.toUpperCase())}</span>${escapeHtml(String(v))}</div>`)
            .join("")}
        </div>
        <pre class="code-block" id="json-${idx}" hidden>${escapeHtml(JSON.stringify(a.event, null, 2))}</pre>
      </section>`
      )
      .join("")}
  `;
}

function wireEvidenceButtons(container) {
  container.querySelectorAll("[data-view-json]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const pre = container.querySelector(`#json-${btn.dataset.viewJson}`);
      pre.hidden = !pre.hidden;
      btn.textContent = pre.hidden ? "VIEW RAW JSON" : "HIDE RAW JSON";
    });
  });
  container.querySelectorAll("[data-copy-json]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const pre = container.querySelector(`#json-${btn.dataset.copyJson}`);
      copyToClipboard(pre.textContent, btn);
    });
  });
}

async function renderDetectionTab(detail, ctx) {
  const uniqueRuleIds = [...new Set(detail.alerts.map((a) => a.rule_id))];
  const rules = await Promise.all(
    uniqueRuleIds.map((id) => api.detection(id).catch(() => null))
  );
  return rules
    .filter(Boolean)
    .map((rule) => {
      const conditions = rule.selections
        .map((s) => `<div class="condition-row"><span class="mono">${escapeHtml(JSON.stringify(s.criteria))}</span><span class="check">&check;</span></div>`)
        .join("");
      const fps = rule.falsepositives.map((f) => `<li>${escapeHtml(f)}</li>`).join("");
      const matchingAlert = detail.alerts.find((a) => a.rule_id === rule.id);
      return `
      <div class="two-col" style="margin-bottom:16px;">
        <section class="panel">
          <div class="detail-label">MATCHED DETECTION</div>
          <h4>${escapeHtml(rule.title)} ${severityLabel(rule.severity)}</h4>
          <p class="mono dim">${rule.techniques.map((t) => escapeHtml(t.id)).join(", ")} &nbsp; ${escapeHtml(rule.techniques[0]?.name || "")}</p>
          <div class="detail-label small-caps">MATCHED CONDITIONS</div>
          ${conditions}
          <p class="dim mono">EVENT ${escapeHtml(matchingAlert?.id || "")} &nbsp; RULE ID ${escapeHtml(rule.id)}</p>
        </section>
        <section class="panel">
          <div class="detail-label">PURPOSE</div>
          <p>${escapeHtml(rule.description)}</p>
          ${fps ? `<div class="detail-label">FALSE-POSITIVE CONSIDERATIONS</div><ul>${fps}</ul>` : ""}
          <button class="btn-secondary" data-view-rule="${rule.id}">VIEW RULE IN DETECTION LIBRARY &rarr;</button>
        </section>
      </div>
      <section class="panel">
        <div class="detail-label">SIGMA RULE <span class="mono dim">detections/sigma/${escapeHtml(rule.filename)}</span></div>
        <pre class="code-block">${escapeHtml(rule.raw_yaml)}</pre>
      </section>`;
    })
    .join("");
}

function wireDetectionButtons(container, detail, ctx) {
  container.querySelectorAll("[data-view-rule]").forEach((btn) => {
    btn.addEventListener("click", () => ctx.navigate("rules", { ruleId: btn.dataset.viewRule }));
  });
}

function renderAttackTab(detail) {
  const chain = detail.attack_chain;
  if (detail.source === "live") {
    return `
      <section class="panel">
        <div class="detail-label">MITRE ATT&amp;CK MAPPING</div>
        <div class="chain-note">&#9670; ${escapeHtml(chain.note)}</div>
      </section>`;
  }
  const rows = chain.steps
    .map(
      (s, i) => `
      <div class="attack-chain-row">
        <div class="stacked-stat"><span class="dim small-caps">TACTIC</span><strong>${escapeHtml(s.tactic)}</strong></div>
        <div><span class="mono">${escapeHtml(s.technique_id || "")}</span> ${escapeHtml(s.technique_name || "")}</div>
        <div class="mono dim">${formatTime(s.timestamp)}</div>
        <div><span class="observed-badge"><span class="dot dot-good"></span>OBSERVED</span></div>
      </div>
      ${i < chain.steps.length - 1 ? '<div class="chain-arrow">&darr;</div>' : ""}`
    )
    .join("");
  return `
    <section class="panel">
      <div class="detail-label">MITRE ATT&amp;CK CHAIN &middot; THIS INCIDENT ONLY <span class="dim" style="float:right;">${chain.mapped_techniques} OF ${chain.total_techniques} MAPPED TECHNIQUES</span></div>
      ${rows}
      <div class="chain-arrow">&darr;</div>
      <div class="chain-note">&#9670; ${escapeHtml(chain.note)}</div>
    </section>
  `;
}

function renderNistTab(detail) {
  const order = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"];
  const engaged = order.filter((fn) => (detail.nist_csf[fn] || []).length > 0);
  const initial = engaged.includes("DETECT") ? "DETECT" : engaged[0] || order[0];
  return `
    <section class="panel">
      <div class="detail-label">NIST CSF 2.0 &middot; FUNCTIONS ENGAGED <span class="dim" style="float:right;">GENERATED FROM INCIDENT DATA</span></div>
      <div class="nist-pills">
        ${order
          .map(
            (fn) =>
              `<button class="nist-pill ${fn === initial ? "active" : ""}" data-nist="${fn}"><span class="dot ${engaged.includes(fn) ? "dot-engaged" : "dot-idle"}"></span>${fn}</button>`
          )
          .join("")}
      </div>
      <div id="nist-body"></div>
    </section>
  `;
}

function wireNistTabs(container, detail) {
  const order = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"];
  const engaged = order.filter((fn) => (detail.nist_csf[fn] || []).length > 0);
  function draw(fn) {
    container.querySelectorAll(".nist-pill").forEach((p) => p.classList.toggle("active", p.dataset.nist === fn));
    const items = detail.nist_csf[fn] || [];
    const statusLabelText = items.some((i) => i.status === "pending") ? "RECOMMENDED" : items.length ? "COMPLETED" : "";
    const body = container.querySelector("#nist-body");
    body.innerHTML = items.length
      ? `<div class="nist-function-panel sev-border-${fn === "RESPOND" ? "high" : "low"}">
          <div class="detail-label">${fn} ${statusLabelText ? `<span class="dim">${statusLabelText}</span>` : ""}</div>
          ${items
            .map(
              (it) =>
                `<div class="nist-item"><span class="check-box ${it.status === "done" ? "done" : it.status === "pending" ? "pending" : "na"}">${
                  it.status === "done" ? "&check;" : it.status === "pending" ? "&#9675;" : "&minus;"
                }</span>${escapeHtml(it.item)}</div>`
            )
            .join("")}
          ${fn === "RESPOND" ? '<p class="footnote">Recommendations are not executed actions.</p>' : ""}
        </div>`
      : `<p class="dim">No items generated for this function on this incident.</p>`;
    container.querySelectorAll("[data-nist]").forEach((btn) => {
      btn.onclick = () => draw(btn.dataset.nist);
    });
  }
  const initial = engaged.includes("DETECT") ? "DETECT" : engaged[0] || order[0];
  draw(initial);
}
