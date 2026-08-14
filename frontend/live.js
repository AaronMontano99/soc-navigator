import { api } from "./api.js";
import {
  escapeHtml,
  severityLabel,
  statusLabel,
  confidenceBar,
  relativeTime,
  loadingState,
  errorState,
} from "./helpers.js";

function deviceRow(device) {
  const ports = device.open_ports || [];
  return `
    <tr>
      <td class="mono">${escapeHtml(device.ip)}</td>
      <td>${escapeHtml(device.hostname || "—")}</td>
      <td>${
        ports.length
          ? ports.map((p) => `<span class="technique-chip">${p.port} ${escapeHtml(p.service)}</span>`).join(" ")
          : '<span class="dim">none found</span>'
      }</td>
      <td>${device.is_new ? '<span class="status-label status-needs_investigation">NEW</span>' : '<span class="dim">seen before</span>'}</td>
    </tr>`;
}

function findingRow(incident, ctx) {
  return `
    <tr class="clickable-row" data-incident="${incident.id}">
      <td>${severityLabel(incident.risk_level)}</td>
      <td>
        <div class="row-title">${escapeHtml(incident.title)}</div>
        <div class="row-meta">${escapeHtml(incident.hosts.join(", ") || "—")}</div>
      </td>
      <td>${incident.confidence}%${confidenceBar(incident.confidence)}</td>
      <td>${statusLabel(incident.status)}</td>
      <td class="col-age">${relativeTime(incident.generated_at)}</td>
    </tr>`;
}

function wireFindingRows(container, ctx) {
  container.querySelectorAll("[data-incident]").forEach((row) => {
    row.addEventListener("click", () => ctx.navigate("incident", { id: row.dataset.incident, from: "live" }));
  });
}

export async function renderLive(container, ctx) {
  container.innerHTML = loadingState();
  let last;
  try {
    last = await api.liveLast();
  } catch (e) {
    container.innerHTML = errorState();
    return;
  }

  function renderShell(state) {
    const hasResult = state.devices && state.devices.length > 0;
    container.innerHTML = `
      <div class="content-header">
        <div>
          <h2>My Network</h2>
          <p class="content-subtitle">A real scan of your local network — device discovery + common-port inventory. Not a claim of endpoint-level (EDR) visibility.</p>
        </div>
        <button class="btn-run" id="scan-btn" ${state.scanning ? "disabled" : ""}>${state.scanning ? "SCANNING…" : "SCAN MY NETWORK"}</button>
      </div>

      <section class="panel">
        <p class="dim" style="margin:0;">
          ${
            state.subnet
              ? `Subnet: <span class="mono">${escapeHtml(state.subnet)}</span>${state.scanned_at ? ` &middot; last scanned ${relativeTime(state.scanned_at)} ago` : ""}`
              : "No scan yet — the subnet is auto-detected from this machine's local network address when you click Scan."
          }
        </p>
        <p class="footnote" style="margin:10px 0 0;">
          Only scans your own private local network (RFC1918 address space, capped at a /24) — this can never be pointed at a public IP range.
          No authentication, database, or credential access is attempted; this only checks whether a TCP port accepts a connection.
        </p>
      </section>

      ${state.error ? `<section class="panel"><p class="critical">${escapeHtml(state.error)}</p></section>` : ""}

      ${
        hasResult
          ? `<section class="panel">
              <h3>Devices Found (${state.devices.length})</h3>
              <table class="data-table"><thead><tr><th>IP</th><th>Hostname</th><th>Open Ports</th><th>Inventory</th></tr></thead>
              <tbody>${state.devices.map(deviceRow).join("")}</tbody></table>
            </section>
            <section class="panel">
              <h3>Findings (${state.incidents.length})</h3>
              ${
                state.incidents.length
                  ? `<table class="data-table"><thead><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>Status</th><th>Age</th></tr></thead>
                     <tbody id="live-findings-body">${state.incidents.map((i) => findingRow(i, ctx)).join("")}</tbody></table>`
                  : `<p class="dim">No findings — nothing on your network matched a Live detection rule.</p>`
              }
            </section>`
          : !state.scanning
            ? `<section class="panel"><p class="dim">No scan has been run yet this session. Click Scan My Network to discover devices and check for exposed services.</p></section>`
            : ""
      }
    `;

    container.querySelector("#scan-btn").addEventListener("click", () => runScan(state.subnet));
    if (hasResult) wireFindingRows(container, ctx);
  }

  async function runScan(subnet) {
    renderShell({ subnet, scanning: true });
    try {
      const result = await api.liveScan(subnet);
      renderShell({ ...result, scanning: false });
    } catch (e) {
      renderShell({ subnet, scanning: false, error: e.message || "Scan failed." });
    }
  }

  renderShell({ ...last, scanning: false });
}
