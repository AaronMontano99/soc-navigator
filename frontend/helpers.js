export function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

export function severityDot(level) {
  return `<span class="sev-dot sev-${level}"></span>`;
}

export function severityLabel(level) {
  return `<span class="sev-label sev-${level}">${severityDot(level)}${escapeHtml((level || "").toUpperCase())}</span>`;
}

export function statusLabel(status) {
  const text = (status || "").replace(/_/g, " ").toUpperCase();
  return `<span class="status-label status-${status}">${escapeHtml(text)}</span>`;
}

export function techniqueChip(t) {
  return `<span class="technique-chip">${escapeHtml(t.id)}</span>`;
}

export function techniqueChips(list, limit) {
  const items = limit ? list.slice(0, limit) : list;
  const chips = items.map(techniqueChip).join(" ");
  const overflow = limit && list.length > limit ? `<span class="technique-overflow">+${list.length - limit}</span>` : "";
  return chips + overflow;
}

export function confidenceBar(value) {
  return `<div class="confidence-bar"><div class="confidence-bar-fill" style="width:${value}%"></div></div>`;
}

export function relativeTime(isoString) {
  if (!isoString) return "—";
  const then = new Date(isoString).getTime();
  const now = Date.now();
  const diffSec = Math.max(0, Math.round((now - then) / 1000));
  if (diffSec < 60) return `${diffSec}s`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h`;
  const diffDay = Math.round(diffHr / 24);
  return `${diffDay}d`;
}

export function formatTime(isoString) {
  if (!isoString) return "—";
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return isoString;
  return d.toISOString().slice(11, 19);
}

export function el(html) {
  const template = document.createElement("template");
  template.innerHTML = html.trim();
  return template.content.firstElementChild;
}

export function copyToClipboard(text, button) {
  navigator.clipboard.writeText(text).then(() => {
    const original = button.textContent;
    button.textContent = "COPIED";
    button.classList.add("copied");
    setTimeout(() => {
      button.textContent = original;
      button.classList.remove("copied");
    }, 1200);
  });
}

export function loadingState(label) {
  return `<div class="state-panel state-loading">${escapeHtml(label || "LOADING…")}</div>`;
}

export function emptyState(title, subtitle) {
  return `<div class="state-panel state-empty"><div class="state-title">${escapeHtml(title)}</div>${
    subtitle ? `<div class="state-subtitle">${escapeHtml(subtitle)}</div>` : ""
  }</div>`;
}

export function errorState(message) {
  return `<div class="state-panel state-error"><div class="state-title">LOCAL API UNAVAILABLE</div><div class="state-subtitle">${escapeHtml(
    message || "Make sure soc-navigator is running (uvicorn app.main:app --reload)."
  )}</div></div>`;
}
