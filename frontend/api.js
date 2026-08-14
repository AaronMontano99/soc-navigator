const BASE = "/api";

async function request(path, opts) {
  let res;
  try {
    res = await fetch(BASE + path, opts);
  } catch (e) {
    throw new Error("NETWORK");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `HTTP_${res.status}`);
  }
  return res.json();
}

export const api = {
  dashboard: () => request("/dashboard"),
  scenarios: () => request("/scenarios"),
  runScenario: (id) => request(`/scenarios/${id}/run`, { method: "POST" }),
  incidents: () => request("/incidents"),
  incident: (id) => request(`/incidents/${id}`),
  ask: (id, question) =>
    request(`/incidents/${id}/ask`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
    }),
  alerts: () => request("/alerts"),
  detections: () => request("/detections"),
  detection: (id) => request(`/detections/${id}`),
  coverage: () => request("/coverage"),
  liveScan: (subnet) =>
    request("/live/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(subnet ? { subnet } : {}),
    }),
  liveLast: () => request("/live/last"),
};
