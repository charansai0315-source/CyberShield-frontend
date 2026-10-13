const $ = (selector) => document.querySelector(selector);

const categoryStyle = [
  { name: "Benign", color: "#24b697" },
  { name: "DDoS", color: "#eb7771" },
  { name: "Port scan", color: "#e99d50" },
  { name: "Brute force", color: "#987de0" },
  { name: "Data exfiltration", color: "#5683ed" },
];

let recentEvents = [];
let toastTimer;

function number(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function confidence(value) {
  return `${Math.round(Number(value || 0) * 100)}%`;
}

function showToast(message, isError = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 3400);
}

async function requestJson(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.detail || body.title || `Request failed (${response.status})`);
  }
  return body;
}

function formatTime(timestamp) {
  if (!timestamp) return "—";
  const date = new Date(timestamp);
  const elapsed = Math.max(0, Date.now() - date.getTime());
  if (elapsed < 45_000) return "Just now";
  if (elapsed < 3_600_000) return `${Math.floor(elapsed / 60_000)}m ago`;
  return new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(date);
}

function severityClass(severity) {
  const value = String(severity || "").toUpperCase();
  if (value === "CRITICAL") return "critical";
  if (value === "HIGH") return "high";
  if (value === "MEDIUM") return "medium";
  return "";
}

function makeCell(content, className) {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  if (content instanceof Node) cell.append(content);
  else cell.textContent = content;
  return cell;
}

function renderActivity(events) {
  const body = $("#activity-rows");
  body.replaceChildren();

  const query = $("#activity-search").value.trim().toLowerCase();
  const filtered = events.filter((event) => {
    const searchable = `${event.sourceIp} ${event.destinationIp} ${event.protocol} ${event.category} ${event.severity}`.toLowerCase();
    return searchable.includes(query);
  });

  if (!filtered.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "empty-cell";
    cell.textContent = query ? "No flows match this search." : "No analyzed traffic yet. Submit a flow or load demo data.";
    row.append(cell);
    body.append(row);
    $("#activity-count").textContent = query ? "0 matching flows" : "No flows yet";
    return;
  }

  filtered.forEach((event) => {
    const row = document.createElement("tr");
    const flow = document.createElement("div");
    flow.className = "flow-cell";
    const route = document.createElement("span");
    route.className = "flow-route";
    route.textContent = `${event.sourceIp} → ${event.destinationIp}`;
    const ports = document.createElement("span");
    ports.className = "flow-port";
    ports.textContent = `${event.sourcePort} → ${event.destinationPort}`;
    flow.append(route, ports);

    const protocol = document.createElement("span");
    protocol.className = "protocol-pill";
    protocol.textContent = event.protocol;

    const classification = document.createElement("div");
    classification.className = "classification-cell";
    const indicator = document.createElement("span");
    const severity = String(event.severity || "").toUpperCase();
    indicator.className = `class-indicator${severity === "CRITICAL" ? " is-critical" : severity === "HIGH" || severity === "MEDIUM" ? " is-threat" : ""}`;
    const category = document.createElement("span");
    category.textContent = event.category;
    classification.append(indicator, category);

    const severityTag = document.createElement("span");
    severityTag.className = `severity-pill ${severityClass(event.severity)}`;
    severityTag.textContent = severity || "INFO";

    const score = document.createElement("div");
    score.className = "confidence-cell";
    const miniTrack = document.createElement("span");
    miniTrack.className = "confidence-mini";
    const miniBar = document.createElement("span");
    miniBar.style.width = confidence(event.confidence);
    miniTrack.append(miniBar);
    const scoreLabel = document.createElement("span");
    scoreLabel.textContent = confidence(event.confidence);
    score.append(miniTrack, scoreLabel);

    row.append(
      makeCell(flow),
      makeCell(protocol),
      makeCell(classification),
      makeCell(severityTag),
      makeCell(score),
      makeCell(formatTime(event.createdAt)),
    );
    body.append(row);
  });

  $("#activity-count").textContent = query
    ? `${filtered.length} matching ${filtered.length === 1 ? "flow" : "flows"}`
    : `Showing ${filtered.length} recent ${filtered.length === 1 ? "flow" : "flows"}`;
}

function renderCategories(summary) {
  const counts = summary.categoryCounts || {};
  const total = Number(summary.totalAnalyzed || 0);
  const max = Math.max(1, ...categoryStyle.map(({ name }) => Number(counts[name] || 0)));
  $("#category-total").textContent = number(total);

  const container = $("#category-bars");
  container.replaceChildren();
  categoryStyle.forEach(({ name, color }) => {
    const count = Number(counts[name] || 0);
    const row = document.createElement("div");
    row.className = "category-row";
    row.style.setProperty("--bar-color", color);
    const label = document.createElement("div");
    label.className = "category-row-label";
    const swatch = document.createElement("span");
    swatch.className = "category-swatch";
    const text = document.createElement("span");
    text.textContent = name;
    label.append(swatch, text);
    const value = document.createElement("span");
    value.className = "category-row-value";
    value.textContent = `${number(count)} · ${total ? Math.round((count / total) * 100) : 0}%`;
    const track = document.createElement("div");
    track.className = "category-track";
    const bar = document.createElement("span");
    bar.style.setProperty("--bar-width", `${count ? Math.max(4, (count / max) * 100) : 0}%`);
    track.append(bar);
    row.append(label, value, track);
    container.append(row);
  });
}

function renderSummary(summary) {
  const total = Number(summary.totalAnalyzed || 0);
  $("#stat-total").textContent = number(total);
  $("#stat-threats").textContent = number(summary.threatsDetected);
  $("#stat-benign").textContent = number(summary.benignCount);
  $("#stat-threat-rate").textContent = `${Number(summary.threatRate || 0).toFixed(1)}% of flows`;
  $("#stat-confidence").textContent = total ? confidence(summary.averageConfidence) : "—";
  renderCategories(summary);
}

function setServiceStatus(health) {
  const model = health.model || {};
  const modelIsUp = model.status === "UP";
  const previewMode = model.mode === "PREVIEW";
  const dot = $("#api-dot");
  dot.classList.toggle("is-up", modelIsUp);
  dot.classList.toggle("is-down", !modelIsUp);
  $("#api-status").textContent = modelIsUp ? (previewMode ? "Local preview connected" : "All services connected") : "Model service unavailable";
  $("#model-status-side").textContent = modelIsUp ? (previewMode ? "Preview mode online" : "Classifier online") : "Classifier unavailable";
  const accuracy = Number(model.holdoutAccuracy || 0);
  $("#model-detail-side").textContent = modelIsUp
    ? (previewMode ? "In-memory demo data" : `${number(model.trainingRows)} synthetic training rows`)
    : "Check the Python service";
  $(".model-card-foot span:first-child").textContent = previewMode ? "Local preview" : "Random forest";
  $("#stat-confidence").closest(".stat-card").querySelector(".stat-top > span:first-child").textContent = previewMode ? "Preview score" : "Model confidence";
  $(".result-confidence span").textContent = previewMode ? "Preview score" : "Model confidence";
  $("#model-note-text").textContent = previewMode
    ? "This local preview uses sample rules and in-memory data. Use Docker Compose for the Python ML model and MySQL storage."
    : "Predictions use generated sample traffic. Validate with a representative dataset before operational use.";
  $(".model-meter span").style.width = modelIsUp ? `${Math.max(15, Math.min(100, accuracy * 100))}%` : "12%";
}

function showResult(event) {
  $("#result-empty").classList.add("hidden");
  $("#result-content").classList.remove("hidden");
  $("#result-category").textContent = event.category;
  $("#result-confidence-value").textContent = confidence(event.confidence);
  $("#result-confidence-bar").style.width = confidence(event.confidence);
  $("#result-summary").textContent = event.summary;
  $("#result-source").textContent = `${event.sourceIp} → ${event.destinationIp}`;
  $("#result-time").textContent = formatTime(event.createdAt);
  const chip = $("#result-severity");
  const severity = String(event.severity || "INFO").toUpperCase();
  chip.textContent = severity;
  chip.classList.toggle("threat-high", severity === "HIGH" || severity === "MEDIUM");
  chip.classList.toggle("threat-critical", severity === "CRITICAL");
}

async function refreshDashboard() {
  try {
    const [health, summary, events] = await Promise.all([
      requestJson("/api/health"),
      requestJson("/api/dashboard/summary"),
      requestJson("/api/traffic/recent?limit=16"),
    ]);
    setServiceStatus(health);
    renderSummary(summary);
    recentEvents = events;
    renderActivity(recentEvents);
    $("#last-updated").textContent = `Last synced ${new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(new Date())}`;
  } catch (error) {
    $("#api-dot").classList.remove("is-up");
    $("#api-dot").classList.add("is-down");
    $("#api-status").textContent = "API unavailable";
    $("#model-status-side").textContent = "Waiting for API";
    $("#model-detail-side").textContent = "Start the app services";
    $("#last-updated").textContent = "Could not sync with the API";
    showToast(error.message || "Could not load the dashboard.", true);
  }
}

async function loadDemoData() {
  const button = $("#load-demo-button");
  button.disabled = true;
  try {
    const added = await requestJson("/api/traffic/demo", { method: "POST" });
    await refreshDashboard();
    showToast(`${added.length} example flows analyzed and saved.`);
  } catch (error) {
    showToast(error.message || "Could not load demo traffic.", true);
  } finally {
    button.disabled = false;
  }
}

async function analyzeFlow(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $("#analyze-button");
  const payload = Object.fromEntries(new FormData(form).entries());
  ["sourcePort", "destinationPort", "flowDurationMs", "packetsForward", "packetsBackward", "bytesForward", "bytesBackward", "failedLogins"]
    .forEach((field) => { payload[field] = Number(payload[field]); });

  button.disabled = true;
  button.textContent = "Analyzing flow...";
  try {
    const result = await requestJson("/api/traffic/analyze", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    showResult(result);
    await refreshDashboard();
    showToast(`${result.category} classification saved to traffic history.`);
  } catch (error) {
    showToast(error.message || "Could not analyze this flow.", true);
  } finally {
    button.disabled = false;
    button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v18M3 12h18"/></svg> Analyze flow';
  }
}

function start() {
  $("#today-label").textContent = new Intl.DateTimeFormat(undefined, {
    weekday: "short", month: "short", day: "numeric",
  }).format(new Date());
  $("#analysis-form").addEventListener("submit", analyzeFlow);
  $("#load-demo-button").addEventListener("click", loadDemoData);
  $("#refresh-button").addEventListener("click", refreshDashboard);
  $("#activity-search").addEventListener("input", () => renderActivity(recentEvents));
  refreshDashboard();
}

document.addEventListener("DOMContentLoaded", start);
