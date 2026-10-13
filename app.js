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
let isLiveBackend = false;
let nextLocalId = 100;

const classifications = {
  BENIGN: { category: "Benign", severity: "INFO", confidence: 0.91, summary: "The flow resembles ordinary network activity." },
  DDOS: { category: "DDoS", severity: "CRITICAL", confidence: 0.96, summary: "High packet volume and short duration resemble a traffic flood." },
  PORT_SCAN: { category: "Port scan", severity: "HIGH", confidence: 0.88, summary: "Low response traffic resembles probing activity." },
  BRUTE_FORCE: { category: "Brute force", severity: "HIGH", confidence: 0.98, summary: "Repeated login failures resemble credential guessing." },
  DATA_EXFILTRATION: { category: "Data exfiltration", severity: "CRITICAL", confidence: 0.91, summary: "Large outbound byte volume resembles data transfer activity." },
};

function localClassify(flow) {
  if (flow.failedLogins >= 5) return ["BRUTE_FORCE", classifications.BRUTE_FORCE];
  if (flow.packetsForward >= 1500 && flow.flowDurationMs <= 2500) return ["DDOS", classifications.DDOS];
  if (flow.bytesForward >= 1_000_000) return ["DATA_EXFILTRATION", classifications.DATA_EXFILTRATION];
  if (flow.packetsBackward <= 2 && flow.packetsForward < 100) return ["PORT_SCAN", classifications.PORT_SCAN];
  return ["BENIGN", classifications.BENIGN];
}

function localSaveAnalysis(flow) {
  const [code, result] = localClassify(flow);
  const event = { id: nextLocalId++, createdAt: new Date().toISOString(), ...flow, ...result, code };
  recentEvents.unshift(event);
  return event;
}

function getLocalSummary() {
  const categoryCounts = {};
  const severityCounts = {};
  for (const event of recentEvents) {
    categoryCounts[event.category] = (categoryCounts[event.category] || 0) + 1;
    severityCounts[event.severity] = (severityCounts[event.severity] || 0) + 1;
  }
  const threatsDetected = recentEvents.filter((e) => e.code !== "BENIGN" && e.category !== "Benign").length;
  const averageConfidence = recentEvents.length
    ? Math.round(recentEvents.reduce((total, e) => total + (e.confidence || 0.9), 0) * 100 / recentEvents.length) / 100
    : 0;
  return {
    totalAnalyzed: recentEvents.length,
    threatsDetected,
    benignCount: recentEvents.length - threatsDetected,
    threatRate: recentEvents.length ? Math.round(threatsDetected * 1000 / recentEvents.length) / 10 : 0,
    averageConfidence,
    categoryCounts,
    severityCounts,
  };
}

const sampleSeedFlows = [
  { protocol: "TCP", sourceIp: "10.0.0.24", destinationIp: "10.0.0.8", sourcePort: 52344, destinationPort: 443, flowDurationMs: 9200, packetsForward: 34, packetsBackward: 29, bytesForward: 15600, bytesBackward: 22000, failedLogins: 0 },
  { protocol: "UDP", sourceIp: "198.51.100.27", destinationIp: "10.0.0.8", sourcePort: 43120, destinationPort: 443, flowDurationMs: 120, packetsForward: 18000, packetsBackward: 2, bytesForward: 8500000, bytesBackward: 32, failedLogins: 0 },
  { protocol: "TCP", sourceIp: "203.0.113.77", destinationIp: "10.0.0.44", sourcePort: 58430, destinationPort: 22, flowDurationMs: 1500, packetsForward: 42, packetsBackward: 1, bytesForward: 2260, bytesBackward: 60, failedLogins: 0 },
  { protocol: "TCP", sourceIp: "198.51.100.92", destinationIp: "10.0.0.18", sourcePort: 50124, destinationPort: 22, flowDurationMs: 64000, packetsForward: 38, packetsBackward: 14, bytesForward: 9200, bytesBackward: 5800, failedLogins: 18 },
];

function getApiBase() {
  const urlParams = new URLSearchParams(window.location.search);
  const paramUrl = urlParams.get("api");
  if (paramUrl) {
    const clean = paramUrl.replace(/\/+$/, "");
    localStorage.setItem("cybershield_api_url", clean);
    return clean;
  }
  const saved = localStorage.getItem("cybershield_api_url");
  return saved ? saved.replace(/\/+$/, "") : "";
}

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
  const apiBase = getApiBase();
  const url = apiBase ? `${apiBase}${path}` : path;
  const response = await fetch(url, {
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

function setServiceStatus(health, isPreviewFallback = false) {
  const model = health.model || {};
  const modelIsUp = isPreviewFallback ? true : model.status === "UP";
  const previewMode = isPreviewFallback || model.mode === "PREVIEW";
  const dot = $("#api-dot");
  
  if (isPreviewFallback) {
    dot.classList.remove("is-up", "is-down");
    $("#api-status").textContent = "Interactive Demo Mode (Click to set Backend URL)";
    $("#model-status-side").textContent = "Preview model online";
    $("#model-detail-side").textContent = "Backend waking up / offline";
    $(".model-card-foot span:first-child").textContent = "Local heuristic";
    $("#model-note-text").textContent = "Using in-browser sample rules. Connect your live backend via BACKEND_URL or click above.";
    $(".model-meter span").style.width = "88%";
    return;
  }

  dot.classList.remove("is-down");
  dot.classList.add("is-up");
  $("#api-status").textContent = "All services connected & active";
  $("#model-status-side").textContent = "Classifier online";
  const accuracy = Number(model.holdoutAccuracy || 0.96);
  $("#model-detail-side").textContent = model.trainingRows
    ? `${number(model.trainingRows)} verified training rows`
    : "Random forest model active";
  $(".model-card-foot span:first-child").textContent = "Random forest";
  $("#stat-confidence").closest(".stat-card").querySelector(".stat-top > span:first-child").textContent = "Model confidence";
  $(".result-confidence span").textContent = "Model confidence";
  const noteHeader = $("#model-note-header");
  if (noteHeader) noteHeader.textContent = "Intrusion Detection Engine";
  $("#model-note-text").textContent = "Real-time behavioral and signature traffic classification active across all monitored endpoints.";
  $(".model-meter span").style.width = `${Math.round(accuracy * 100)}%`;
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
    isLiveBackend = true;
    setServiceStatus(health, false);
    renderSummary(summary);
    recentEvents = events;
    renderActivity(recentEvents);
    $("#last-updated").textContent = `Last synced ${new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(new Date())}`;
  } catch (error) {
    isLiveBackend = false;
    // Activate resilient in-browser demo fallback so the app is immediately working
    if (recentEvents.length === 0) {
      recentEvents = sampleSeedFlows.map(localSaveAnalysis);
    }
    setServiceStatus({ model: { mode: "PREVIEW", status: "UP" } }, true);
    renderSummary(getLocalSummary());
    renderActivity(recentEvents);
    $("#last-updated").textContent = "Running in interactive demo mode";
  }
}

async function loadDemoData() {
  const button = $("#load-demo-button");
  button.disabled = true;
  try {
    if (isLiveBackend) {
      const added = await requestJson("/api/traffic/demo", { method: "POST" });
      await refreshDashboard();
      showToast(`${added.length} example flows analyzed and saved.`);
    } else {
      sampleSeedFlows.forEach(localSaveAnalysis);
      renderSummary(getLocalSummary());
      renderActivity(recentEvents);
      showToast("4 example flows analyzed (Interactive demo mode).");
    }
  } catch (error) {
    sampleSeedFlows.forEach(localSaveAnalysis);
    renderSummary(getLocalSummary());
    renderActivity(recentEvents);
    showToast("4 example flows analyzed (Interactive demo mode).");
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
    if (isLiveBackend) {
      const result = await requestJson("/api/traffic/analyze", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      showResult(result);
      await refreshDashboard();
      showToast(`${result.category} classification saved to traffic history.`);
    } else {
      const localResult = localSaveAnalysis(payload);
      showResult(localResult);
      renderSummary(getLocalSummary());
      renderActivity(recentEvents);
      showToast(`${localResult.category} classification analyzed (Demo mode).`);
    }
  } catch (error) {
    const localResult = localSaveAnalysis(payload);
    showResult(localResult);
    renderSummary(getLocalSummary());
    renderActivity(recentEvents);
    showToast(`${localResult.category} classification analyzed (Demo mode).`);
  } finally {
    button.disabled = false;
    button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v18M3 12h18"/></svg> Analyze flow';
  }
}

function configureApiUrl() {
  const current = getApiBase() || "Default proxy (/api)";
  const input = prompt(
    "Enter your CyberShield Backend URL on Render:\n(e.g., https://cybershield-backend-xxxx.onrender.com)\n\nLeave empty to use default proxy:",
    getApiBase()
  );
  if (input !== null) {
    const trimmed = input.trim().replace(/\/+$/, "");
    if (trimmed) {
      localStorage.setItem("cybershield_api_url", trimmed);
      showToast(`Backend URL set to: ${trimmed}`);
    } else {
      localStorage.removeItem("cybershield_api_url");
      showToast("Using default proxy URL.");
    }
    refreshDashboard();
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

  const connState = document.querySelector(".connection-state");
  if (connState) {
    connState.style.cursor = "pointer";
    connState.title = "Click to configure Backend URL";
    connState.addEventListener("click", configureApiUrl);
  }

  refreshDashboard();
  // Silently check every 25s so if backend spins up on Render, it automatically connects!
  setInterval(refreshDashboard, 25000);
}

document.addEventListener("DOMContentLoaded", start);
