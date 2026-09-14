const state = {
  email: localStorage.getItem("wvhEmail") || "demo@wvh.local",
  attemptId: localStorage.getItem("wvhAttemptId") || "",
  currentAttempt: null,
};

const steps = [
  "Collecting login context",
  "Checking historical behavior",
  "Evaluating risk signals",
  "Calculating risk score",
  "Selecting authentication level",
];

const $ = (selector) => document.querySelector(selector);

function levelClass(level) {
  return String(level || "").toLowerCase();
}

function riskColor(level) {
  if (level === "LOW") return "#16a34a";
  if (level === "MEDIUM") return "#d97706";
  if (level === "HIGH") return "#dc2626";
  return "#2563eb";
}

function switchView(route) {
  document.querySelectorAll(".view").forEach((view) => view.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.route === route));
  $(`#${route}View`).classList.add("active");
  if (route === "dashboard") loadDashboard();
}

function getBrowserContext() {
  const ua = navigator.userAgent;
  const low = ua.toLowerCase();
  const browser = low.includes("edg/") ? "Edge" : low.includes("firefox/") ? "Firefox" : low.includes("safari/") && !low.includes("chrome/") ? "Safari" : low.includes("chrome/") ? "Chrome" : "Unknown";
  const os = low.includes("windows") ? "Windows" : low.includes("mac") ? "MacOS" : low.includes("android") ? "Android" : low.includes("iphone") || low.includes("ipad") ? "iOS" : low.includes("linux") ? "Linux" : "Unknown";
  const device = low.includes("android") ? "Android-Phone" : low.includes("iphone") ? "iPhone" : low.includes("ipad") ? "iPad" : os === "Windows" ? "Windows-Laptop" : os === "MacOS" ? "MacBook" : os === "Linux" ? "Linux-Laptop" : "Unknown Device";
  return { browser, os, device, deviceType: os };
}

function collectContext() {
  return {
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language,
    platform: navigator.platform,
    browserContext: getBrowserContext(),
    screen: { width: window.screen.width, height: window.screen.height },
  };
}

function renderSteps(activeCount = 0) {
  $("#analysisSteps").innerHTML = steps.map((step, index) => `
    <div class="step ${index < activeCount ? "done" : ""}">
      <span class="dot"></span>
      <span>${step}</span>
    </div>
  `).join("");
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function playAnalysis() {
  $("#analysisTitle").textContent = "Analyzing Login...";
  $("#spinner").classList.add("active");
  $("#decisionArea").innerHTML = "";
  for (let i = 1; i <= steps.length; i += 1) {
    renderSteps(i);
    await delay(360);
  }
  $("#spinner").classList.remove("active");
}

function metricGrid(attempt) {
  return `
    <div class="metrics">
      <div class="metric"><span>Risk Score</span><strong>${attempt.riskScore} / 100</strong></div>
      <div class="metric"><span>Risk Level</span><strong>${attempt.riskLevel}</strong></div>
      <div class="metric"><span>Decision</span><strong>${attempt.decision}</strong></div>
    </div>
  `;
}

function renderDecision(result) {
  const attempt = result.attempt;
  const level = levelClass(attempt.riskLevel);
  $("#analysisTitle").textContent = "Risk-Based Decision";
  $("#engineStatus").textContent = `Score ${attempt.riskScore} / 100`;
  localStorage.setItem("wvhEmail", attempt.email);
  localStorage.setItem("wvhAttemptId", attempt.attemptId);
  state.email = attempt.email;
  state.attemptId = attempt.attemptId;
  state.currentAttempt = attempt;

  if (result.decisionStatus === "SUCCESS") {
    $("#decisionArea").innerHTML = `
      <div class="result-card ${level}">
        <h2>Login Successful</h2>
        ${metricGrid(attempt)}
        <p>Password authentication is sufficient for this low-risk attempt.</p>
        <div class="actions"><button class="primary" id="dashboardButton">Go to Dashboard</button></div>
      </div>
    `;
    $("#dashboardButton").addEventListener("click", () => switchView("dashboard"));
    return;
  }

  if (result.decisionStatus === "FAILED") {
    $("#decisionArea").innerHTML = `
      <div class="result-card failed">
        <h2>Authentication Failed</h2>
        ${metricGrid(attempt)}
        <p>${attempt.message}</p>
        <div class="actions"><button class="secondary" id="tryAgain">Try Again</button></div>
      </div>
    `;
    $("#tryAgain").addEventListener("click", resetLogin);
    return;
  }

  if (result.decisionStatus === "OTP_REQUIRED") {
    $("#decisionArea").innerHTML = `
      <div class="result-card ${level}">
        <h2>OTP Verification Required</h2>
        ${metricGrid(attempt)}
        <p>Additional verification is required. Prototype OTP: <strong>${attempt.simulatedOtp}</strong></p>
        <form id="otpForm" class="form">
          <label><span>One-Time Password</span><input id="otp" inputmode="numeric" autocomplete="one-time-code" required /></label>
          <button class="primary" type="submit">Verify OTP</button>
        </form>
        <p class="form-error" id="otpError"></p>
      </div>
    `;
    $("#otpForm").addEventListener("submit", verifyOtp);
    return;
  }

  $("#decisionArea").innerHTML = `
    <div class="result-card high">
      <h2>Suspicious Login Detected</h2>
      ${metricGrid(attempt)}
      <p>Major signals: ${attempt.riskReasons.join(", ")}</p>
      <div class="actions">
        <button class="danger" id="tryAgain">Try Again</button>
        <button class="secondary" id="dashboardButton">Go to Dashboard</button>
      </div>
    </div>
  `;
  $("#tryAgain").addEventListener("click", resetLogin);
  $("#dashboardButton").addEventListener("click", () => switchView("dashboard"));
}

async function submitLogin(event) {
  event.preventDefault();
  $("#loginError").textContent = "";
  const email = $("#email").value.trim();
  const password = $("#password").value;
  await playAnalysis();
  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, context: collectContext() }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Login failed.");
    renderDecision(result);
  } catch (error) {
    $("#loginError").textContent = error.message;
    $("#analysisTitle").textContent = "Waiting for login";
    renderSteps(0);
  }
}

async function verifyOtp(event) {
  event.preventDefault();
  $("#otpError").textContent = "";
  try {
    const response = await fetch("/api/verify-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ attemptId: state.attemptId, otp: $("#otp").value.trim() }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "OTP verification failed.");
    state.currentAttempt = result.attempt;
    $("#decisionArea").innerHTML = `
      <div class="result-card ${levelClass(result.attempt.riskLevel)}">
        <h2>Login Successful</h2>
        ${metricGrid(result.attempt)}
        <p>User: <strong>${result.attempt.email}</strong></p>
        <p>Authentication method used: <strong>Password + OTP</strong></p>
        <div class="actions"><button class="primary" id="dashboardButton">Go to Dashboard</button></div>
      </div>
    `;
    $("#dashboardButton").addEventListener("click", () => switchView("dashboard"));
  } catch (error) {
    $("#otpError").textContent = error.message;
  }
}

function resetLogin() {
  $("#analysisTitle").textContent = "Waiting for login";
  $("#decisionArea").innerHTML = "";
  renderSteps(0);
  $("#password").focus();
}

function formatTime(value) {
  if (!value) return "Unavailable";
  const date = new Date(String(value).replace(" ", "T") + "Z");
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function renderCurrent(attempt) {
  const score = attempt ? Number(attempt.riskScore) : 0;
  const level = attempt ? attempt.riskLevel : "";
  $("#scoreValue").textContent = attempt ? Math.round(score) : "--";
  $("#scoreRing").style.setProperty("--score", `${score}%`);
  $("#scoreRing").style.setProperty("--score-color", riskColor(level));
  $("#riskLevel").textContent = attempt ? `${level} Risk` : "No attempt";
  $("#decisionText").textContent = attempt ? `${attempt.decision} — ${attempt.authenticationStatus}` : "Run a login simulation to populate the dashboard.";

  $("#currentDetails").innerHTML = attempt ? `
    <p class="eyebrow">Context</p>
    <div class="kv">
      <div><span>User</span><strong>${attempt.email}</strong></div>
      <div><span>Login Time</span><strong>${formatTime(attempt.loginTime)}</strong></div>
      <div><span>Device</span><strong>${attempt.device}</strong></div>
      <div><span>Browser / OS</span><strong>${attempt.browser} / ${attempt.os}</strong></div>
      <div><span>IP</span><strong>${attempt.ipAddress}</strong></div>
      <div><span>Location</span><strong>${attempt.country}</strong></div>
    </div>
  ` : `<p class="eyebrow">Context</p><p>No current login attempt yet.</p>`;

  const copy = level === "LOW" ? "Password Only — Low risk detected." : level === "MEDIUM" ? "Password + OTP — Additional verification required." : level === "HIGH" ? "High Risk — Login blocked / strong verification required." : "Authentication decision pending.";
  $("#authDecision").innerHTML = `
    <p class="eyebrow">Authentication Decision</p>
    <p class="decision-copy">${copy}</p>
    <p>${attempt ? attempt.message : "The backend risk engine will provide the decision after login."}</p>
  `;
}

function renderSignals(signals = []) {
  $("#signalsBody").innerHTML = signals.map((row) => `
    <tr>
      <td>${row.signal}</td>
      <td>${row.observedValue}</td>
      <td><span class="impact ${levelClass(row.impact)}">${row.impact}</span></td>
    </tr>
  `).join("") || `<tr><td colspan="3">No signal data available.</td></tr>`;
}

function renderHistory(history = []) {
  $("#historyBody").innerHTML = history.map((row) => `
    <tr>
      <td>${formatTime(row.time)}</td>
      <td>${row.user}</td>
      <td>${row.location}</td>
      <td>${row.device}</td>
      <td>${row.riskScore}</td>
      <td><span class="level ${levelClass(row.riskLevel)}">${row.riskLevel}</span></td>
      <td>${row.decision}</td>
      <td>${row.status}</td>
    </tr>
  `).join("") || `<tr><td colspan="8">No history available.</td></tr>`;
}

function drawTrend(points = []) {
  const canvas = $("#trendChart");
  const context = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  context.clearRect(0, 0, width, height);
  context.strokeStyle = "#e5eaf2";
  context.lineWidth = 1;
  context.font = "12px system-ui";
  context.fillStyle = "#667085";
  [0, 25, 50, 75, 100].forEach((tick) => {
    const y = height - 28 - (tick / 100) * (height - 56);
    context.beginPath();
    context.moveTo(42, y);
    context.lineTo(width - 18, y);
    context.stroke();
    context.fillText(String(tick), 12, y + 4);
  });
  if (points.length === 0) return;
  const plotWidth = width - 70;
  const plotHeight = height - 56;
  const coords = points.map((point, index) => ({
    x: 42 + (index / Math.max(points.length - 1, 1)) * plotWidth,
    y: height - 28 - (Number(point.score) / 100) * plotHeight,
  }));
  context.strokeStyle = "#2563eb";
  context.lineWidth = 3;
  context.beginPath();
  coords.forEach((point, index) => {
    if (index === 0) context.moveTo(point.x, point.y);
    else context.lineTo(point.x, point.y);
  });
  context.stroke();
  coords.forEach((point) => {
    context.fillStyle = "#ffffff";
    context.strokeStyle = "#2563eb";
    context.lineWidth = 3;
    context.beginPath();
    context.arc(point.x, point.y, 5, 0, Math.PI * 2);
    context.fill();
    context.stroke();
  });
}

function renderSummary(summary) {
  $("#summaryPanel").innerHTML = `
    <p class="eyebrow">User Risk Summary</p>
    <h2>Historical Statistics</h2>
    <div class="summary-grid">
      <div class="summary-stat"><span>Average Risk</span><strong>${summary.averageRiskScore}</strong></div>
      <div class="summary-stat"><span>Attempts</span><strong>${summary.recentAttempts}</strong></div>
      <div class="summary-stat"><span>Low / Medium / High</span><strong>${summary.lowCount} / ${summary.mediumCount} / ${summary.highCount}</strong></div>
      <div class="summary-stat"><span>Known Devices</span><strong>${summary.knownDevices.join(", ") || "None"}</strong></div>
      <div class="summary-stat"><span>Common Locations</span><strong>${summary.commonLocations.join(", ") || "None"}</strong></div>
    </div>
  `;
}

function renderInsights(insights = []) {
  $("#insightsPanel").innerHTML = `
    <p class="eyebrow">Security Insights</p>
    <h2>Contextual Findings</h2>
    <div class="insight-list">
      ${(insights.length ? insights : ["No supported anomaly insights for the current history."]).map((insight) => `<div class="insight">${insight}</div>`).join("")}
    </div>
  `;
}

async function loadDashboard() {
  const params = new URLSearchParams({ email: state.email || "demo@wvh.local" });
  if (state.attemptId) params.set("attemptId", state.attemptId);
  const response = await fetch(`/api/dashboard?${params.toString()}`);
  const data = await response.json();
  state.currentAttempt = data.currentAttempt;
  renderCurrent(data.currentAttempt);
  renderSignals(data.currentAttempt?.signals || []);
  renderHistory(data.history || []);
  drawTrend(data.trend || []);
  renderSummary(data.summary || {});
  renderInsights(data.insights || []);
}

document.querySelectorAll(".nav-item").forEach((item) => {
  item.addEventListener("click", () => switchView(item.dataset.route));
});

$("#email").value = state.email;
$("#loginForm").addEventListener("submit", submitLogin);
renderSteps(0);
loadDashboard().catch(() => {});
