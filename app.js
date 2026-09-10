const state = {
  scans: JSON.parse(localStorage.getItem("safescan-scans") || "[]"),
  selectedFile: null,
  qrStream: null,
};

const seedScans = [
  { id: "seed-1", type: "url", target: "https://support.google.com/accounts", riskScore: 4, verdict: "low-risk", reputation: "No known threats found", createdAt: new Date(Date.now() - 1000 * 60 * 18).toISOString(), findings: [{ severity: "low", title: "No obvious threats detected", description: "No strong signals found in this scan." }] },
  { id: "seed-2", type: "qr", target: "https://www.example.com/event/tickets", riskScore: 18, verdict: "low-risk", reputation: "No known threats found", createdAt: new Date(Date.now() - 1000 * 60 * 95).toISOString(), findings: [{ severity: "low", title: "No obvious threats detected", description: "No strong signals found in this scan." }] },
  { id: "seed-3", type: "pdf", target: "invoice_march.pdf", riskScore: 26, verdict: "low-risk", reputation: "No known hash match", createdAt: new Date(Date.now() - 1000 * 60 * 60 * 3).toISOString(), sha256: "8d3c…b911", findings: [{ severity: "low", title: "PDF ready for basic analysis", description: "No known hash match in this local scan." }] },
];
if (!state.scans.length) state.scans = seedScans;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const verdictLabel = (verdict) => ({ "low-risk": "Low risk", caution: "Caution", suspicious: "Suspicious", dangerous: "Dangerous" }[verdict] || verdict);
const typeLabel = (type) => ({ url: "Link", qr: "QR code", file: "File", apk: "APK", pdf: "PDF" }[type] || "Scan");
const iconFor = (type) => ({ url: "↗", qr: "⌗", file: "⌁", apk: "⌁", pdf: "▧" }[type] || "•");
const timeAgo = (date) => {
  const minutes = Math.max(1, Math.round((Date.now() - new Date(date).getTime()) / 60000));
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
};
const truncate = (value, length = 42) => value.length > length ? `${value.slice(0, length - 1)}…` : value;

function persist() {
  localStorage.setItem("safescan-scans", JSON.stringify(state.scans.slice(0, 50)));
}

async function hydrateHistory() {
  try {
    const response = await fetch("/v1/scans?limit=20");
    if (!response.ok) return;
    const data = await response.json();
    const remoteScans = Array.isArray(data.scans) ? data.scans : [];
    const known = new Set(state.scans.map((scan) => scan.id));
    state.scans = [...remoteScans.filter((scan) => !known.has(scan.id)), ...state.scans].slice(0, 50);
    persist();
    renderRecent();
    renderHistory();
  } catch {
    // The local history remains usable when the API is unavailable.
  }
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("visible");
  setTimeout(() => toast.classList.remove("visible"), 3200);
}

function navigate(view) {
  $$(".view").forEach((item) => item.classList.toggle("active-view", item.id === `${view}-view`));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (view === "history") renderHistory();
}

$$("[data-view]").forEach((button) => button.addEventListener("click", (event) => {
  event.preventDefault();
  navigate(button.dataset.view);
}));

$$(".scan-tab").forEach((tab) => tab.addEventListener("click", () => {
  $$(".scan-tab").forEach((item) => item.classList.remove("active"));
  tab.classList.add("active");
  $$(".scan-panel").forEach((panel) => panel.classList.remove("active-panel"));
  $(`#${tab.dataset.scanMode}-panel`).classList.add("active-panel");
}));

function renderRecent() {
  const recent = $("#recent-scans");
  recent.innerHTML = state.scans.slice(0, 3).map((scan) => `
    <article class="recent-card" data-scan-id="${scan.id}">
      <div class="recent-top"><span class="scan-type">${typeLabel(scan.type)}</span><span class="verdict-dot ${scan.verdict}"></span></div>
      <h3>${escapeHtml(scan.target)}</h3>
      <p>${escapeHtml(scan.reputation || "Analysis complete")}</p>
      <div class="recent-bottom"><span>${timeAgo(scan.createdAt)}</span><span class="score-chip">${scan.riskScore}/100</span></div>
    </article>`).join("");
  $$(".recent-card").forEach((card) => card.addEventListener("click", () => {
    const scan = state.scans.find((item) => item.id === card.dataset.scanId);
    if (scan) renderResult(scan);
  }));
}

function renderHistory() {
  const query = ($("#history-search")?.value || "").toLowerCase();
  const scans = state.scans.filter((scan) => scan.target.toLowerCase().includes(query));
  $("#history-list").innerHTML = scans.length ? scans.map((scan) => `
    <article class="history-item">
      <div class="type-icon">${iconFor(scan.type)}</div>
      <div class="history-copy"><b>${escapeHtml(scan.target)}</b><small>${typeLabel(scan.type)} · ${timeAgo(scan.createdAt)}${scan.sha256 ? ` · ${escapeHtml(scan.sha256)}` : ""}</small></div>
      <div class="history-result ${scan.verdict}">${verdictLabel(scan.verdict)}</div>
      <div class="history-score">${scan.riskScore}/100</div>
    </article>`).join("") : `<div class="empty-state">No matching scans yet.</div>`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[character]));
}

function renderResult(scan) {
  const colorClass = scan.verdict === "low-risk" ? "low" : scan.verdict;
  const findings = (scan.findings || []).slice(0, 4).map((finding) => `
    <div class="finding"><span class="finding-pin ${finding.severity === "low" ? "low-risk" : finding.severity === "medium" ? "caution" : "dangerous"}"></span><div><b>${escapeHtml(finding.title)}</b><p>${escapeHtml(finding.description)}</p></div></div>`).join("");
  $("#result-area").innerHTML = `
    <article class="result-card">
      <div class="result-head"><div class="result-identity"><div class="result-icon">${iconFor(scan.type)}</div><div><h3>Scan complete</h3><p>${escapeHtml(scan.target)}</p></div></div><div class="result-verdict"><strong>${verdictLabel(scan.verdict)}</strong><small>${escapeHtml(scan.reputation || "Analysis complete")}</small></div></div>
      <div class="result-body"><div class="score-box"><div class="score-label">RISK SCORE</div><div class="score-number">${scan.riskScore}<span>/100</span></div><div class="score-track"><span style="width:${Math.max(4, scan.riskScore)}%;background:${scan.riskScore > 60 ? "var(--red)" : scan.riskScore > 30 ? "var(--amber)" : "var(--green)"}"></span></div><p class="score-caption">${scan.riskScore < 31 ? "No strong signals found. Stay cautious anyway." : "Some signals deserve a closer look before you continue."}</p></div><div><p class="findings-heading">${(scan.findings || []).length} finding${(scan.findings || []).length === 1 ? "" : "s"}</p>${findings}</div></div>
      <div class="result-footer">SafeScan checks signals, not certainty. <button id="dismiss-result">Dismiss</button></div>
    </article>`;
  $("#dismiss-result").addEventListener("click", () => { $("#result-area").innerHTML = ""; });
  $("#result-area").scrollIntoView({ behavior: "smooth", block: "center" });
}

async function scanUrl(url, type = "url") {
  const cleaned = url.trim();
  if (!cleaned || cleaned === "https://") return showToast("Paste a link first.");
  const button = type === "qr" ? $("#scan-qr-btn") : $("#scan-url-btn");
  button.disabled = true;
  button.querySelector("span").textContent = "Analyzing…";
  try {
    const response = await fetch("/v1/scans/url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: cleaned }) });
    if (!response.ok) throw new Error("Could not analyze that link");
    const scan = await response.json();
    scan.type = type;
    state.scans.unshift(scan);
    persist();
    renderRecent();
    renderResult(scan);
    showToast("Scan complete.");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
    button.querySelector("span").textContent = type === "qr" ? "Analyze QR link" : "Scan link";
  }
}

$("#scan-url-btn").addEventListener("click", () => scanUrl($("#url-input").value));
$("#scan-qr-btn").addEventListener("click", () => scanUrl($("#qr-input").value, "qr"));
$("#url-input").addEventListener("keydown", (event) => { if (event.key === "Enter") scanUrl($("#url-input").value); });
$("#history-search").addEventListener("input", renderHistory);

$("#file-input").addEventListener("change", () => {
  const file = $("#file-input").files[0];
  state.selectedFile = file;
  $("#selected-file").classList.toggle("hidden", !file);
  $("#selected-file").innerHTML = file ? `<span>Selected</span> · ${escapeHtml(file.name)} · ${Math.round(file.size / 1024)} KB` : "";
  $("#scan-file-btn").disabled = !file;
});

async function inspectFile(file) {
  const signals = [];
  if (!file || file.type !== "application/pdf" && !file.name.toLowerCase().endsWith(".pdf")) return signals;
  const bytes = new Uint8Array(await file.arrayBuffer());
  const sample = new TextDecoder("latin1").decode(bytes);
  if (/\/JavaScript|\/JS\b/i.test(sample)) signals.push("javascript");
  if (/\/EmbeddedFile|\/Filespec/i.test(sample)) signals.push("embedded-file");
  if (/https?:\/\/[^\s<>()]+/i.test(sample)) signals.push("embedded-url");
  return signals;
}

async function sha256(file) {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

$("#scan-file-btn").addEventListener("click", async () => {
  const file = state.selectedFile;
  if (!file) return;
  const button = $("#scan-file-btn");
  button.disabled = true;
  button.querySelector("span").textContent = "Fingerprinting…";
  try {
    const hash = await sha256(file);
    const signals = await inspectFile(file);
    const response = await fetch("/v1/scans/file", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ fileName: file.name, fileSize: file.size, mimeType: file.type, sha256: hash, signals }) });
    if (!response.ok) throw new Error("Could not analyze that file");
    const scan = await response.json();
    state.scans.unshift(scan);
    persist();
    renderRecent();
    renderResult(scan);
    showToast("File fingerprint created.");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
    button.querySelector("span").textContent = "Scan file";
  }
});

function closeCamera() {
  if (state.qrStream) state.qrStream.getTracks().forEach((track) => track.stop());
  state.qrStream = null;
  $("#camera-video").srcObject = null;
  $("#camera-modal").classList.add("hidden");
  $("#camera-modal").setAttribute("aria-hidden", "true");
}

async function openCamera() {
  if (!("mediaDevices" in navigator) || !navigator.mediaDevices.getUserMedia) {
    return showToast("Camera access is not available in this browser.");
  }
  if (!("BarcodeDetector" in window)) {
    return showToast("Live QR scanning is not supported here. Paste the decoded link instead.");
  }
  try {
    state.qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
    const video = $("#camera-video");
    video.srcObject = state.qrStream;
    $("#camera-modal").classList.remove("hidden");
    $("#camera-modal").setAttribute("aria-hidden", "false");
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    const scanFrame = async () => {
      if (!state.qrStream) return;
      try {
        const codes = await detector.detect(video);
        if (codes.length && codes[0].rawValue) {
          $("#qr-input").value = codes[0].rawValue;
          closeCamera();
          showToast("QR code decoded. Ready to analyze.");
          return;
        }
      } catch {
        // Keep the camera open while a frame is not ready.
      }
      requestAnimationFrame(scanFrame);
    };
    video.addEventListener("loadeddata", () => requestAnimationFrame(scanFrame), { once: true });
  } catch {
    closeCamera();
    showToast("Camera permission was not granted.");
  }
}

$("#open-camera").addEventListener("click", openCamera);
$("#close-camera").addEventListener("click", closeCamera);
$("#camera-modal").addEventListener("click", (event) => { if (event.target.id === "camera-modal") closeCamera(); });

$("#clear-history").addEventListener("click", () => {
  state.scans = [];
  persist();
  renderRecent();
  renderHistory();
  showToast("Scan history deleted.");
});

renderRecent();
renderHistory();
hydrateHistory();
if ("serviceWorker" in navigator) navigator.serviceWorker.register("/service-worker.js").catch(() => {});