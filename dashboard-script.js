/* global chrome */

const STORAGE_KEY = "phishing_dashboard_data";

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function clampNumber(value, min, max, fallback = 0) {
  const numericValue = Number(value);
  if (!Number.isFinite(numericValue)) return fallback;
  return Math.max(min, Math.min(max, numericValue));
}

function getRiskColor(riskScore) {
  if (riskScore >= 80) return "#c62828";
  if (riskScore >= 65) return "#e5484d";
  if (riskScore >= 45) return "#c76a12";
  if (riskScore >= 30) return "#d89500";
  return "#16803c";
}

function getRiskLevel(riskScore) {
  if (riskScore >= 80) return "High Risk";
  if (riskScore >= 65) return "Elevated Risk";
  if (riskScore >= 45) return "Medium Risk";
  if (riskScore >= 30) return "Low-Medium Risk";
  return "Low Risk";
}

function getVerdictLabel(verdict) {
  if (verdict === "phishing") return "Phishing";
  if (verdict === "suspicious") return "Suspicious";
  if (verdict === "safe") return "Safe";
  return "Unknown";
}

function getVerdictClass(verdict) {
  if (verdict === "phishing") return "phishing";
  if (verdict === "suspicious") return "suspicious";
  if (verdict === "safe") return "safe";
  return "";
}

function getDefaultData() {
  return {
    currentStats: {
      totalSitesScanned: 0,
      suspiciousSites: 0,
      confirmedPhishing: 0,
      falsePositives: 0,
      lastScanTime: ""
    },
    detectedSites: [],
    riskHistory: [],
    categoryStats: [
      { category: "Banking", count: 0, avgRisk: 0 },
      { category: "Payment", count: 0, avgRisk: 0 },
      { category: "Tech Support", count: 0, avgRisk: 0 },
      { category: "Social Media", count: 0, avgRisk: 0 },
      { category: "Email", count: 0, avgRisk: 0 },
      { category: "Delivery", count: 0, avgRisk: 0 },
      { category: "Other", count: 0, avgRisk: 0 }
    ]
  };
}

function normalizeData(data) {
  const defaults = getDefaultData();
  const nextData = data || defaults;

  nextData.currentStats = {
    ...defaults.currentStats,
    ...(nextData.currentStats || {})
  };
  nextData.detectedSites = Array.isArray(nextData.detectedSites) ? nextData.detectedSites : [];
  nextData.riskHistory = Array.isArray(nextData.riskHistory) ? nextData.riskHistory : [];
  nextData.categoryStats = Array.isArray(nextData.categoryStats) && nextData.categoryStats.length
    ? nextData.categoryStats
    : defaults.categoryStats;

  for (const category of defaults.categoryStats) {
    if (!nextData.categoryStats.some((item) => item.category === category.category)) {
      nextData.categoryStats.push({ ...category });
    }
  }

  return nextData;
}

function formatTime(value) {
  if (!value) return "No scans yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "No scans yet";
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function formatFullTime(value) {
  if (!value) return "No scans yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "No scans yet";
  return date.toLocaleString();
}

function getSiteVerdict(site) {
  if (site.verdict) return site.verdict;
  if (site.isPhishing) return "phishing";
  if (site.isSuspicious || site.isUnsafe) return "suspicious";
  return "safe";
}

function getSiteRisk(site) {
  return Math.round(clampNumber(site.riskScore ?? site.probability, 0, 100, 0));
}

function calculateStats(data) {
  const detectedSites = data.detectedSites || [];
  const totalSitesScanned = Number(data.currentStats.totalSitesScanned || detectedSites.length || 0);
  const phishing = Number(data.currentStats.confirmedPhishing || 0);
  const suspicious = Number(data.currentStats.suspiciousSites || 0);
  const safe = Math.max(0, totalSitesScanned - phishing - suspicious);
  const averageRisk = detectedSites.length
    ? Math.round(detectedSites.reduce((sum, site) => sum + getSiteRisk(site), 0) / detectedSites.length)
    : 0;

  return {
    totalSitesScanned,
    safe,
    suspicious,
    phishing,
    averageRisk,
    lastScanTime: data.currentStats.lastScanTime
  };
}

function percent(value, total) {
  if (!total) return 0;
  return Math.round((value / total) * 100);
}

function createStorageGet(keys) {
  return new Promise((resolve) => {
    if (typeof chrome === "undefined" || !chrome.storage) {
      resolve({});
      return;
    }
    chrome.storage.local.get(keys, (result) => resolve(result || {}));
  });
}

function createStorageSet(values) {
  return new Promise((resolve, reject) => {
    if (typeof chrome === "undefined" || !chrome.storage) {
      resolve();
      return;
    }
    chrome.storage.local.set(values, () => {
      const error = chrome.runtime && chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve();
    });
  });
}

class PhishingDashboard {
  constructor() {
    this.data = normalizeData(null);
    this.loading = true;
    this.toastTimer = null;
    this.init();
  }

  async init() {
    await this.loadData();
    this.render();
    this.setupStorageListener();
  }

  async loadData() {
    const result = await createStorageGet([STORAGE_KEY]);
    this.data = normalizeData(result[STORAGE_KEY]);
    this.loading = false;
  }

  render() {
    const root = document.getElementById("root");

    if (this.loading) {
      root.innerHTML = '<div class="loading">Loading Dashboard...</div>';
      return;
    }

    const stats = calculateStats(this.data);
    const riskColor = getRiskColor(stats.averageRisk);
    root.innerHTML = `
      <main class="dashboard-shell">
        <header class="dashboard-topbar">
          <div class="dashboard-title">
            <h1>Site Detection Dashboard</h1>
            <p>Gemini phishing verdicts, risk history, and recent site analyses.</p>
          </div>
          <div class="dashboard-actions" aria-label="Dashboard actions">
            <button id="refreshBtn" class="btn" type="button">Refresh</button>
            <button id="exportBtn" class="btn secondary" type="button">Export JSON</button>
            <button id="clearBtn" class="btn danger" type="button">Clear Data</button>
          </div>
        </header>

        <section class="status-strip" aria-label="Scan totals">
          ${this.renderMetricCard("Sites Scanned", stats.totalSitesScanned.toLocaleString(), `Last scan: ${escapeHtml(formatTime(stats.lastScanTime))}`, "primary")}
          ${this.renderMetricCard("Safe", stats.safe.toLocaleString(), `${percent(stats.safe, stats.totalSitesScanned)}% of scans`, "safe")}
          ${this.renderMetricCard("Suspicious", stats.suspicious.toLocaleString(), "Needs caution", "suspicious")}
          ${this.renderMetricCard("Phishing", stats.phishing.toLocaleString(), "High-risk verdicts", "phishing")}
        </section>

        <div class="content-grid">
          <div>
            <section class="section">
              <div class="section-header">
                <h2 class="section-title">Risk Overview</h2>
                <span class="section-subtitle">${escapeHtml(getRiskLevel(stats.averageRisk))}</span>
              </div>
              <div class="section-body">
                <div class="risk-overview" style="--risk-color: ${riskColor}; --risk-score: ${stats.averageRisk};">
                  <div class="risk-gauge" aria-label="Average risk ${stats.averageRisk} percent">
                    <div class="risk-gauge-inner">
                      <span class="risk-score">${stats.averageRisk}%</span>
                      <span class="risk-label">Average Risk</span>
                    </div>
                  </div>
                  <div class="verdict-mix">
                    ${this.renderMixRow("Safe", stats.safe, stats.totalSitesScanned, "#16803c")}
                    ${this.renderMixRow("Suspicious", stats.suspicious, stats.totalSitesScanned, "#c76a12")}
                    ${this.renderMixRow("Phishing", stats.phishing, stats.totalSitesScanned, "#c62828")}
                  </div>
                </div>
              </div>
            </section>

            <section class="section">
              <div class="section-header">
                <h2 class="section-title">Risk History</h2>
                <span class="section-subtitle">Last 5 cycles</span>
              </div>
              <div class="section-body">
                ${this.renderRiskHistory(this.data.riskHistory)}
              </div>
            </section>

            <section class="section">
              <div class="section-header">
                <h2 class="section-title">Recent Analyses</h2>
                <span class="section-subtitle">${Math.min(this.data.detectedSites.length, 12)} shown</span>
              </div>
              <div class="section-body">
                ${this.renderDetectedSites(this.data.detectedSites)}
              </div>
            </section>
          </div>

          <aside>
            <section class="section">
              <div class="section-header">
                <h2 class="section-title">Risk by Category</h2>
                <span class="section-subtitle">Average risk</span>
              </div>
              <div class="section-body">
                ${this.renderCategories(this.data.categoryStats)}
              </div>
            </section>
          </aside>
        </div>
      </main>
    `;

    this.bindActionButtons();
  }

  renderMetricCard(label, value, note, tone) {
    const toneClass = ["safe", "suspicious", "phishing"].includes(tone) ? tone : "";
    const cardClass = tone === "primary" ? "metric-card primary" : "metric-card";
    return `
      <article class="${cardClass}">
        <div class="metric-label">${escapeHtml(label)}</div>
        <div class="metric-value ${toneClass}">${escapeHtml(value)}</div>
        <div class="metric-note">${note}</div>
      </article>
    `;
  }

  renderMixRow(label, value, total, color) {
    const width = percent(value, total);
    return `
      <div class="mix-row">
        <span>${escapeHtml(label)}</span>
        <div class="mix-track">
          <div class="mix-fill" style="--width: ${width}%; --color: ${color};"></div>
        </div>
        <strong>${width}%</strong>
      </div>
    `;
  }

  renderRiskHistory(riskHistory) {
    if (!riskHistory.length) {
      return '<div class="empty-state">No risk history yet.</div>';
    }

    return `
      <div class="trend-chart">
        ${riskHistory.slice(0, 5).map((cycle, index) => {
          const overallRisk = Math.round(clampNumber(cycle.overallRisk, 0, 100, 0));
          const height = Math.max(18, Math.round((overallRisk / 100) * 170));
          return `
            <div class="trend-item">
              <div class="trend-bar-wrap">
                <div class="trend-bar" style="height: ${height}px; --bar-color: ${getRiskColor(overallRisk)};">
                  ${overallRisk}%
                </div>
              </div>
              <div class="trend-meta">
                <strong>${escapeHtml(cycle.cycle || `Cycle ${index + 1}`)}</strong><br>
                ${Number(cycle.threats || 0)} warnings / ${Number(cycle.sitesScanned || 0)} scans
              </div>
            </div>
          `;
        }).join("")}
      </div>
    `;
  }

  renderDetectedSites(detectedSites) {
    if (!detectedSites.length) {
      return '<div class="empty-state">No analyses yet. Visit a website or run a manual scan.</div>';
    }

    return `
      <div class="analysis-list">
        ${detectedSites.slice(0, 12).map((site) => this.renderAnalysisItem(site)).join("")}
      </div>
    `;
  }

  renderAnalysisItem(site) {
    const url = String(site.url || "");
    const displayUrl = url.length > 92 ? `${url.slice(0, 89)}...` : url;
    const verdict = getSiteVerdict(site);
    const riskScore = getSiteRisk(site);
    const confidence = Math.round(clampNumber(site.confidence, 0, 100, 0));

    return `
      <article class="analysis-item" style="--risk-color: ${getRiskColor(riskScore)};">
        <div>
          <div class="site-url" title="${escapeHtml(url)}">${escapeHtml(displayUrl)}</div>
          <div class="site-summary">${escapeHtml(site.summary || site.result || "No summary recorded.")}</div>
          <div class="site-meta">
            <span class="pill ${getVerdictClass(verdict)}">${escapeHtml(getVerdictLabel(verdict))}</span>
            <span class="pill">${escapeHtml(site.category || "Other")}</span>
            <span>${escapeHtml(formatFullTime(site.timestamp || site.detectedAt))}</span>
            <span>${escapeHtml(site.model || site.engine || "Gemini")}</span>
          </div>
        </div>
        <div class="risk-stack">
          <span class="risk-number">${riskScore}%</span>
          <span>${confidence}% confidence</span>
        </div>
      </article>
    `;
  }

  renderCategories(categoryStats) {
    const activeCategories = categoryStats
      .map((category) => ({
        category: category.category,
        count: Number(category.count || 0),
        avgRisk: Math.round(clampNumber(category.avgRisk, 0, 100, 0))
      }))
      .sort((a, b) => b.count - a.count || b.avgRisk - a.avgRisk);

    if (!activeCategories.some((category) => category.count > 0)) {
      return '<div class="empty-state">No category data yet.</div>';
    }

    return `
      <div class="category-list">
        ${activeCategories.map((category) => `
          <div class="category-row">
            <div class="category-meta">
              <span>${escapeHtml(category.category)}</span>
              <span>${category.count} scans · ${category.avgRisk}%</span>
            </div>
            <div class="category-track">
              <div class="category-fill" style="--width: ${Math.max(4, category.avgRisk)}%; --color: ${getRiskColor(category.avgRisk)};"></div>
            </div>
          </div>
        `).join("")}
      </div>
    `;
  }

  bindActionButtons() {
    document.getElementById("refreshBtn")?.addEventListener("click", () => {
      this.refreshData();
    });

    document.getElementById("exportBtn")?.addEventListener("click", () => {
      this.exportData();
    });

    document.getElementById("clearBtn")?.addEventListener("click", () => {
      this.clearData();
    });
  }

  setupStorageListener() {
    if (typeof chrome !== "undefined" && chrome.storage) {
      chrome.storage.onChanged.addListener((changes) => {
        if (changes[STORAGE_KEY]) {
          this.data = normalizeData(changes[STORAGE_KEY].newValue);
          this.render();
        }
      });
    }
  }

  async refreshData(options = {}) {
    await this.loadData();
    this.render();
    if (!options.silent) {
      this.showToast("Dashboard refreshed.");
    }
  }

  exportData() {
    try {
      const dataStr = JSON.stringify(this.data, null, 2);
      const blob = new Blob([dataStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `phishing-analysis-${new Date().toISOString().split("T")[0]}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      this.showToast("Dashboard data exported.");
    } catch (error) {
      this.showToast(`Export failed: ${error.message}`, "error");
    }
  }

  async clearData() {
    if (!confirm("Clear all phishing analysis data?")) return;

    try {
      this.data = getDefaultData();
      await createStorageSet({ [STORAGE_KEY]: this.data });
      this.render();
      this.showToast("Dashboard data cleared.");
    } catch (error) {
      this.showToast(`Clear failed: ${error.message}`, "error");
    }
  }

  showToast(message, type = "") {
    const toast = document.getElementById("toast");
    if (!toast) return;

    toast.textContent = message;
    toast.className = `toast visible ${type}`.trim();

    window.clearTimeout(this.toastTimer);
    this.toastTimer = window.setTimeout(() => {
      toast.className = "toast";
    }, 2600);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  window.dashboard = new PhishingDashboard();
});

document.addEventListener("visibilitychange", () => {
  if (!document.hidden && window.dashboard) {
    window.dashboard.refreshData({ silent: true });
  }
});
