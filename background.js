/* global chrome, GeminiPhishing */

importScripts("gemini-client.js");

const STORAGE_KEY = "phishing_dashboard_data";
const analysisResults = new Map();

function getDefaultDashboardData() {
  return {
    currentStats: {
      totalSitesScanned: 0,
      suspiciousSites: 0,
      confirmedPhishing: 0,
      falsePositives: 0,
      lastScanTime: new Date().toISOString()
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

function initializeDashboardData() {
  chrome.storage.local.get([STORAGE_KEY], (result) => {
    if (!result[STORAGE_KEY]) {
      chrome.storage.local.set({ [STORAGE_KEY]: getDefaultDashboardData() });
    }
  });
}

function ensureDashboardShape(data) {
  const nextData = data || getDefaultDashboardData();
  const defaults = getDefaultDashboardData();

  nextData.currentStats = {
    ...defaults.currentStats,
    ...(nextData.currentStats || {})
  };
  nextData.detectedSites = Array.isArray(nextData.detectedSites) ? nextData.detectedSites : [];
  nextData.riskHistory = Array.isArray(nextData.riskHistory) ? nextData.riskHistory : [];
  nextData.categoryStats = Array.isArray(nextData.categoryStats) && nextData.categoryStats.length
    ? nextData.categoryStats
    : defaults.categoryStats;

  for (const defaultCategory of defaults.categoryStats) {
    if (!nextData.categoryStats.some((item) => item.category === defaultCategory.category)) {
      nextData.categoryStats.push({ ...defaultCategory });
    }
  }

  return nextData;
}

function getCategoryFromUrl(url) {
  const urlLower = String(url || "").toLowerCase();

  if (urlLower.includes("bank") || urlLower.includes("login") || urlLower.includes("account")) {
    return "Banking";
  }
  if (urlLower.includes("pay") || urlLower.includes("payment") || urlLower.includes("paypal")) {
    return "Payment";
  }
  if (urlLower.includes("support") || urlLower.includes("help") || urlLower.includes("tech")) {
    return "Tech Support";
  }
  if (
    urlLower.includes("social") ||
    urlLower.includes("facebook") ||
    urlLower.includes("instagram") ||
    urlLower.includes("twitter") ||
    urlLower.includes("x.com")
  ) {
    return "Social Media";
  }
  if (urlLower.includes("email") || urlLower.includes("mail") || urlLower.includes("newsletter")) {
    return "Email";
  }
  if (urlLower.includes("delivery") || urlLower.includes("shipping") || urlLower.includes("track")) {
    return "Delivery";
  }
  return "Other";
}

function notifyDashboard(analysis) {
  try {
    chrome.runtime.sendMessage({ type: "NEW_ANALYSIS", analysis }, () => {
      void chrome.runtime.lastError;
    });
  } catch {
    // The dashboard may not be open.
  }
}

function saveAnalysisData(url, analysis) {
  if (!analysis || analysis.status !== "success") return;

  const riskScore = Number.isFinite(Number(analysis.riskScore))
    ? Number(analysis.riskScore)
    : Number(analysis.probability || 0);
  const category = getCategoryFromUrl(url);
  const analysisData = {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    url,
    result: GeminiPhishing.formatAnalysisText(analysis),
    verdict: analysis.verdict,
    isPhishing: analysis.verdict === "phishing",
    isSuspicious: analysis.verdict === "suspicious",
    isUnsafe: analysis.verdict !== "safe",
    probability: riskScore,
    riskScore,
    confidence: analysis.confidence,
    summary: analysis.summary,
    reasons: analysis.reasons || [],
    recommendedAction: analysis.recommendedAction,
    engine: analysis.engine,
    model: analysis.model,
    category,
    timestamp: analysis.analyzedAt || new Date().toISOString(),
    date: new Date().toISOString().split("T")[0]
  };

  chrome.storage.local.get([STORAGE_KEY], (result) => {
    const data = ensureDashboardShape(result[STORAGE_KEY]);

    data.currentStats.totalSitesScanned += 1;
    if (analysis.verdict === "phishing") {
      data.currentStats.confirmedPhishing += 1;
    } else if (analysis.verdict === "suspicious") {
      data.currentStats.suspiciousSites += 1;
    }
    data.currentStats.lastScanTime = new Date().toISOString();

    data.detectedSites.unshift(analysisData);
    data.detectedSites = data.detectedSites.slice(0, 50);

    const today = new Date().toISOString().split("T")[0];
    const existingEntry = data.riskHistory.find((entry) => entry.date === today);

    if (existingEntry) {
      existingEntry.sitesScanned += 1;
      if (analysis.verdict !== "safe") existingEntry.threats += 1;
      existingEntry.overallRisk = Math.round(
        (existingEntry.threats / Math.max(existingEntry.sitesScanned, 1)) * 100
      );
    } else {
      data.riskHistory.unshift({
        date: today,
        cycle: `Cycle ${data.riskHistory.length + 1}`,
        sitesScanned: 1,
        threats: analysis.verdict !== "safe" ? 1 : 0,
        overallRisk: analysis.verdict !== "safe" ? 100 : 0
      });
    }

    data.riskHistory = data.riskHistory.slice(0, 20);

    const categoryEntry = data.categoryStats.find((item) => item.category === category);
    if (categoryEntry) {
      const previousCount = categoryEntry.count || 0;
      categoryEntry.count = previousCount + 1;
      categoryEntry.avgRisk = Math.round(
        ((categoryEntry.avgRisk || 0) * previousCount + riskScore) / categoryEntry.count
      );
    }

    chrome.storage.local.set({ [STORAGE_KEY]: data }, () => notifyDashboard(analysisData));
  });
}

function buildErrorAnalysis(url, error) {
  const message = error && error.message ? error.message : "Analysis failed.";
  const setupRequired = message.toLowerCase().includes("api key");

  return {
    status: setupRequired ? "setup_required" : "error",
    engine: "gemini",
    model: GeminiPhishing.DEFAULT_MODEL,
    url,
    verdict: "unknown",
    riskScore: 0,
    probability: 0,
    confidence: 0,
    summary: message,
    reasons: [],
    recommendedAction: setupRequired
      ? "Open the extension popup and save your Gemini API key."
      : "Try again or verify your Gemini API key and network connection.",
    isPhishing: false,
    isSuspicious: false,
    isUnsafe: false,
    analyzedAt: new Date().toISOString()
  };
}

async function analyzeUrl(url, pageContext = {}, options = {}) {
  if (!GeminiPhishing.isSupportedUrl(url)) return null;

  const cacheKey = GeminiPhishing.normalizeUrl(url);
  if (!options.force && analysisResults.has(cacheKey)) {
    return analysisResults.get(cacheKey);
  }

  try {
    const analysis = await GeminiPhishing.analyzeUrl(url, pageContext);
    analysisResults.set(cacheKey, analysis);
    saveAnalysisData(url, analysis);
    return analysis;
  } catch (error) {
    console.error("[Background] Gemini analysis failed:", error);
    const fallback = buildErrorAnalysis(url, error);
    if (fallback.status !== "setup_required") {
      analysisResults.set(cacheKey, fallback);
    }
    return fallback;
  }
}

function sendAnalysisToTab(tabId, url, analysis) {
  if (!analysis) return;

  chrome.tabs.sendMessage(
    tabId,
    {
      type: "PHISHING_ANALYSIS",
      url,
      analysis,
      result: GeminiPhishing.formatAnalysisText(analysis)
    },
    () => {
      void chrome.runtime.lastError;
    }
  );
}

function requestContentAnalysis(tabId) {
  chrome.tabs.sendMessage(tabId, { type: "RUN_PHISHING_ANALYSIS" }, () => {
    void chrome.runtime.lastError;
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && GeminiPhishing.isSupportedUrl(tab.url)) {
    requestContentAnalysis(tabId);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (!tab.url || !GeminiPhishing.isSupportedUrl(tab.url)) return;

    const cacheKey = GeminiPhishing.normalizeUrl(tab.url);
    if (analysisResults.has(cacheKey)) {
      sendAnalysisToTab(activeInfo.tabId, tab.url, analysisResults.get(cacheKey));
    } else {
      requestContentAnalysis(activeInfo.tabId);
    }
  } catch (error) {
    console.error("[Background] Tab activation analysis failed:", error);
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "ANALYZE_URL") {
    analyzeUrl(request.url, request.pageContext || {}, { force: Boolean(request.force) })
      .then((analysis) => {
        if (sender.tab && sender.tab.id !== undefined) {
          sendAnalysisToTab(sender.tab.id, request.url, analysis);
        }
        sendResponse({
          analysis,
          result: GeminiPhishing.formatAnalysisText(analysis)
        });
      })
      .catch((error) => {
        const analysis = buildErrorAnalysis(request.url, error);
        sendResponse({
          analysis,
          error: error.message,
          result: GeminiPhishing.formatAnalysisText(analysis)
        });
      });
    return true;
  }

  if (request.type === "GET_CACHED_ANALYSIS") {
    const cacheKey = GeminiPhishing.normalizeUrl(request.url);
    const analysis = analysisResults.get(cacheKey) || null;
    sendResponse({
      analysis,
      result: GeminiPhishing.formatAnalysisText(analysis)
    });
    return false;
  }

  return false;
});

initializeDashboardData();

console.log("[Background] Gemini phishing detection background script loaded");
