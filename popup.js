/* global chrome, GeminiPhishing */

function getElement(id) {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Missing element: ${id}`);
  }
  return element;
}

function setOutput(message, className = "") {
  const output = getElement("output");
  output.className = className;
  output.textContent = message;
}

function setLoading(isLoading) {
  const button = getElement("getUrlBtn");
  button.disabled = isLoading;
  button.textContent = isLoading ? "Analyzing..." : "Analyze Current Page";
}

function chromeTabsQuery(queryInfo) {
  return new Promise((resolve, reject) => {
    chrome.tabs.query(queryInfo, (tabs) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve(tabs || []);
    });
  });
}

function chromeTabsSendMessage(tabId, message) {
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, message, (response) => {
      const error = chrome.runtime.lastError;
      if (error) {
        resolve(null);
        return;
      }
      resolve(response || null);
    });
  });
}

function chromeRuntimeSendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve(response || {});
    });
  });
}

function validateApiKey(apiKey) {
  const cleanKey = String(apiKey || "").trim();
  if (!cleanKey) {
    throw new Error("Enter a Gemini API key first.");
  }
  if (cleanKey.length < 20) {
    throw new Error("That API key looks too short.");
  }
  return cleanKey;
}

async function refreshSettingsUi() {
  const settings = await GeminiPhishing.getSettings();
  const apiKeyInput = getElement("geminiApiKey");
  const modelInput = getElement("geminiModel");
  const keyStatus = getElement("keyStatus");

  apiKeyInput.value = "";
  apiKeyInput.placeholder = settings.apiKey
    ? `Gemini API key ${GeminiPhishing.maskApiKey(settings.apiKey)}`
    : "Paste Gemini API key";
  modelInput.value = settings.model || GeminiPhishing.DEFAULT_MODEL;
  keyStatus.textContent = settings.apiKey
    ? `API key ${GeminiPhishing.maskApiKey(settings.apiKey)}`
    : "No API key saved";
  keyStatus.className = settings.apiKey ? "key-status saved" : "key-status";
}

async function saveApiKeyFromUi() {
  const apiKeyInput = getElement("geminiApiKey");
  const modelInput = getElement("geminiModel");
  const existingSettings = await GeminiPhishing.getSettings();
  const apiKey = apiKeyInput.value.trim() || existingSettings.apiKey;

  validateApiKey(apiKey);
  await GeminiPhishing.saveSettings({
    apiKey,
    model: modelInput.value || GeminiPhishing.DEFAULT_MODEL
  });
  await refreshSettingsUi();
  setOutput("Gemini API key saved. You can now analyze pages.", "success");
}

async function clearApiKeyFromUi() {
  await GeminiPhishing.clearApiKey();
  await refreshSettingsUi();
  setOutput("Gemini API key removed from Chrome local storage.", "success");
}

async function getActiveTab() {
  const tabs = await chromeTabsQuery({ active: true, currentWindow: true });
  if (!tabs.length) throw new Error("No active tab found.");
  if (!tabs[0].url) throw new Error("The active tab has no URL.");
  if (!GeminiPhishing.isSupportedUrl(tabs[0].url)) {
    throw new Error("Only http and https pages can be analyzed.");
  }
  return tabs[0];
}

async function collectActivePageContext(tabId) {
  const response = await chromeTabsSendMessage(tabId, { type: "COLLECT_PAGE_CONTEXT" });
  return response && response.pageContext ? response.pageContext : {};
}

async function analyzeCurrentPage() {
  setLoading(true);
  setOutput("Checking current tab...", "loading");

  try {
    const settings = await GeminiPhishing.getSettings();
    validateApiKey(settings.apiKey);

    const tab = await getActiveTab();
    setOutput("Collecting page signals...", "loading");
    const pageContext = await collectActivePageContext(tab.id);

    setOutput("Analyzing with Gemini...", "loading");
    const response = await chromeRuntimeSendMessage({
      type: "ANALYZE_URL",
      url: tab.url,
      pageContext,
      force: true
    });

    const analysis = response.analysis;
    if (!analysis) {
      throw new Error(response.error || "No analysis was returned.");
    }

    const verdict = GeminiPhishing.getVerdictLabel(analysis.verdict);
    const reasons = Array.isArray(analysis.reasons) && analysis.reasons.length
      ? `\n\nEvidence:\n- ${analysis.reasons.join("\n- ")}`
      : "";

    setOutput(
      [
        `${verdict} (${analysis.riskScore}/100 risk, ${analysis.confidence}/100 confidence)`,
        "",
        analysis.summary,
        reasons,
        "",
        `Action: ${analysis.recommendedAction}`
      ].join("\n"),
      analysis.verdict === "safe" ? "success" : "warning"
    );
  } catch (error) {
    setOutput(`Analysis failed: ${error.message}`, "error");
  } finally {
    setLoading(false);
  }
}

async function testGeminiConnection() {
  setOutput("Testing Gemini API key...", "loading");

  try {
    const settings = await GeminiPhishing.getSettings();
    validateApiKey(settings.apiKey);
    const analysis = await GeminiPhishing.analyzeUrl("https://www.google.com", {
      title: "Google",
      host: "www.google.com",
      formCount: 1,
      passwordFieldCount: 0,
      emailFieldCount: 0,
      externalFormActionCount: 0,
      iframeCount: 0,
      externalLinkHostCount: 0,
      visibleSecurityTerms: [],
      formActionHosts: [],
      externalLinkHosts: []
    });

    setOutput(
      `Gemini connection works. Test verdict: ${GeminiPhishing.getVerdictLabel(analysis.verdict)} (${analysis.riskScore}/100 risk).`,
      "success"
    );
  } catch (error) {
    setOutput(`Gemini test failed: ${error.message}`, "error");
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  try {
    await refreshSettingsUi();

    getElement("saveKeyBtn").addEventListener("click", () => {
      saveApiKeyFromUi().catch((error) => setOutput(`Could not save key: ${error.message}`, "error"));
    });

    getElement("clearKeyBtn").addEventListener("click", () => {
      clearApiKeyFromUi().catch((error) => setOutput(`Could not clear key: ${error.message}`, "error"));
    });

    getElement("testKeyBtn").addEventListener("click", () => {
      testGeminiConnection();
    });

    getElement("getUrlBtn").addEventListener("click", () => {
      analyzeCurrentPage();
    });

    getElement("dashboardBtn").addEventListener("click", () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("react-dashboard.html") });
    });
  } catch (error) {
    setOutput(`Popup failed to initialize: ${error.message}`, "error");
  }
});
