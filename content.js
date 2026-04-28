/* global chrome */

let analysisOverlay = null;
let isOverlayVisible = false;
let analysisInFlight = false;

function createElement(tag, options = {}) {
  const element = document.createElement(tag);
  if (options.id) element.id = options.id;
  if (options.className) element.className = options.className;
  if (options.text !== undefined) element.textContent = options.text;
  if (options.styles) element.style.cssText = options.styles;
  return element;
}

function createOverlay() {
  if (analysisOverlay) return analysisOverlay;

  const overlay = createElement("div", {
    id: "phishing-analysis-overlay",
    styles: `
      position: fixed;
      top: 20px;
      right: 20px;
      width: min(380px, calc(100vw - 40px));
      max-height: min(520px, calc(100vh - 40px));
      background: #ffffff;
      border: 2px solid #d1d5db;
      border-radius: 8px;
      box-shadow: 0 18px 40px rgba(15, 23, 42, 0.22);
      z-index: 2147483647;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.4;
      overflow: hidden;
      transition: transform 0.25s ease, opacity 0.25s ease;
      transform: translateX(calc(100% + 28px));
      opacity: 0;
    `
  });

  const header = createElement("div", {
    styles: `
      background: #f8fafc;
      padding: 12px 14px;
      border-bottom: 1px solid #e5e7eb;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
    `
  });

  const title = createElement("div", {
    text: "Phishing Analysis",
    styles: "font-weight: 700; color: #111827;"
  });

  const closeButton = createElement("button", {
    text: "x",
    styles: `
      width: 28px;
      height: 28px;
      border: none;
      background: transparent;
      color: #64748b;
      cursor: pointer;
      font-size: 16px;
      line-height: 1;
    `
  });
  closeButton.type = "button";
  closeButton.addEventListener("click", hideOverlay);

  const content = createElement("div", {
    id: "analysis-content",
    styles: `
      padding: 14px;
      color: #334155;
      max-height: 410px;
      overflow-y: auto;
    `
  });

  const footer = createElement("div", {
    text: "Powered by Gemini API",
    styles: `
      background: #f8fafc;
      padding: 8px 14px;
      border-top: 1px solid #e5e7eb;
      font-size: 12px;
      color: #64748b;
      text-align: center;
    `
  });

  header.appendChild(title);
  header.appendChild(closeButton);
  overlay.appendChild(header);
  overlay.appendChild(content);
  overlay.appendChild(footer);
  document.documentElement.appendChild(overlay);
  analysisOverlay = overlay;
  return overlay;
}

function clearNode(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function getVerdictMeta(analysis) {
  if (!analysis || analysis.status === "setup_required") {
    return {
      label: "Setup Required",
      color: "#2563eb",
      background: "#eff6ff"
    };
  }

  if (analysis.status && analysis.status !== "success") {
    return {
      label: "Analysis Failed",
      color: "#64748b",
      background: "#f8fafc"
    };
  }

  if (analysis.verdict === "phishing") {
    return {
      label: "Phishing",
      color: "#dc2626",
      background: "#fef2f2"
    };
  }

  if (analysis.verdict === "suspicious") {
    return {
      label: "Suspicious",
      color: "#d97706",
      background: "#fffbeb"
    };
  }

  return {
    label: "Safe",
    color: "#16a34a",
    background: "#f0fdf4"
  };
}

function normalizeLegacyPayload(url, payload) {
  if (payload && typeof payload === "object" && payload.analysis) return payload.analysis;
  if (payload && typeof payload === "object" && payload.verdict) return payload;

  const result = typeof payload === "string" ? payload : "";
  const isUnsafe = /phishing|suspicious/i.test(result);
  return {
    status: "success",
    url,
    verdict: isUnsafe ? "suspicious" : "safe",
    riskScore: isUnsafe ? 70 : 15,
    confidence: 50,
    summary: result || "No analysis details were returned.",
    reasons: [],
    recommendedAction: isUnsafe
      ? "Verify this page before entering sensitive information."
      : "No obvious phishing indicators were found.",
    isUnsafe
  };
}

function appendMetricRow(parent, label, value) {
  const row = createElement("div", {
    styles: `
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 6px 0;
      border-bottom: 1px solid #f1f5f9;
    `
  });
  row.appendChild(createElement("span", { text: label, styles: "color: #64748b;" }));
  row.appendChild(createElement("strong", { text: value, styles: "color: #111827; text-align: right;" }));
  parent.appendChild(row);
}

function showOverlay(url, payload) {
  const analysis = normalizeLegacyPayload(url, payload);
  const overlay = createOverlay();
  const content = overlay.querySelector("#analysis-content");
  const meta = getVerdictMeta(analysis);

  clearNode(content);

  const status = createElement("div", {
    text: meta.label,
    styles: `
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      background: ${meta.background};
      color: ${meta.color};
      font-weight: 700;
      margin-bottom: 10px;
    `
  });

  const summary = createElement("div", {
    text: analysis.summary || "No summary returned.",
    styles: "font-weight: 600; color: #111827; margin-bottom: 10px;"
  });

  const metrics = createElement("div", { styles: "margin-bottom: 10px;" });
  appendMetricRow(metrics, "Risk", `${analysis.riskScore || 0}/100`);
  appendMetricRow(metrics, "Confidence", `${analysis.confidence || 0}/100`);
  appendMetricRow(metrics, "URL", url.length > 54 ? `${url.slice(0, 54)}...` : url);

  content.appendChild(status);
  content.appendChild(summary);
  content.appendChild(metrics);

  if (Array.isArray(analysis.reasons) && analysis.reasons.length) {
    const reasonsTitle = createElement("div", {
      text: "Evidence",
      styles: "font-weight: 700; color: #111827; margin: 10px 0 4px;"
    });
    const list = createElement("ul", {
      styles: "margin: 0 0 10px 18px; padding: 0;"
    });
    for (const reason of analysis.reasons.slice(0, 5)) {
      list.appendChild(createElement("li", { text: reason, styles: "margin: 3px 0;" }));
    }
    content.appendChild(reasonsTitle);
    content.appendChild(list);
  }

  const action = createElement("div", {
    text: analysis.recommendedAction || "Use caution with sensitive information.",
    styles: `
      background: #f8fafc;
      border: 1px solid #e5e7eb;
      border-radius: 6px;
      padding: 10px;
      color: #334155;
    `
  });
  content.appendChild(action);

  overlay.style.borderColor = meta.color;
  overlay.style.transform = "translateX(0)";
  overlay.style.opacity = "1";
  isOverlayVisible = true;
  updateIndicatorColor(analysis);

  if (analysis.verdict === "safe") {
    setTimeout(() => {
      if (isOverlayVisible) hideOverlay();
    }, 10000);
  }
}

function showLoadingOverlay() {
  const overlay = createOverlay();
  const content = overlay.querySelector("#analysis-content");
  clearNode(content);
  content.appendChild(createElement("div", {
    text: "Analyzing this page with Gemini...",
    styles: "color: #2563eb; font-weight: 600;"
  }));
  overlay.style.borderColor = "#2563eb";
  overlay.style.transform = "translateX(0)";
  overlay.style.opacity = "1";
  isOverlayVisible = true;
}

function hideOverlay() {
  if (analysisOverlay && isOverlayVisible) {
    analysisOverlay.style.transform = "translateX(calc(100% + 28px))";
    analysisOverlay.style.opacity = "0";
    isOverlayVisible = false;
  }
}

function updateIndicatorColor(analysis) {
  const indicator = document.getElementById("phishing-extension-indicator");
  if (!indicator) return;

  const meta = getVerdictMeta(analysis);
  indicator.style.background = meta.color;
  indicator.style.boxShadow = `0 8px 24px ${meta.color}55`;
  indicator.title = `${meta.label} - click to re-analyze`;
}

function uniqueValues(values, limit) {
  return Array.from(new Set(values.filter(Boolean))).slice(0, limit);
}

function collectPageContext() {
  const forms = Array.from(document.forms || []);
  const links = Array.from(document.links || []);
  const pageHost = window.location.hostname.toLowerCase();
  const bodyText = (document.body && document.body.innerText ? document.body.innerText : "")
    .replace(/\s+/g, " ")
    .toLowerCase()
    .slice(0, 6000);
  const visibleSecurityTerms = [
    "account",
    "bank",
    "billing",
    "confirm",
    "login",
    "password",
    "payment",
    "secure",
    "security",
    "sign in",
    "update",
    "verify",
    "wallet"
  ].filter((term) => bodyText.includes(term));

  const formActionHosts = forms
    .map((form) => {
      try {
        return form.action ? new URL(form.action, window.location.href).hostname.toLowerCase() : "";
      } catch {
        return "";
      }
    })
    .filter(Boolean);

  const externalFormActionCount = formActionHosts.filter((host) => host && host !== pageHost).length;

  const externalLinkHosts = links
    .map((link) => {
      try {
        return link.href ? new URL(link.href).hostname.toLowerCase() : "";
      } catch {
        return "";
      }
    })
    .filter((host) => host && host !== pageHost);

  return {
    title: document.title || "",
    host: pageHost,
    formCount: forms.length,
    passwordFieldCount: document.querySelectorAll('input[type="password"]').length,
    emailFieldCount: document.querySelectorAll('input[type="email"], input[name*="email" i]').length,
    externalFormActionCount,
    iframeCount: document.querySelectorAll("iframe").length,
    externalLinkHostCount: uniqueValues(externalLinkHosts, 1000).length,
    visibleSecurityTerms,
    formActionHosts: uniqueValues(formActionHosts, 10),
    externalLinkHosts: uniqueValues(externalLinkHosts, 10)
  };
}

function requestAnalysis(force = false) {
  if (analysisInFlight && !force) return;
  analysisInFlight = true;
  showLoadingOverlay();

  chrome.runtime.sendMessage(
    {
      type: "ANALYZE_URL",
      url: window.location.href,
      pageContext: collectPageContext(),
      force
    },
    (response) => {
      analysisInFlight = false;
      const error = chrome.runtime.lastError;
      if (error) {
        showOverlay(window.location.href, {
          status: "error",
          verdict: "unknown",
          riskScore: 0,
          confidence: 0,
          summary: error.message,
          reasons: [],
          recommendedAction: "Reload the extension and try again."
        });
        return;
      }

      showOverlay(window.location.href, response && (response.analysis || response.result));
    }
  );
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "PHISHING_ANALYSIS") {
    showOverlay(request.url || window.location.href, request.analysis || request.result);
    sendResponse({ shown: true });
    return false;
  }

  if (request.type === "RUN_PHISHING_ANALYSIS") {
    requestAnalysis(false);
    sendResponse({ started: true });
    return false;
  }

  if (request.type === "COLLECT_PAGE_CONTEXT") {
    sendResponse({ pageContext: collectPageContext() });
    return false;
  }

  return false;
});

document.addEventListener("keydown", (event) => {
  if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "p") {
    event.preventDefault();
    if (isOverlayVisible) {
      hideOverlay();
    } else {
      requestAnalysis(true);
    }
  }
});

function addExtensionIndicator() {
  if (document.getElementById("phishing-extension-indicator")) return;

  const indicator = createElement("button", {
    id: "phishing-extension-indicator",
    text: "P",
    styles: `
      position: fixed;
      bottom: 20px;
      right: 20px;
      width: 42px;
      height: 42px;
      border: none;
      border-radius: 50%;
      background: #2563eb;
      color: white;
      font-size: 16px;
      font-weight: 800;
      cursor: pointer;
      z-index: 2147483646;
      box-shadow: 0 8px 24px rgba(37, 99, 235, 0.35);
      transition: transform 0.2s ease, opacity 0.2s ease;
      opacity: 0.86;
    `
  });
  indicator.type = "button";
  indicator.title = "Phishing detection active - click to analyze this page";
  indicator.addEventListener("click", () => requestAnalysis(true));
  indicator.addEventListener("mouseenter", () => {
    indicator.style.opacity = "1";
    indicator.style.transform = "scale(1.08)";
  });
  indicator.addEventListener("mouseleave", () => {
    indicator.style.opacity = "0.86";
    indicator.style.transform = "scale(1)";
  });

  document.documentElement.appendChild(indicator);
}

function initialize() {
  addExtensionIndicator();
  window.setTimeout(() => requestAnalysis(false), 500);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initialize, { once: true });
} else {
  initialize();
}
