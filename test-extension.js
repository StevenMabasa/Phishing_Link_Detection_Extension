// Browser-console helper for checking the extension on the current page.

console.log("=== Extension Debug Test ===");

console.log("1. Chrome runtime available:", typeof chrome !== "undefined" && Boolean(chrome.runtime));

const overlay = document.getElementById("phishing-analysis-overlay");
const indicator = document.getElementById("phishing-extension-indicator");
console.log("2. Overlay element exists:", Boolean(overlay));
console.log("3. Indicator element exists:", Boolean(indicator));

if (typeof chrome !== "undefined" && chrome.runtime) {
  chrome.runtime.sendMessage(
    {
      type: "ANALYZE_URL",
      url: window.location.href,
      pageContext: {
        title: document.title,
        host: window.location.hostname,
        formCount: document.forms.length,
        passwordFieldCount: document.querySelectorAll('input[type="password"]').length
      },
      force: true
    },
    (response) => {
      const error = chrome.runtime.lastError;
      if (error) {
        console.error("4. Background analysis error:", error.message);
        return;
      }

      console.log("4. Background analysis response:", response);
      if (response && response.analysis) {
        console.log("5. Verdict:", response.analysis.verdict);
        console.log("6. Risk:", response.analysis.riskScore);
        console.log("7. Confidence:", response.analysis.confidence);
      }
    }
  );
}

console.log("=== End Debug Test ===");
