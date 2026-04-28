// Browser-console helper for testing suspicious URL classification.

console.log("=== Testing Suspicious URL Detection ===");

const testUrls = [
  "https://paypal-security-alert.com",
  "https://facebook-login-verification.net",
  "https://amazon-account-suspended.org",
  "https://google-security-check.ml",
  "https://apple-id-verification.tk",
  "https://microsoft-account-locked.com",
  "https://bank-of-america-security.net",
  "https://chase-bank-verification.org",
  "https://wells-fargo-security.com",
  "https://paypal-account-limited.net"
];

function testUrl(url) {
  console.log(`Testing: ${url}`);

  if (typeof chrome === "undefined" || !chrome.runtime) {
    console.error("Chrome extension API is not available.");
    return;
  }

  chrome.runtime.sendMessage(
    {
      type: "ANALYZE_URL",
      url,
      pageContext: {
        title: "Account verification",
        host: new URL(url).hostname,
        formCount: 1,
        passwordFieldCount: 1,
        emailFieldCount: 1,
        externalFormActionCount: 0,
        visibleSecurityTerms: ["account", "verify", "password", "security"]
      },
      force: true
    },
    (response) => {
      const error = chrome.runtime.lastError;
      if (error) {
        console.error(`${url}: ${error.message}`);
        return;
      }

      const analysis = response && response.analysis;
      if (!analysis) {
        console.error(`${url}: no analysis returned`, response);
        return;
      }

      console.log(
        `${url}: ${analysis.verdict.toUpperCase()} - ${analysis.riskScore}/100 risk, ${analysis.confidence}/100 confidence`
      );
      console.log(`  ${analysis.summary}`);
    }
  );
}

testUrls.forEach((url, index) => {
  setTimeout(() => testUrl(url), index * 2000);
});

console.log("=== Test requests scheduled ===");
