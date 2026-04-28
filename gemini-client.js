/* global chrome */

var GeminiPhishing = (() => {
  const SETTINGS_KEY = "gemini_settings";
  const DEFAULT_MODEL = "gemini-2.5-flash";
  const GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models";

  const ANALYSIS_SCHEMA = {
    type: "object",
    properties: {
      verdict: {
        type: "string",
        enum: ["safe", "suspicious", "phishing"],
        description: "Final classification for the page."
      },
      risk_score: {
        type: "integer",
        minimum: 0,
        maximum: 100,
        description: "0 means no visible risk, 100 means clear phishing."
      },
      confidence: {
        type: "integer",
        minimum: 0,
        maximum: 100,
        description: "Confidence in the verdict based only on supplied evidence."
      },
      summary: {
        type: "string",
        description: "One concise sentence explaining the verdict."
      },
      reasons: {
        type: "array",
        items: { type: "string" },
        description: "Short evidence-based reasons."
      },
      recommended_action: {
        type: "string",
        description: "A short user-facing action recommendation."
      }
    },
    required: [
      "verdict",
      "risk_score",
      "confidence",
      "summary",
      "reasons",
      "recommended_action"
    ]
  };

  const BRAND_DOMAINS = {
    amazon: ["amazon.com", "amazon.co.uk", "amazon.co.za"],
    apple: ["apple.com", "icloud.com"],
    chase: ["chase.com"],
    facebook: ["facebook.com", "meta.com"],
    google: ["google.com", "gmail.com", "accounts.google.com"],
    instagram: ["instagram.com"],
    microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com"],
    netflix: ["netflix.com"],
    paypal: ["paypal.com"],
    whatsapp: ["whatsapp.com"],
    "wells fargo": ["wellsfargo.com"]
  };

  const SENSITIVE_TERMS = [
    "account",
    "alert",
    "bank",
    "billing",
    "confirm",
    "invoice",
    "login",
    "password",
    "pay",
    "secure",
    "security",
    "signin",
    "sso",
    "support",
    "update",
    "verify",
    "wallet"
  ];

  const RISKY_TLDS = [
    "zip",
    "mov",
    "top",
    "click",
    "country",
    "gq",
    "kim",
    "link",
    "ml",
    "mom",
    "quest",
    "rest",
    "tk",
    "work",
    "xyz"
  ];

  function storageGet(keys) {
    return new Promise((resolve, reject) => {
      if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
        resolve({});
        return;
      }

      chrome.storage.local.get(keys, (result) => {
        const error = chrome.runtime && chrome.runtime.lastError;
        if (error) {
          reject(new Error(error.message));
          return;
        }
        resolve(result || {});
      });
    });
  }

  function storageSet(values) {
    return new Promise((resolve, reject) => {
      if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
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

  async function getSettings() {
    const result = await storageGet([SETTINGS_KEY]);
    const stored = result[SETTINGS_KEY] || {};

    return {
      apiKey: typeof stored.apiKey === "string" ? stored.apiKey : "",
      model: normalizeModelName(stored.model || DEFAULT_MODEL)
    };
  }

  async function saveSettings(settings) {
    const nextSettings = {
      apiKey: (settings.apiKey || "").trim(),
      model: normalizeModelName(settings.model || DEFAULT_MODEL)
    };
    await storageSet({ [SETTINGS_KEY]: nextSettings });
    return nextSettings;
  }

  async function clearApiKey() {
    const settings = await getSettings();
    await saveSettings({ ...settings, apiKey: "" });
  }

  function normalizeModelName(model) {
    const value = String(model || DEFAULT_MODEL).trim();
    return (value || DEFAULT_MODEL).replace(/^models\//, "");
  }

  function maskApiKey(apiKey) {
    const cleanKey = String(apiKey || "").trim();
    if (!cleanKey) return "";
    if (cleanKey.length <= 8) return "saved";
    return `saved, ending ${cleanKey.slice(-4)}`;
  }

  function isSupportedUrl(url) {
    return /^https?:\/\//i.test(String(url || ""));
  }

  function normalizeUrl(url) {
    try {
      const parsed = new URL(url);
      parsed.hash = "";
      return parsed.toString();
    } catch {
      return String(url || "").trim();
    }
  }

  function clampInteger(value, min, max, fallback) {
    const numericValue = Number(value);
    if (!Number.isFinite(numericValue)) return fallback;
    return Math.max(min, Math.min(max, Math.round(numericValue)));
  }

  function safeString(value, maxLength = 240) {
    return String(value || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, maxLength);
  }

  function getApproxRegisteredDomain(hostname) {
    const parts = hostname.split(".").filter(Boolean);
    if (parts.length <= 2) return hostname;

    const last = parts[parts.length - 1];
    const secondLast = parts[parts.length - 2];
    const thirdLast = parts[parts.length - 3];
    const commonSecondLevelTlds = new Set(["co", "com", "net", "org", "gov", "ac"]);

    if (last.length === 2 && commonSecondLevelTlds.has(secondLast) && thirdLast) {
      return [thirdLast, secondLast, last].join(".");
    }

    return [secondLast, last].join(".");
  }

  function findBrandTerms(urlText, hostname) {
    const lowerText = urlText.toLowerCase();
    const hostText = hostname.toLowerCase().replace(/-/g, " ");
    const hits = [];

    for (const brand of Object.keys(BRAND_DOMAINS)) {
      const normalizedBrand = brand.replace(/\s+/g, "");
      if (
        lowerText.includes(normalizedBrand) ||
        lowerText.includes(brand) ||
        hostText.includes(brand)
      ) {
        hits.push(brand);
      }
    }

    return hits;
  }

  function findPossibleBrandImpersonation(hostname, brandHits) {
    return brandHits.filter((brand) => {
      const officialDomains = BRAND_DOMAINS[brand] || [];
      return !officialDomains.some(
        (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
      );
    });
  }

  function extractUrlSignals(url) {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      const labels = hostname.split(".").filter(Boolean);
      const tld = labels[labels.length - 1] || "";
      const pathSegments = parsed.pathname.split("/").filter(Boolean);
      const urlText = parsed.toString().toLowerCase();
      const brandHits = findBrandTerms(urlText, hostname);
      const possibleBrandImpersonation = findPossibleBrandImpersonation(hostname, brandHits);
      const encodedMatches = parsed.toString().match(/%[0-9a-f]{2}/gi) || [];
      const digitMatches = parsed.toString().match(/\d/g) || [];
      const hyphenMatches = hostname.match(/-/g) || [];
      const sensitiveTerms = SENSITIVE_TERMS.filter((term) => urlText.includes(term));

      return {
        urlLength: parsed.toString().length,
        scheme: parsed.protocol.replace(":", ""),
        hostname,
        registeredDomain: getApproxRegisteredDomain(hostname),
        tld,
        riskyTld: RISKY_TLDS.includes(tld),
        isIpAddressHost: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname),
        isPunycodeHost: hostname.includes("xn--"),
        subdomainCount: Math.max(0, labels.length - 2),
        hyphenCountInHost: hyphenMatches.length,
        digitCountInUrl: digitMatches.length,
        encodedCharCount: encodedMatches.length,
        hasAtSymbol: parsed.toString().includes("@"),
        hasUnusualPort: Boolean(parsed.port && !["80", "443"].includes(parsed.port)),
        pathDepth: pathSegments.length,
        hasQuery: Boolean(parsed.search),
        sensitiveTerms,
        brandTerms: brandHits,
        possibleBrandImpersonation
      };
    } catch {
      return {
        parseError: true,
        rawUrl: safeString(url, 500)
      };
    }
  }

  function compactPageContext(pageContext) {
    const context = pageContext || {};
    return {
      title: safeString(context.title, 160),
      host: safeString(context.host, 120),
      formCount: clampInteger(context.formCount, 0, 100, 0),
      passwordFieldCount: clampInteger(context.passwordFieldCount, 0, 100, 0),
      emailFieldCount: clampInteger(context.emailFieldCount, 0, 100, 0),
      externalFormActionCount: clampInteger(context.externalFormActionCount, 0, 100, 0),
      iframeCount: clampInteger(context.iframeCount, 0, 100, 0),
      externalLinkHostCount: clampInteger(context.externalLinkHostCount, 0, 1000, 0),
      visibleSecurityTerms: Array.isArray(context.visibleSecurityTerms)
        ? context.visibleSecurityTerms.map((term) => safeString(term, 40)).slice(0, 20)
        : [],
      formActionHosts: Array.isArray(context.formActionHosts)
        ? context.formActionHosts.map((host) => safeString(host, 120)).slice(0, 10)
        : [],
      externalLinkHosts: Array.isArray(context.externalLinkHosts)
        ? context.externalLinkHosts.map((host) => safeString(host, 120)).slice(0, 10)
        : []
    };
  }

  function buildPrompt(url, pageContext) {
    const urlSignals = extractUrlSignals(url);
    const pageSignals = compactPageContext(pageContext);

    return [
      "Classify this browser page for phishing risk using only the supplied evidence.",
      "",
      "Rules:",
      "- Return safe only when the URL/page signals look ordinary or low risk.",
      "- Return suspicious when there are warning signs but not enough evidence for phishing.",
      "- Return phishing only for clear credential theft, brand impersonation, malicious payment/account flows, deceptive domains, or obvious scam indicators.",
      "- Do not mark a site phishing merely because it has login/account words on an official domain.",
      "- Do not claim you visited the site, checked live reputation databases, or verified ownership.",
      "- Prefer cautious, evidence-based reasoning over broad assumptions.",
      "- Return exactly one JSON object. Do not use markdown fences, headings, or explanatory prose outside the JSON.",
      '- JSON keys must be: "verdict", "risk_score", "confidence", "summary", "reasons", "recommended_action".',
      "",
      `URL: ${url}`,
      `URL signals: ${JSON.stringify(urlSignals)}`,
      `Page signals: ${JSON.stringify(pageSignals)}`
    ].join("\n");
  }

  function extractCandidateText(responseData) {
    const parts = responseData?.candidates?.[0]?.content?.parts || [];
    return parts
      .map((part) => part.text || "")
      .join("")
      .trim();
  }

  function stripJsonWrappers(text) {
    let cleaned = String(text || "")
      .replace(/^\uFEFF/, "")
      .trim();

    cleaned = cleaned
      .replace(/^```(?:json|javascript|js)?\s*/i, "")
      .replace(/\s*```$/i, "")
      .trim();

    if (
      (cleaned.startsWith('"') && cleaned.endsWith('"')) ||
      (cleaned.startsWith("'") && cleaned.endsWith("'"))
    ) {
      try {
        const unwrapped = JSON.parse(cleaned);
        if (typeof unwrapped === "string") return unwrapped.trim();
      } catch {
        // Keep the original value if it is not a JSON-encoded string.
      }
    }

    return cleaned;
  }

  function findBalancedJsonCandidate(text, openChar, closeChar) {
    const source = String(text || "");
    const start = source.indexOf(openChar);
    if (start === -1) return "";

    let depth = 0;
    let inString = false;
    let escapeNext = false;

    for (let index = start; index < source.length; index += 1) {
      const char = source[index];

      if (escapeNext) {
        escapeNext = false;
        continue;
      }

      if (char === "\\") {
        escapeNext = true;
        continue;
      }

      if (char === '"') {
        inString = !inString;
        continue;
      }

      if (inString) continue;

      if (char === openChar) depth += 1;
      if (char === closeChar) depth -= 1;

      if (depth === 0) {
        return source.slice(start, index + 1);
      }
    }

    return "";
  }

  function coerceParsedJson(value) {
    if (Array.isArray(value)) {
      const firstObject = value.find((item) => item && typeof item === "object" && !Array.isArray(item));
      if (firstObject) return firstObject;
    }

    if (value && typeof value === "object") return value;

    if (typeof value === "string") {
      return parseJsonObject(value);
    }

    throw new Error("Gemini JSON response did not contain an object.");
  }

  function parseJsonObject(text) {
    const trimmed = stripJsonWrappers(text);
    if (!trimmed) {
      throw new Error("Gemini returned an empty response.");
    }

    try {
      return coerceParsedJson(JSON.parse(trimmed));
    } catch {
      const objectCandidate = findBalancedJsonCandidate(trimmed, "{", "}");
      if (objectCandidate) {
        try {
          return coerceParsedJson(JSON.parse(objectCandidate));
        } catch {
          // Try an array candidate below before giving up.
        }
      }

      const arrayCandidate = findBalancedJsonCandidate(trimmed, "[", "]");
      if (arrayCandidate) {
        return coerceParsedJson(JSON.parse(arrayCandidate));
      }

      throw new Error("Gemini returned a response that was not valid JSON.");
    }
  }

  function verdictFromRiskScore(score) {
    if (score >= 70) return "phishing";
    if (score >= 35) return "suspicious";
    return "safe";
  }

  function normalizeReasons(reasons) {
    const source = Array.isArray(reasons) ? reasons : [];
    return source
      .map((reason) => safeString(reason, 180))
      .filter(Boolean)
      .slice(0, 5);
  }

  function inferVerdictFromText(text, url, pageContext) {
    const rawText = String(text || "");
    const lowerText = rawText.toLowerCase();
    const riskText = lowerText
      .replace(/\bnot phishing\b/g, " ")
      .replace(/\bno phishing\b/g, " ")
      .replace(/\bdoes not appear to be phishing\b/g, " ")
      .replace(/\bnot suspicious\b/g, " ")
      .replace(/\bno suspicious(?: url)? indicators?\b/g, " ")
      .replace(/\bdo not see suspicious(?: url)? indicators?\b/g, " ")
      .replace(/\bdoes not show suspicious(?: url)? indicators?\b/g, " ")
      .replace(/\bno evidence of suspicious(?: activity| indicators?)?\b/g, " ")
      .replace(/\bno obvious phishing indicators?\b/g, " ");
    const urlSignals = extractUrlSignals(url);
    const pageSignals = compactPageContext(pageContext);

    let riskScore = 20;
    const reasons = [];

    const saysSafe =
      /\b(safe|legitimate|benign|not phishing|not suspicious|low risk)\b/.test(lowerText) &&
      !/\b(phishing|suspicious|malicious|unsafe|dangerous|credential theft|scam)\b/.test(riskText);
    const saysSuspicious = /\b(suspicious|caution|warning|potentially risky|risk indicators?)\b/.test(riskText);
    const saysPhishing = /\b(phishing|credential theft|deceptive|malicious|unsafe|scam)\b/.test(riskText);

    if (saysSafe) {
      riskScore = 15;
      reasons.push("Gemini described the page as safe or legitimate.");
    }

    if (saysSuspicious) {
      riskScore = Math.max(riskScore, 55);
      reasons.push("Gemini described warning signs or suspicious indicators.");
    }

    if (saysPhishing) {
      riskScore = Math.max(riskScore, 82);
      reasons.push("Gemini described phishing, scam, deceptive, or malicious indicators.");
    }

    if (urlSignals.parseError) {
      riskScore += 15;
      reasons.push("The URL could not be parsed cleanly.");
    } else {
      if (urlSignals.possibleBrandImpersonation?.length) {
        riskScore += 30;
        reasons.push(`Possible brand impersonation: ${urlSignals.possibleBrandImpersonation.join(", ")}.`);
      }
      if (urlSignals.hasAtSymbol) {
        riskScore += 20;
        reasons.push("The URL contains an @ symbol, which can hide the real destination.");
      }
      if (urlSignals.isIpAddressHost) {
        riskScore += 20;
        reasons.push("The page is hosted on an IP address instead of a normal domain.");
      }
      if (urlSignals.isPunycodeHost) {
        riskScore += 20;
        reasons.push("The hostname uses punycode, which can be used for lookalike domains.");
      }
      if (urlSignals.riskyTld) {
        riskScore += 12;
        reasons.push(`The top-level domain .${urlSignals.tld} is commonly abused in suspicious links.`);
      }
      if (urlSignals.subdomainCount >= 3) {
        riskScore += 8;
        reasons.push("The hostname has an unusually deep subdomain chain.");
      }
    }

    if (pageSignals.passwordFieldCount > 0 && urlSignals.possibleBrandImpersonation?.length) {
      riskScore += 18;
      reasons.push("The page asks for a password while showing possible brand impersonation signals.");
    }

    if (pageSignals.externalFormActionCount > 0) {
      riskScore += 14;
      reasons.push("One or more forms submit to a different host.");
    }

    riskScore = clampInteger(riskScore, 0, 100, 50);

    const verdict = verdictFromRiskScore(riskScore);
    const summary = rawText
      ? safeString(rawText, 220)
      : `${verdict[0].toUpperCase()}${verdict.slice(1)} verdict based on URL and page signals.`;

    return {
      verdict,
      risk_score: riskScore,
      confidence: rawText ? 60 : 45,
      summary,
      reasons: reasons.length ? reasons : ["Gemini returned prose, so the extension used URL and page signals as a fallback."],
      recommended_action: defaultRecommendedAction(verdict)
    };
  }

  function normalizeAnalysis(rawAnalysis, url, model) {
    const riskScore = clampInteger(
      rawAnalysis.risk_score ??
        rawAnalysis.riskScore ??
        rawAnalysis.risk ??
        rawAnalysis.score ??
        rawAnalysis.probability,
      0,
      100,
      50
    );
    const confidence = clampInteger(
      rawAnalysis.confidence ?? rawAnalysis.confidence_score ?? rawAnalysis.confidenceScore,
      0,
      100,
      65
    );
    const rawVerdict = safeString(
      rawAnalysis.verdict ?? rawAnalysis.classification ?? rawAnalysis.label ?? rawAnalysis.result,
      40
    ).toLowerCase();
    let verdict = ["safe", "suspicious", "phishing"].includes(rawVerdict)
      ? rawVerdict
      : verdictFromRiskScore(riskScore);

    if (verdict === "safe" && riskScore >= 55) verdict = "suspicious";
    if (verdict === "phishing" && riskScore < 60) verdict = "suspicious";

    const reasons = normalizeReasons(rawAnalysis.reasons);
    const summary =
      safeString(rawAnalysis.summary || rawAnalysis.explanation || rawAnalysis.reason, 220) ||
      `${verdict[0].toUpperCase()}${verdict.slice(1)} verdict based on URL and page signals.`;

    return {
      status: "success",
      engine: "gemini",
      model,
      url,
      verdict,
      riskScore,
      probability: riskScore,
      confidence,
      summary,
      reasons,
      recommendedAction:
        safeString(rawAnalysis.recommended_action || rawAnalysis.recommendedAction, 180) ||
        defaultRecommendedAction(verdict),
      isPhishing: verdict === "phishing",
      isSuspicious: verdict === "suspicious",
      isUnsafe: verdict !== "safe",
      analyzedAt: new Date().toISOString()
    };
  }

  function defaultRecommendedAction(verdict) {
    if (verdict === "phishing") {
      return "Do not enter credentials or payment details on this page.";
    }
    if (verdict === "suspicious") {
      return "Proceed carefully and verify the domain before entering sensitive information.";
    }
    return "No obvious phishing indicators were found in the supplied signals.";
  }

  async function analyzeUrl(url, pageContext = {}, options = {}) {
    if (!isSupportedUrl(url)) {
      throw new Error("Only http and https pages can be analyzed.");
    }

    const settings = await getSettings();
    const apiKey = (options.apiKey || settings.apiKey || "").trim();
    const model = normalizeModelName(options.model || settings.model || DEFAULT_MODEL);

    if (!apiKey) {
      throw new Error("Gemini API key is not configured. Open the extension popup and save your key.");
    }

    const response = await fetch(`${GEMINI_API_BASE}/${model}:generateContent`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey
      },
      body: JSON.stringify({
        systemInstruction: {
          parts: [
            {
              text:
                "You are a careful phishing detection engine embedded in a browser extension. " +
                "Return only structured JSON matching the provided schema."
            }
          ]
        },
        contents: [
          {
            role: "user",
            parts: [{ text: buildPrompt(url, pageContext) }]
          }
        ],
        generationConfig: {
          temperature: 0,
          topP: 0.8,
          maxOutputTokens: 600,
          responseMimeType: "application/json",
          responseJsonSchema: ANALYSIS_SCHEMA
        }
      })
    });

    const responseData = await response.json().catch(() => ({}));

    if (!response.ok) {
      const message = responseData?.error?.message || response.statusText || "Gemini request failed.";
      throw new Error(`Gemini API error (${response.status}): ${message}`);
    }

    const text = extractCandidateText(responseData);
    let parsed;

    try {
      parsed = parseJsonObject(text);
    } catch (error) {
      console.warn("[GeminiPhishing] Falling back from malformed JSON response:", error.message, text);
      parsed = inferVerdictFromText(text, url, pageContext);
    }

    return normalizeAnalysis(parsed, url, model);
  }

  function getVerdictLabel(verdict) {
    if (verdict === "phishing") return "Phishing";
    if (verdict === "suspicious") return "Suspicious";
    if (verdict === "safe") return "Safe";
    return "Unknown";
  }

  function getVerdictColor(verdict) {
    if (verdict === "phishing") return "#dc2626";
    if (verdict === "suspicious") return "#d97706";
    if (verdict === "safe") return "#16a34a";
    return "#64748b";
  }

  function formatAnalysisText(analysis) {
    if (!analysis) return "No analysis is available.";
    if (analysis.status && analysis.status !== "success") return analysis.summary || "Analysis failed.";

    const reasons = Array.isArray(analysis.reasons) && analysis.reasons.length
      ? ` Reasons: ${analysis.reasons.join("; ")}`
      : "";
    return `${getVerdictLabel(analysis.verdict)}. Risk ${analysis.riskScore}/100. Confidence ${analysis.confidence}/100. ${analysis.summary}${reasons} Action: ${analysis.recommendedAction}`;
  }

  return {
    SETTINGS_KEY,
    DEFAULT_MODEL,
    analyzeUrl,
    clearApiKey,
    compactPageContext,
    extractUrlSignals,
    formatAnalysisText,
    getSettings,
    getVerdictColor,
    getVerdictLabel,
    isSupportedUrl,
    maskApiKey,
    normalizeModelName,
    normalizeUrl,
    saveSettings
  };
})();
