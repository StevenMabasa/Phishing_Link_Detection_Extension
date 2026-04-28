// Compatibility loader for older popup HTML versions.
// The live popup now loads gemini-client.js and popup.js directly.
(function loadPopupScripts() {
  function loadScript(src, onload) {
    const script = document.createElement("script");
    script.src = src;
    script.onload = onload;
    document.head.appendChild(script);
  }

  if (window.GeminiPhishing) {
    loadScript("popup.js");
    return;
  }

  loadScript("gemini-client.js", () => loadScript("popup.js"));
})();
