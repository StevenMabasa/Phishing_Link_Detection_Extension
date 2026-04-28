# Auto Phishing Detection Extension

Chrome extension that analyzes visited websites with the Gemini API and shows a page-level phishing verdict.

## Setup

1. Get a Gemini API key from Google AI Studio.
2. Open Chrome and go to `chrome://extensions/`.
3. Enable Developer Mode.
4. Click **Load unpacked** and select this folder.
5. Open the extension popup (Click on the extension icon).
6. Paste your Gemini API key, keep the model as `gemini-2.5-flash`, and click **Save Key**.
7. Visit a website. The content overlay will analyze the page automatically.

The API key is stored in Chrome local extension storage so that it is not committed to this project.

## How It Works

- `background.js` coordinates analysis and dashboard history.
- `content.js` collects URL/page signals and renders the on-page verdict overlay.
- `gemini-client.js` calls Gemini with structured JSON output.
- `hello.html` and `popup.js` provide API-key setup and manual scanning.
- `react-dashboard.html` and `dashboard-script.js` show scan history.

