/**
 * Backend HTTP client and response normalizer.
 *
 * sendToBackend posts the extracted email payload to the FastAPI /scan endpoint
 * and returns a normalized result the UI layer can render directly.
 *
 * explainBackendHttpError converts HTML error bodies (ngrok offline, placeholder
 * URL, wrong path) into actionable Apps Script messages that show up in the
 * error card — much more useful than "HTTP 502".
 */

function truncateAddonSnippet(text, maxLen) {
  // Strip HTML tags + collapse whitespace before truncating, so the snippet shown
  // in the error card is human-readable instead of raw <html> noise.
  const s = String(text || "").replace(/<[^>]*>/gi, " ").replace(/\s+/g, " ").trim();
  if (!maxLen || s.length <= maxLen) return s;
  return s.slice(0, Math.max(0, maxLen - 3)) + "...";
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function explainBackendHttpError(statusCode, responseText, requestUrl) {
  const req = String(requestUrl || "");
  const body = String(responseText || "");
  const bl = body.toLowerCase();

  // Most common pitfall in fresh setups: API_URL still points at the placeholder.
  if (!req || req.indexOf("YOUR_PUBLIC_HOST_HERE") >= 0) {
    return (
      "[Setup] API_URL still uses the placeholder. Open gmail-addon/Config.js and set API_URL " +
      "to https://<your-ngrok-or-public-host>/scan (HTTPS), save, then clasp push from the repo root."
    );
  }

  // Free ngrok URLs change on every restart, so an "expired URL" looks almost
  // identical to "tunnel offline". Detect both via body text and 5xx codes.
  const ngrokOffline =
    bl.indexOf("err_ngrok_3200") >= 0 ||
    bl.indexOf("ngrok is offline") >= 0 ||
    (bl.indexOf("ngrok-free") >= 0 && (bl.indexOf("offline") >= 0 || bl.indexOf("not online") >= 0)) ||
    (bl.indexOf("endpoint") >= 0 && bl.indexOf("offline") >= 0);

  if (ngrokOffline || (statusCode >= 502 && statusCode <= 504 && bl.indexOf("ngrok") >= 0)) {
    return (
      "[Tunnel offline or expired URL] Ngrok responded instead of FastAPI - the tunnel was stopped or " +
      "this subdomain no longer forwards to your machine (free ngrok URLs change when you restart ngrok)." +
      " Fix: (1) Start backend: uvicorn on port 8000. " +
      "(2) Run: ngrok http 8000. " +
      "(3) Copy the new https forwarding URL. " +
      "(4) Set API_URL = that URL with /scan on the end. " +
      "(5) clasp push. " +
      "HTTP status was " + statusCode + "; snippet: " + truncateAddonSnippet(body, 220)
    );
  }

  if (statusCode === 404) {
    return (
      "[404 Not Found] No route matched. Check API_URL ends with /scan exactly, your FastAPI app exposes POST /scan, " +
      "and ngrok forwards to the same port as uvicorn. Snippet: " + truncateAddonSnippet(body, 200)
    );
  }

  return "[Backend HTTP " + statusCode + "] " + truncateAddonSnippet(body, 450);
}

function sendToBackend(emailData) {
  if (typeof API_URL === "undefined" || !String(API_URL).trim()) {
    throw new Error("[Config] API_URL is missing. Set it in gmail-addon/Config.js and redeploy.");
  }

  const options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(emailData),
    // muteHttpExceptions lets us read the body of 4xx/5xx responses for
    // explainBackendHttpError instead of UrlFetchApp throwing immediately.
    muteHttpExceptions: true,
    // Bypass ngrok-free's HTML interstitial so the JSON response reaches us cleanly.
    headers: { "ngrok-skip-browser-warning": "true" }
  };

  const response = UrlFetchApp.fetch(API_URL, options);
  const responseText = response.getContentText();
  const statusCode = response.getResponseCode();

  if (statusCode < 200 || statusCode >= 300) {
    throw new Error(explainBackendHttpError(statusCode, responseText, API_URL));
  }

  return normalizeBackendResult(JSON.parse(responseText));
}

function normalizeBackendResult(result) {
  // Default shape: lets the UI render even when the response is missing/garbled
  // without scattering null checks across the renderers.
  if (!result || typeof result !== "object") {
    return {
      maliciousScore: 0,
      verdict: "Unknown",
      icon: "⚪",
      verdictReasoning: "",
      recommendation: "",
      familiarSenderCalibration: false,
      comments: [],
      riskIndicators: [],
      infoFindings: ["No valid response returned from backend."],
      scoreBreakdown: {}
    };
  }

  // Clamp score into [0, 100] so a malformed backend can't break the gauge.
  const score = Math.max(0, Math.min(100, Number(result.maliciousScore || 0)));
  const comments = asArray(result.comments);

  return {
    maliciousScore: score,
    verdict: result.verdict || "Unknown",
    icon: result.icon || "⚪",
    verdictReasoning: result.verdictReasoning || "",
    recommendation: result.recommendation || "",
    familiarSenderCalibration: !!result.familiarSenderCalibration,
    comments: comments,
    // Older builds returned only `comments`; fall back to it so the UI keeps working.
    riskIndicators: Array.isArray(result.riskIndicators) ? result.riskIndicators : comments,
    infoFindings: asArray(result.infoFindings),
    scoreBreakdown: result.scoreBreakdown || {},
    reasons: asArray(result.reasons),
    tip: result.tip || ""
  };
}
