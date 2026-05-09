function sendToBackend(emailData) {
  const options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(emailData),
    muteHttpExceptions: true
  };

  const response = UrlFetchApp.fetch(API_URL, options);
  const responseText = response.getContentText();
  const statusCode = response.getResponseCode();

  if (statusCode < 200 || statusCode >= 300) {
    throw new Error("Backend returned status " + statusCode + ": " + responseText);
  }

  const parsed = JSON.parse(responseText);
  return normalizeBackendResult(parsed);
}

function getArrayData(arr) {
  return Array.isArray(arr) ? arr : [];
}

function normalizeBackendResult(result) {
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

  let score = Number(result.maliciousScore || 0);
  score = Math.max(0, Math.min(100, score));

  return {
    maliciousScore: score,
    verdict: result.verdict || "Unknown",
    icon: result.icon || "⚪",
      verdictReasoning: result.verdictReasoning || "",
      recommendation: result.recommendation || "",
    familiarSenderCalibration: !!result.familiarSenderCalibration,
    comments: getArrayData(result.comments),
    riskIndicators: Array.isArray(result.riskIndicators)
      ? result.riskIndicators
      : getArrayData(result.comments),
    infoFindings: getArrayData(result.infoFindings),
    scoreBreakdown: result.scoreBreakdown || {},
    reasons: getArrayData(result.reasons),
    tip: result.tip || ""
  };
}