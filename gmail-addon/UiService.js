const TRANSLATIONS = {
  he: {
    welcomeTitle: "ברוכה הבאה 👋",
    welcomeText: "פתחי מייל כדי לראות ציון זדוניות, ממצאים חשודים והמלצות בטיחות.",
    scanSummary: "סיכום הבדיקה",
    riskLevel: "רמת סיכון",
    maliciousScore: "ציון זדוניות",
    verdict: "פסק דין",
    verdictReasoning: "נימוק ההכרעה",
    recommendation: "המלצה מעשית",
    prioritizedThreats: "איומים מתועדפים (QR/BEC)",
    riskIndicators: "אינדיקטורים לסיכון",
    noRiskIndicators: "לא נמצאו אינדיקטורים חזקים לסיכון.",
    scoreBreakdown: "פירוט ציון",
    additionalContext: "מידע נוסף (לא בהכרח סיכון)",
    noAdditionalContext: "אין מידע נוסף.",
    decisionExplanation: "הסבר החלטת המערכת",
    noDetailedReasons: "לא סופקו סיבות מפורטות על ידי השרת.",
    errorTitle: "שגיאה",
    errorText: "לא ניתן היה לנתח את המייל.",
    noScoreBreakdown: "לא התקבל פירוט ציון מהשרת.",
    safetyTip: "טיפ בטיחות",
    tip: "טיפ:",
    lowRisk: "נמוך",
    suspicious: "חשוד",
    dangerous: "מסוכן - לא לפתוח",
    safeBanner: "🟢 נראה בטוח, ללא אינדיקציות חזקות לסיכון",
    suspiciousBanner: "🟠 נמצאו סימנים שדורשים בדיקה נוספת",
    dangerousBanner: "⛔ המייל מסוכן - לא לפתוח קישורים או קבצים",
    noReasoning: "לא התקבל נימוק מפורש מהשרת.",
    noRecommendation: "המלצה: בדקי את השולח בערוץ אמין לפני כל פעולה."
  },
  en: {
    welcomeTitle: "Welcome 👋",
    welcomeText: "Open an email to see its maliciousness score, suspicious findings, and safety guidance.",
    scanSummary: "Scan Summary",
    riskLevel: "Risk Level",
    maliciousScore: "Maliciousness Score",
    verdict: "Verdict",
    verdictReasoning: "Reasoning",
    recommendation: "Recommendation",
    prioritizedThreats: "Prioritized Threats (QR/BEC)",
    riskIndicators: "Risk Indicators",
    noRiskIndicators: "No strong risk indicators were found.",
    scoreBreakdown: "Score Breakdown",
    additionalContext: "Additional Context (Not necessarily risk)",
    noAdditionalContext: "No additional context.",
    decisionExplanation: "How the result was decided",
    noDetailedReasons: "No detailed reasons were returned by the backend.",
    errorTitle: "Error",
    errorText: "Could not analyze this email.",
    noScoreBreakdown: "No score breakdown was returned by the backend.",
    safetyTip: "Safety Tip",
    tip: "Tip:",
    lowRisk: "Low",
    suspicious: "Suspicious",
    dangerous: "Dangerous / Do Not Open",
    safeBanner: "🟢 Looks safe, no strong malicious indicators",
    suspiciousBanner: "🟠 Signals were found that require additional review",
    dangerousBanner: "⛔ Dangerous email - do not open links or files",
    noReasoning: "No explicit reasoning was returned by the backend.",
    noRecommendation: "Recommendation: verify the sender via a trusted channel before taking action."
  },
  es: {
    welcomeTitle: "Bienvenida 👋",
    welcomeText: "Abre un correo para ver su puntuacion de malicia, hallazgos sospechosos y recomendaciones de seguridad.",
    scanSummary: "Resumen del analisis",
    riskLevel: "Nivel de riesgo",
    maliciousScore: "Puntuacion de malicia",
    verdict: "Veredicto",
    verdictReasoning: "Razonamiento",
    recommendation: "Recomendacion",
    prioritizedThreats: "Amenazas priorizadas (QR/BEC)",
    riskIndicators: "Indicadores de riesgo",
    noRiskIndicators: "No se encontraron indicadores fuertes de riesgo.",
    scoreBreakdown: "Desglose de puntuacion",
    additionalContext: "Contexto adicional (no necesariamente riesgo)",
    noAdditionalContext: "No hay contexto adicional.",
    decisionExplanation: "Como se decidio el resultado",
    noDetailedReasons: "El servidor no devolvio razones detalladas.",
    errorTitle: "Error",
    errorText: "No se pudo analizar este correo.",
    noScoreBreakdown: "El backend no devolvio desglose de puntuacion.",
    safetyTip: "Consejo de seguridad",
    tip: "Consejo:",
    lowRisk: "Bajo",
    suspicious: "Sospechoso",
    dangerous: "Peligroso / No abrir",
    safeBanner: "🟢 Parece seguro, sin indicadores fuertes de malicia",
    suspiciousBanner: "🟠 Se encontraron senales que requieren revision adicional",
    dangerousBanner: "⛔ Correo peligroso: no abras enlaces ni archivos",
    noReasoning: "El backend no devolvio una explicacion explicita.",
    noRecommendation: "Recomendacion: verifica el remitente por un canal confiable antes de actuar."
  }
};

function getText(lang) {
  return TRANSLATIONS[lang] || TRANSLATIONS[LANG_EN];
}

function buildHomePageCard(lang) {
  const text = getText(lang);
  const card = buildAppCard(lang);
  card.addSection(buildLanguageSwitcher(lang));

  card.addSection(
    CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(
        wrapDirectionalHtml(
          lang,
          "<p><b>" + text.welcomeTitle + "</b></p>" +
          "<p>" + text.welcomeText + "</p>"
        )
      )
    )
  );

  card.addSection(buildTipSection(lang));
  return card.build();
}

function buildResultCard(result, lang) {
  const text = getText(lang);
  const card = buildAppCard(lang);
  const risk = getRiskMeta(result.verdict, lang);

  card.addSection(buildLanguageSwitcher(lang));
  card.addSection(buildSummarySection(result, lang, text, risk));

  card.addSection(
    buildSection(
      lang,
      text.riskIndicators,
      bulletListHtml(
        localizeItems(result.riskIndicators || result.comments, lang),
        text.noRiskIndicators
      )
    )
  );

  card.addSection(
    buildSection(
      lang,
      text.scoreBreakdown,
      buildScoreBreakdownHtml(result.scoreBreakdown, lang),
      true
    )
  );

  card.addSection(
    buildSection(
      lang,
      text.additionalContext,
      bulletListHtml(
        localizeItems(result.infoFindings, lang),
        text.noAdditionalContext
      ),
      true
    )
  );

  card.addSection(
    buildSection(
      lang,
      text.decisionExplanation,
      wrapDirectionalHtml(
        lang,
        "<p><b>" + text.verdictReasoning + ":</b> " + buildLocalizedReasoning(result, lang) + "</p>" +
        "<p><b>" + text.recommendation + ":</b> " + buildLocalizedRecommendation(result, lang) + "</p>"
      )
    )
  );

  card.addSection(buildTipSection(lang, result.tip));
  return card.build();
}

function buildSummarySection(result, lang, text, risk) {
  const section = CardService.newCardSection().setHeader(text.scanSummary);
  section.addWidget(
    CardService.newTextParagraph().setText(
      wrapDirectionalHtml(lang, "<p style=\"font-size:15px;\"><b>" + risk.bannerTitle + "</b></p>")
    )
  );
  section.addWidget(
    CardService.newTextParagraph().setText(
      wrapDirectionalHtml(
        lang,
        "<p><b>" + text.verdict + ":</b> " + (result.icon || "") + " " + (result.verdict || risk.label) + "</p>"
      )
    )
  );
  section.addWidget(
    CardService.newTextParagraph().setText(
      wrapDirectionalHtml(
        lang,
        "<p><b>" + text.riskLevel + ":</b> " + risk.label + "</p>"
      )
    )
  );
  section.addWidget(
    CardService.newTextParagraph().setText(
      wrapDirectionalHtml(
        lang,
        "<p><b>" + text.maliciousScore + ":</b> " + (result.maliciousScore || 0) + "/100</p>"
      )
    )
  );
  return section;
}

function buildErrorCard(error, lang) {
  const text = getText(lang);
  const card = buildAppCard(lang, "Runtime Error");
  card.addSection(buildLanguageSwitcher(lang));

  card.addSection(
    buildSection(
      lang,
      text.errorTitle,
      wrapDirectionalHtml(
        lang,
        "<p><b>" + text.errorText + "</b></p>" +
        "<p>" + String(error) + "</p>"
      )
    )
  );

  return card.build();
}

function buildAppCard(lang, subtitle) {
  const card = CardService.newCardBuilder();
  card.setHeader(
    CardService.newCardHeader()
      .setTitle(APP_NAME)
      .setSubtitle(subtitle || APP_SUBTITLE)
      .setImageUrl(APP_LOGO_URL)
  );
  return card;
}

function buildSection(lang, title, html, collapsible) {
  const section = CardService.newCardSection().setHeader(title);
  if (collapsible) {
    section.setCollapsible(true);
  }
  section.addWidget(CardService.newTextParagraph().setText(html));
  return section;
}

function buildLanguageSwitcher(currentLang) {
  const section = CardService.newCardSection();
  const heAction = CardService.newAction()
    .setFunctionName("switchLanguage")
    .setParameters({ lang: LANG_HE });
  const enAction = CardService.newAction()
    .setFunctionName("switchLanguage")
    .setParameters({ lang: LANG_EN });
  const esAction = CardService.newAction()
    .setFunctionName("switchLanguage")
    .setParameters({ lang: LANG_ES });

  section.addWidget(
    CardService.newTextButton()
      .setText(currentLang === LANG_HE ? "✓ עברית" : "עברית")
      .setOnClickAction(heAction)
  );
  section.addWidget(
    CardService.newTextButton()
      .setText(currentLang === LANG_EN ? "✓ English" : "English")
      .setOnClickAction(enAction)
  );
  section.addWidget(
    CardService.newTextButton()
      .setText(currentLang === LANG_ES ? "✓ Espanol" : "Espanol")
      .setOnClickAction(esAction)
  );

  return section;
}

function bulletListHtml(items, emptyText) {
  if (!items || !items.length) {
    return "<p>• " + emptyText + "</p>";
  }
  return items
    .map(function(item) {
      return "<p style=\"margin:0 0 8px 0;\">• " + String(item) + "</p>";
    })
    .join("");
}

function buildScoreBreakdownHtml(scoreBreakdown, lang) {
  const text = getText(lang);
  if (!scoreBreakdown || typeof scoreBreakdown !== "object") {
    return text.noScoreBreakdown;
  }

  const labels = lang === LANG_HE
    ? {
        keywords: "מילות סיכון",
        language: "איכות שפה",
        sender: "שולח/דומיין",
        time: "זמן שליחה",
        priorityThreats: "איומים מתועדפים (QR/BEC)",
        linkBase: "קנס בסיס על קישורים",
        urlRaw: "URL גולמי (לפני סקייל)",
        urlApplied: "URL מוחל (אחרי סקייל)",
        attachments: "קבצים מצורפים",
        totalPenalty: "סה\"כ קנס"
      }
    : lang === LANG_ES
    ? {
        keywords: "Palabras clave",
        language: "Lenguaje",
        sender: "Remitente/Dominio",
        time: "Hora de envio",
        priorityThreats: "Amenazas priorizadas (QR/BEC)",
        linkBase: "Penalizacion base de enlaces",
        urlRaw: "URL bruto (antes de escala)",
        urlApplied: "URL aplicado (despues de escala)",
        attachments: "Adjuntos",
        totalPenalty: "Penalizacion total"
      }
    : {
        keywords: "Keywords",
        language: "Language",
        sender: "Sender/Domain",
        time: "Sending Time",
        priorityThreats: "Prioritized Threats (QR/BEC)",
        linkBase: "Base Link Penalty",
        urlRaw: "URL Raw (before scaling)",
        urlApplied: "URL Applied (after scaling)",
        attachments: "Attachments",
        totalPenalty: "Total Penalty"
      };

  const lines = [];
  Object.keys(labels).forEach(function(key) {
    const rawValue = Number(scoreBreakdown[key] || 0);
    const shownValue = rawValue > 0 ? "-" + rawValue : "0";
    lines.push("<p style=\"margin:0 0 6px 0;\"><b>" + labels[key] + ":</b> " + shownValue + "</p>");
  });
  return lines.join("");
}

function buildTipSection(lang, tip) {
  const text = getText(lang);
  const html = "<b>" + text.tip + "</b> " + (tip || getRandomTip(lang));
  return buildSection(lang, text.safetyTip, wrapDirectionalHtml(lang, html), true);
}

function getReasons(result) {
  if (result.reasons && result.reasons.length) {
    return result.reasons;
  }
  return []
    .concat(result.riskIndicators || [])
    .concat(result.infoFindings || []);
}

function localizeItems(items, lang) {
  if (!Array.isArray(items)) {
    return [];
  }
  return items.map(function(item) {
    return localizeIndicatorText(item, lang);
  });
}

function localizeIndicatorText(item, lang) {
  const original = String(item || "");
  const normalized = original.toLowerCase();
  if (lang === LANG_EN) {
    return original;
  }

  const heMap = {
    "qr-phishing pattern detected": "זוהתה תבנית QR-Phishing.",
    "potential qr-phishing pattern detected": "זוהתה אינדיקציה אפשרית ל-QR-Phishing.",
    "decoded qr from linked resource": "פוענח QR מקישור חיצוני.",
    "qr-related linked resource detected": "זוהה קישור בעל מאפייני QR.",
    "could not fetch/decode qr-linked resource": "לא ניתן היה למשוך או לפענח משאב QR מהקישור.",
    "bec-style pattern detected": "זוהתה תבנית BEC/התחזות עסקית.",
    "low-confidence bec-style signal detected": "זוהה סיגנל חלש של תבנית BEC.",
    "executable attachment detected": "זוהה קובץ הרצה מצורף.",
    "disguised attachment filename pattern detected": "זוהתה תבנית הסוואת שם קובץ מצורף.",
    "risky archive/container attachment detected": "זוהה קובץ ארכיון/מיכל מסוכן.",
    "look-alike domain": "זוהה דומיין דומה (look-alike).",
    "url points to potentially dangerous downloadable file": "הקישור מפנה לקובץ להורדה שעלול להיות מסוכן.",
    "found ": "נמצאו "
  };

  const esMap = {
    "qr-phishing pattern detected": "Se detecto un patron de phishing con QR.",
    "potential qr-phishing pattern detected": "Se detecto una posible senal de phishing con QR.",
    "decoded qr from linked resource": "Se decodifico un QR desde un recurso enlazado.",
    "qr-related linked resource detected": "Se detecto un recurso enlazado con caracteristicas de QR.",
    "could not fetch/decode qr-linked resource": "No se pudo obtener o decodificar el recurso QR enlazado.",
    "bec-style pattern detected": "Se detecto un patron de BEC/suplantacion empresarial.",
    "low-confidence bec-style signal detected": "Se detecto una senal de baja confianza de BEC.",
    "executable attachment detected": "Se detecto un archivo adjunto ejecutable.",
    "disguised attachment filename pattern detected": "Se detecto un patron de nombre de adjunto disfrazado.",
    "risky archive/container attachment detected": "Se detecto un adjunto de archivo comprimido/contenedor riesgoso.",
    "look-alike domain": "Se detecto un dominio similar (look-alike).",
    "url points to potentially dangerous downloadable file": "La URL apunta a un archivo descargable potencialmente peligroso.",
    "found ": "Se encontraron "
  };

  const map = lang === LANG_HE ? heMap : esMap;
  const keys = Object.keys(map);
  for (let i = 0; i < keys.length; i++) {
    if (normalized.indexOf(keys[i]) >= 0) {
      return map[keys[i]];
    }
  }
  return original;
}

function localizeReasonTag(tag, lang) {
  const normalized = String(tag || "").toLowerCase();
  const maps = {
    he: {
      "executable attachment": "קובץ הרצה מצורף",
      "disguised attachment pattern": "תבנית הסוואת קובץ מצורף",
      "risky archive attachment": "קובץ ארכיון מסוכן",
      "sender spoofing/look-alike signs": "סימני התחזות שולח / דומיין דומה",
      "highly suspicious links": "קישורים חשודים מאוד",
      "sender/domain reputation alerts": "התראות מוניטין על שולח/דומיין",
      "urgent pressure wording": "ניסוח לחץ ודחיפות",
      "qr-phishing pattern": "תבנית פישינג מבוססת QR",
      "bec-style impersonation pattern": "תבנית BEC/התחזות עסקית",
    },
    es: {
      "executable attachment": "adjunto ejecutable",
      "disguised attachment pattern": "patron de adjunto disfrazado",
      "risky archive attachment": "adjunto de archivo comprimido riesgoso",
      "sender spoofing/look-alike signs": "senales de suplantacion o dominio parecido",
      "highly suspicious links": "enlaces altamente sospechosos",
      "sender/domain reputation alerts": "alertas de reputacion del remitente/dominio",
      "urgent pressure wording": "lenguaje de urgencia y presion",
      "qr-phishing pattern": "patron de phishing con QR",
      "bec-style impersonation pattern": "patron de BEC/suplantacion empresarial",
    },
    en: {
      "executable attachment": "executable attachment",
      "disguised attachment pattern": "disguised attachment pattern",
      "risky archive attachment": "risky archive attachment",
      "sender spoofing/look-alike signs": "sender spoofing/look-alike signs",
      "highly suspicious links": "highly suspicious links",
      "sender/domain reputation alerts": "sender/domain reputation alerts",
      "urgent pressure wording": "urgent pressure wording",
      "qr-phishing pattern": "QR-phishing pattern",
      "bec-style impersonation pattern": "BEC-style impersonation pattern",
    }
  };
  const languageMap = maps[lang] || maps.en;
  return languageMap[normalized] || String(tag || "");
}

function buildLocalizedReasoning(result, lang) {
  const text = getText(lang);
  const reasons = getReasons(result).map(function(item) {
    return localizeReasonTag(item, lang);
  });

  if (reasons.length) {
    if (lang === LANG_HE) {
      return "זוהו אינדיקטורים משמעותיים, כולל " + reasons.slice(0, 3).join(", ") + ".";
    }
    if (lang === LANG_ES) {
      return "Se detectaron indicadores significativos, incluyendo " + reasons.slice(0, 3).join(", ") + ".";
    }
    return "Significant indicators were detected, including " + reasons.slice(0, 3).join(", ") + ".";
  }

  if (result.verdictReasoning) {
    return String(result.verdictReasoning);
  }
  return text.noReasoning;
}

function buildLocalizedRecommendation(result, lang) {
  const text = getText(lang);
  const verdict = String(result.verdict || "").toLowerCase();
  if (verdict === "dangerous / do not open") {
    if (lang === LANG_HE) {
      return "אל תפתחי את המייל, אל תלחצי על קישורים ואל תפתחי או תורידי קבצים מצורפים.";
    }
    if (lang === LANG_ES) {
      return "No abras este correo, no hagas clic en enlaces y no abras ni descargues archivos adjuntos.";
    }
    return "Do not open this email, click links, or download/open attached files.";
  }
  if (verdict === "suspicious") {
    if (result.familiarSenderCalibration) {
      if (lang === LANG_HE) {
        return (
          "פתחי קישורים או קבצים מצורפים רק אם את מכירה את השולח והתוכן עומד בציפייה (למשל מסמך שציפית לקבל). " +
          "אם משהו מרגיש חריג — אמתי עם השולח בערוץ נפרד."
        );
      }
      if (lang === LANG_ES) {
        return (
          "Abre enlaces o adjuntos solo si reconoces al remitente y esperabas este tipo de archivo o mensaje. " +
          "Si algo sorprende, verifica por otro medio de confianza."
        );
      }
      return (
        "Only open links or attachments if you recognize this sender and expected this type of file or message. " +
        "If anything feels off, verify through a separate trusted channel."
      );
    }
    if (lang === LANG_HE) {
      return "אל תלחצי על קישורים או קבצים עד שתאמת/י את השולח דרך ערוץ מהימן.";
    }
    if (lang === LANG_ES) {
      return "Evita abrir enlaces o adjuntos hasta verificar al remitente por un canal confiable.";
    }
    return "Avoid links and attachments until you verify the sender through a trusted channel.";
  }
  if (verdict === "safe") {
    if (lang === LANG_HE) {
      return "אפשר להמשיך בזהירות, תוך שמירה על היגיינת אבטחה בסיסית במייל.";
    }
    if (lang === LANG_ES) {
      return "Puedes continuar con cuidado y mantener buenas practicas basicas de seguridad por correo.";
    }
    return "Proceed carefully while maintaining standard email security hygiene.";
  }
  return result.recommendation || text.noRecommendation;
}

function getRiskMeta(verdict, lang) {
  const text = getText(lang);
  const normalized = String(verdict || "").toLowerCase();
  if (normalized === "dangerous / do not open") {
    return {
      label: text.dangerous,
      bannerTitle: text.dangerousBanner
    };
  }

  if (normalized === "suspicious") {
    return {
      label: text.suspicious,
      bannerTitle: text.suspiciousBanner
    };
  }

  return {
    label: text.lowRisk,
    bannerTitle: text.safeBanner
  };
}

function wrapDirectionalHtml(lang, html) {
  const isRtl = lang === LANG_HE;
  const dir = isRtl ? "rtl" : "ltr";
  const align = isRtl ? "right" : "left";
  return "<div dir=\"" + dir + "\" style=\"text-align:" + align + ";\">" + html + "</div>";
}

function getUserLanguage(e) {
  try {
    if (e && e.commonEventObject && e.commonEventObject.userLocale) {
      const locale = String(e.commonEventObject.userLocale).toLowerCase();
      if (locale.indexOf("he") === 0) return LANG_HE;
      if (locale.indexOf("es") === 0) return LANG_ES;
    }
  } catch (err) {}
  return LANG_EN;
}

function getStoredLanguage() {
  const lang = PropertiesService.getUserProperties().getProperty("PHISHWALL_LANG");
  return lang || DEFAULT_LANG;
}

function setStoredLanguage(lang) {
  PropertiesService.getUserProperties().setProperty("PHISHWALL_LANG", lang);
}

function getRandomTip(lang) {
  const list = TIPS[lang] || TIPS[LANG_EN] || [];
  return list[Math.floor(Math.random() * list.length)];
}