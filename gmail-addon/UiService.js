const TRANSLATIONS = {
  he: {
    welcomeTitle: "ברוכה הבאה 👋",
    welcomeText: "פתחי מייל כדי לראות ציון זדוניות, ממצאים חשודים והמלצות בטיחות.",
    scanSummary: "סיכום הבדיקה",
    riskLevel: "רמת סיכון",
    maliciousScore: "ציון זדוניות",
    verdict: "פסק דין",
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
    highRisk: "סיכון גבוה",
    safeBanner: "🟢 לא נמצאו אינדיקציות חזקות לסיכון",
    suspiciousBanner: "🟠 נמצאו סימנים שדורשים בדיקה נוספת",
    highRiskBanner: "🔴 נמצאו אינדיקציות חזקות לסיכון במייל הזה"
  },
  en: {
    welcomeTitle: "Welcome 👋",
    welcomeText: "Open an email to see its maliciousness score, suspicious findings, and safety guidance.",
    scanSummary: "Scan Summary",
    riskLevel: "Risk Level",
    maliciousScore: "Maliciousness Score",
    verdict: "Verdict",
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
    highRisk: "High Risk",
    safeBanner: "🟢 No strong risk indicators were found",
    suspiciousBanner: "🟠 Signals were found that require additional review",
    highRiskBanner: "🔴 Strong risk indicators were found in this email"
  },
  es: {
    welcomeTitle: "Bienvenida 👋",
    welcomeText: "Abre un correo para ver su puntuacion de malicia, hallazgos sospechosos y recomendaciones de seguridad.",
    scanSummary: "Resumen del analisis",
    riskLevel: "Nivel de riesgo",
    maliciousScore: "Puntuacion de malicia",
    verdict: "Veredicto",
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
    highRisk: "Riesgo alto",
    safeBanner: "🟢 No se encontraron indicadores fuertes de riesgo",
    suspiciousBanner: "🟠 Se encontraron senales que requieren revision adicional",
    highRiskBanner: "🔴 Se encontraron indicadores fuertes de riesgo en este correo"
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

  card.addSection(
    buildSection(
      lang,
      text.scanSummary,
      wrapDirectionalHtml(
        lang,
        "<p><b>" + risk.bannerTitle + "</b></p>" +
        "<p>" +
        "<b>" + text.riskLevel + ":</b> " + risk.label + "<br>" +
        "<b>" + text.maliciousScore + ":</b> " + (result.maliciousScore || 0) + "/100<br>" +
        "<b>" + text.verdict + ":</b> " + (result.icon || "") + " " + (result.verdict || risk.label) +
        "</p>"
      )
    )
  );

  card.addSection(
    buildSection(
      lang,
      text.riskIndicators,
      bulletListHtml(
        result.riskIndicators || result.comments,
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
        result.infoFindings,
        text.noAdditionalContext
      ),
      true
    )
  );

  card.addSection(
    buildSection(
      lang,
      text.decisionExplanation,
      bulletListHtml(
        getReasons(result),
        text.noDetailedReasons
      ),
      true
    )
  );

  card.addSection(buildTipSection(lang, result.tip));
  return card.build();
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
    return "• " + emptyText;
  }
  return "• " + items.map(function(item) { return String(item); }).join("<br><br>• ");
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
        linkBase: "Base Link Penalty",
        urlRaw: "URL Raw (before scaling)",
        urlApplied: "URL Applied (after scaling)",
        attachments: "Attachments",
        totalPenalty: "Total Penalty"
      };

  const lines = [];
  Object.keys(labels).forEach(function(key) {
    lines.push("<b>" + labels[key] + ":</b> -" + Number(scoreBreakdown[key] || 0));
  });
  return lines.join("<br>");
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

function getRiskMeta(verdict, lang) {
  const text = getText(lang);
  const normalized = String(verdict || "").toLowerCase();
  if (normalized === "high risk") {
    return {
      label: text.highRisk,
      bannerTitle: text.highRiskBanner
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