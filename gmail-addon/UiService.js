/**
 * Card builders + i18n strings.
 *
 * All UI text lives in TRANSLATIONS keyed by language. CardService TextParagraphs
 * accept only a tiny HTML subset (<b>, <i>, <u>, <s>, <a>, <font>, <br>) so all
 * spacing is built with <br> and emphasis with <font>/<b>.
 */

const TRANSLATIONS = {
  he: {
    welcomeTitle: "שלום,",
    welcomeText: "בחרו מייל כדי לראות רמת חשד, מה בולט בו והמלצה.",
    appCardSubtitle: "בדיקת אבטחה למייל",
    scanSummary: "סיכום",
    verdictLabel: "מצב ההודעה",
    scoreLineLabel: "מדד חשד (0 נמוך · 100 גבוה)",
    verdictReasoning: "הנימוק",
    recommendation: "המלצה",
    moreInformation: "פירוט נוסף",
    riskIndicators: "מה בולט בהודעה",
    noRiskIndicators: "לא נמצאו סימני חשד מהותיים.",
    scoreBreakdown: "פירוט מספרי",
    additionalContext: "הערות מהניתוח",
    noAdditionalContext: "אין הערות נוספות.",
    decisionExplanation: "סיבות עיקריות",
    detailedReasonSubtitle: "כאן יש הסבר מורחב ופירוט מספרי.",
    noDetailedReasons: "אין הסבר מורחב נוסף.",
    errorTitle: "הבדיקה לא הושלמה",
    errorText: "פרטים טכניים בהמשך.",
    runtimeCardSubtitle: "שגיאה",
    noScoreBreakdown: "אין פירוט מספרי.",
    safetyTip: "טיפ קצר",
    lowRisk: "רמת חשד נמוכה",
    suspicious: "שווה לעצור ולוודא",
    dangerous: "חשד גבוה",
    safeBanner: "לא נמצאו סימני חשד מהותיים. שמרו על זהירות רגילה.",
    suspiciousBanner: "יש כמה נקודות שכדאי לבדוק לפני המשך.",
    dangerousBanner: "רמת החשד גבוהה. אל תלחצו על קישורים ואל תפתחו קבצים מההודעה.",
    noReasoning: "אין הסבר נוסף.",
    noRecommendation: "בספק — פנו לשולח בערוץ אחר שאתם סומכים עליו."
  },
  en: {
    welcomeTitle: "Hello,",
    welcomeText: "Pick an email to see exposure level, what stood out, and a practical recommendation.",
    appCardSubtitle: "Email safety scan",
    scanSummary: "Summary",
    verdictLabel: "Status",
    scoreLineLabel: "Exposure index (0 low · 100 high)",
    verdictReasoning: "Rationale",
    recommendation: "What to do",
    moreInformation: "More detail",
    riskIndicators: "What stood out",
    noRiskIndicators: "No strong warning signals in this message.",
    scoreBreakdown: "Score details",
    additionalContext: "Notes from scan",
    noAdditionalContext: "No additional notes.",
    decisionExplanation: "Main reasons",
    detailedReasonSubtitle: "Extended explanation and numeric detail.",
    noDetailedReasons: "No additional narrative.",
    errorTitle: "Scan failed",
    errorText: "Technical details below.",
    runtimeCardSubtitle: "Error",
    noScoreBreakdown: "No numeric breakdown.",
    safetyTip: "Quick tip",
    lowRisk: "Low exposure",
    suspicious: "Pause and verify",
    dangerous: "High risk",
    safeBanner: "No unusual signals stood out. Keep normal email hygiene.",
    suspiciousBanner: "A few items are worth reviewing before you proceed.",
    dangerousBanner: "Exposure is high. Do not click links or open attachments from this message.",
    noReasoning: "No additional explanation.",
    noRecommendation: "If in doubt, reach out to the sender through a channel you already trust."
  },
  es: {
    welcomeTitle: "Hola,",
    welcomeText: "Elige un correo para ver el nivel de riesgo, lo que resalta y una recomendación.",
    appCardSubtitle: "Análisis de seguridad",
    scanSummary: "Resumen",
    verdictLabel: "Estado",
    scoreLineLabel: "Índice de exposición (0 bajo · 100 alto)",
    verdictReasoning: "Justificación",
    recommendation: "Qué hacer",
    moreInformation: "Más detalle",
    riskIndicators: "Lo que resalta",
    noRiskIndicators: "No aparecieron señales fuertes en este mensaje.",
    scoreBreakdown: "Detalle numérico",
    additionalContext: "Notas del análisis",
    noAdditionalContext: "Sin notas adicionales.",
    decisionExplanation: "Razones principales",
    detailedReasonSubtitle: "Explicación ampliada y detalle numérico.",
    noDetailedReasons: "Sin texto adicional.",
    errorTitle: "Análisis fallido",
    errorText: "Detalles técnicos abajo.",
    runtimeCardSubtitle: "Error",
    noScoreBreakdown: "Sin desglose numérico.",
    safetyTip: "Consejo breve",
    lowRisk: "Exposición baja",
    suspicious: "Conviene verificar",
    dangerous: "Riesgo alto",
    safeBanner: "No vimos señales extrañas. Mantén las prácticas habituales.",
    suspiciousBanner: "Hay puntos que conviene revisar antes de continuar.",
    dangerousBanner: "La exposición es alta. No hagas clic ni abras adjuntos de este mensaje.",
    noReasoning: "Sin texto explicativo adicional.",
    noRecommendation: "Si tienes dudas, contacta al remitente por un canal de confianza."
  }
};

// Always returns a translation object — falls back to English so callers never
// have to null-check.
function getText(lang) {
  return TRANSLATIONS[lang] || TRANSLATIONS[LANG_EN];
}

function buildHomePageCard(lang) {
  const text = getText(lang);
  const card = buildAppCard(lang, text.appCardSubtitle);
  card.addSection(buildLanguageSwitcher(lang));

  card.addSection(
    CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(
        "<b>" + escapeHtml(text.welcomeTitle) + "</b><br><br>" +
        escapeHtml(text.welcomeText)
      )
    )
  );

  card.addSection(buildTipSection(lang));
  return card.build();
}

// Escape every dynamic value before it goes into a TextParagraph, otherwise a
// malicious sender name / URL would render as raw HTML.
function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;");
}

function buildResultCard(result, lang) {
  const text = getText(lang);
  const risk = getRiskMeta(result.verdict, lang);
  const card = buildAppCard(lang, text.appCardSubtitle);

  card.addSection(buildLanguageSwitcher(lang));
  card.addSection(buildHeroSummarySection(result, text, risk));

  card.addSection(
    buildSection(
      text.riskIndicators,
      spacedListHtml(localizeItems(result.riskIndicators || result.comments, lang), text.noRiskIndicators),
      false
    )
  );

  card.addSection(
    buildSection(
      text.scoreBreakdown,
      buildScoreBreakdownHtml(result.scoreBreakdown, lang),
      true,
      true
    )
  );

  card.addSection(
    buildSection(
      text.additionalContext,
      spacedListHtml(localizeItems(result.infoFindings, lang), text.noAdditionalContext),
      true,
      true
    )
  );

  card.addSection(buildMoreInformationSection(result, lang, text));

  card.addSection(buildTipSection(lang, result.tip));
  return card.build();
}

function buildHeroSummarySection(result, text, risk) {
  const scoreNum = Number(result.maliciousScore || 0);
  // Inline CSS and <div>/<span> are stripped by CardService — see module header
  // for the supported tag list. Score is colored via <font color> instead.
  const heroHtml =
    "<b>" + escapeHtml(risk.label) + "</b>" +
    "<br><br>" +
    escapeHtml(risk.bannerTitle) +
    "<br><br>" +
    "<font color=\"" + risk.tone + "\"><b>" + scoreNum + "</b></font>" +
    " / 100" +
    "<br>" +
    escapeHtml(text.scoreLineLabel);

  const section = CardService.newCardSection().setHeader(text.scanSummary);
  section.addWidget(CardService.newTextParagraph().setText(heroHtml));
  return section;
}

function captionedParagraph(captionText, bodyText) {
  return (
    "<b>" + escapeHtml(captionText) + "</b>" +
    "<br>" +
    escapeHtml(bodyText) +
    "<br><br>"
  );
}

function buildMoreInformationSection(result, lang, text) {
  const section = CardService.newCardSection().setHeader(text.moreInformation);
  section.setCollapsible(true);
  section.setNumUncollapsibleWidgets(0);

  const serverReason = String(result.verdictReasoning || "").trim();
  const reasonBlock = captionedParagraph(
    text.verdictReasoning,
    serverReason || buildLocalizedReasoning(result, lang)
  );

  const recBlock = captionedParagraph(
    text.recommendation,
    buildLocalizedRecommendation(result, lang)
  );

  const tagReasons = (result.reasons || []).map((r) => localizeReasonTag(r, lang));

  let reasonsBlock = "";
  if (tagReasons.length) {
    const items = tagReasons
      .map((tag) => "• " + escapeHtml(String(tag)))
      .join("<br>");
    reasonsBlock =
      "<b>" + escapeHtml(text.decisionExplanation) + "</b>" +
      "<br>" +
      items;
  }

  const intro = escapeHtml(text.detailedReasonSubtitle) + "<br><br>";
  const html = intro + reasonBlock + recBlock + reasonsBlock;
  section.addWidget(CardService.newTextParagraph().setText(html));
  return section;
}

function buildErrorCard(error, lang) {
  const text = getText(lang);
  const card = buildAppCard(lang, text.runtimeCardSubtitle);
  card.addSection(buildLanguageSwitcher(lang));

  card.addSection(
    buildSection(
      text.errorTitle,
      "<b>" + escapeHtml(text.errorText) + "</b>" +
      "<br><br>" +
      escapeHtml(String(error))
    )
  );

  return card.build();
}

function buildAppCard(lang, subtitle) {
  const card = CardService.newCardBuilder();
  const sub = String(subtitle || "") || getText(lang).appCardSubtitle || APP_SUBTITLE;
  card.setHeader(
    CardService.newCardHeader()
      .setTitle(APP_NAME)
      .setSubtitle(sub)
      .setImageUrl(APP_LOGO_URL)
  );
  return card;
}

function buildSection(title, html, collapsible, collapsedDefault) {
  const section = CardService.newCardSection().setHeader(title);
  if (collapsible) {
    section.setCollapsible(true);
    if (collapsedDefault === true) {
      section.setNumUncollapsibleWidgets(0);
    }
  }
  section.addWidget(CardService.newTextParagraph().setText(html));
  return section;
}

function spacedListHtml(items, emptyText) {
  if (!items || !items.length) {
    return escapeHtml(emptyText);
  }
  return items
    .map((item) => "• " + escapeHtml(String(item)))
    .join("<br><br>");
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
      .setText(currentLang === LANG_ES ? "✓ Español" : "Español")
      .setOnClickAction(esAction)
  );

  return section;
}


function buildScoreBreakdownHtml(scoreBreakdown, lang) {
  const text = getText(lang);
  if (!scoreBreakdown || typeof scoreBreakdown !== "object") {
    return text.noScoreBreakdown;
  }

  // Per-language label map. Keys must match the ScoreBreakdown shape from the
  // backend (see models.py). Anything not in `labels` is hidden from the UI.
  const labels = lang === LANG_HE
    ? {
        keywords: "ניסוח חשוד",
        language: "איכות הניסוח",
        sender: "שולח ודומיין",
        time: "שעת שליחה",
        qr: "QR",
        priorityThreats: "התחזות עסקית / דחיפות",
        linkBase: "כמות קישורים",
        urlRaw: "קישורים (גולמי)",
        urlApplied: "קישורים (בציון)",
        attachments: "קבצים מצורפים",
        totalPenalty: "סה\"כ ניכוי"
      }
    : lang === LANG_ES
    ? {
        keywords: "Palabras clave",
        language: "Lenguaje",
        sender: "Remitente / dominio",
        time: "Hora de envío",
        qr: "QR",
        priorityThreats: "BEC / urgencia",
        linkBase: "Densidad de enlaces",
        urlRaw: "Enlaces (bruto)",
        urlApplied: "Enlaces (en el score)",
        attachments: "Adjuntos",
        totalPenalty: "Total"
      }
    : {
        keywords: "Keywords",
        language: "Language",
        sender: "Sender / domain",
        time: "Sending time",
        qr: "QR",
        priorityThreats: "BEC / urgency",
        linkBase: "Link density",
        urlRaw: "URLs (raw)",
        urlApplied: "URLs (counted)",
        attachments: "Attachments",
        totalPenalty: "Total penalty"
      };

  const orderedKeys = [
    "keywords",
    "language",
    "sender",
    "time",
    "qr",
    "priorityThreats",
    "linkBase",
    "urlRaw",
    "urlApplied",
    "attachments",
    "totalPenalty"
  ];

  return orderedKeys
    .filter((key) => key in labels)
    .map((key) => {
      // Penalties are subtracted from a 100-point trust pool, so we render them
      // as negative numbers ("-12") to match how users read score breakdowns.
      const rawValue = Number(scoreBreakdown[key] || 0);
      const shownValue = rawValue > 0 ? "-" + rawValue : "0";
      return "<b>" + escapeHtml(labels[key]) + ":</b> " + escapeHtml(shownValue);
    })
    .join("<br>");
}

function buildTipSection(lang, tip) {
  const text = getText(lang);
  return buildSection(text.safetyTip, escapeHtml(tip || getRandomTip(lang)), true, true);
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
  if (!Array.isArray(items)) return [];
  return items.map((item) => localizeIndicatorText(item, lang));
}

function localizeIndicatorText(item, lang) {
  // Translate backend findings into the user's language. We match by substring
  // because the backend appends per-finding context (filenames, URLs) that we
  // want to keep but can't translate.
  const original = String(item || "");
  const normalized = original.toLowerCase();
  if (lang === LANG_EN) {
    return original;
  }

  const heMap = {
    "qr-phishing pattern detected": "מאפיין של פישינג דרך QR.",
    "potential qr-phishing pattern detected": "רמז אפשרי לפישינג דרך QR.",
    "decoded qr from linked resource": "קוד QR נקרא מקישור חיצוני.",
    "qr-related linked resource detected": "קישור עם תוכן QR חשוד.",
    "could not fetch/decode qr-linked resource": "לא ניתן היה לקרוא QR מהקישור.",
    "bec-style pattern detected": "טקסט בסגנון התחזות עסקית (BEC).",
    "low-confidence bec-style signal detected": "רמז קל להתחזות עסקית.",
    "executable attachment detected": "קובץ הרצה מצורף (.exe וכדומה).",
    "disguised attachment filename pattern detected": "שם קובץ שמתחזה לסוג אחר.",
    "risky archive/container attachment detected": "קובץ ארכיון שעלול להסתיר תוכן מסוכן.",
    "look-alike domain": "כתובת שמדמה מותג מוכר.",
    "url points to potentially dangerous downloadable file": "קישור לקובץ שעלול להיות מסוכן.",
    "found ": "נמצאו "
  };

  const esMap = {
    "qr-phishing pattern detected": "Patrón de phishing con QR.",
    "potential qr-phishing pattern detected": "Posible señal de phishing con QR.",
    "decoded qr from linked resource": "Se decodificó un QR desde un recurso enlazado.",
    "qr-related linked resource detected": "Recurso enlazado con características de QR.",
    "could not fetch/decode qr-linked resource": "No se pudo leer el QR enlazado.",
    "bec-style pattern detected": "Patrón de BEC / suplantación empresarial.",
    "low-confidence bec-style signal detected": "Señal débil de BEC.",
    "executable attachment detected": "Archivo adjunto ejecutable.",
    "disguised attachment filename pattern detected": "Nombre de adjunto disfrazado.",
    "risky archive/container attachment detected": "Adjunto comprimido / contenedor arriesgado.",
    "look-alike domain": "Dominio parecido (look-alike).",
    "url points to potentially dangerous downloadable file": "Enlace a un archivo descargable potencialmente peligroso.",
    "found ": "Se encontraron "
  };

  const map = lang === LANG_HE ? heMap : esMap;
  // First-substring-match wins. Map keys are ordered most-specific first so
  // "decoded qr from linked resource" beats the broader "decoded qr".
  const matchedKey = Object.keys(map).find((key) => normalized.indexOf(key) >= 0);
  return matchedKey ? map[matchedKey] : original;
}

function localizeReasonTag(tag, lang) {
  const normalized = String(tag || "").toLowerCase();
  const maps = {
    he: {
      "executable attachment": "קובץ הרצה מצורף",
      "disguised attachment pattern": "שם קובץ מתחזה",
      "risky archive attachment": "ארכיון חשוד",
      "sender spoofing/look-alike signs": "חשד להתחזות בשולח",
      "highly suspicious links": "קישורים חשודים מאוד",
      "sender/domain reputation alerts": "חשד על השולח או הדומיין",
      "urgent pressure wording": "ניסוח דוחק",
      "qr-phishing pattern": "פישינג עם QR",
      "bec-style impersonation pattern": "התחזות עסקית (BEC)",
    },
    es: {
      "executable attachment": "adjunto ejecutable",
      "disguised attachment pattern": "nombre de adjunto disfrazado",
      "risky archive attachment": "adjunto comprimido arriesgado",
      "sender spoofing/look-alike signs": "señales de suplantación",
      "highly suspicious links": "enlaces muy sospechosos",
      "sender/domain reputation alerts": "alertas de reputación del remitente",
      "urgent pressure wording": "lenguaje de urgencia",
      "qr-phishing pattern": "phishing con QR",
      "bec-style impersonation pattern": "BEC / suplantación empresarial",
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
  const reasons = getReasons(result).map((item) => localizeReasonTag(item, lang));

  if (reasons.length) {
    if (lang === LANG_HE) {
      return "בין היתר: " + reasons.slice(0, 3).join(" · ") + ".";
    }
    if (lang === LANG_ES) {
      return "Entre otros: " + reasons.slice(0, 3).join(", ") + ".";
    }
    return "Among others: " + reasons.slice(0, 3).join(", ") + ".";
  }

  if (result.verdictReasoning) {
    return String(result.verdictReasoning);
  }
  return text.noReasoning;
}

function buildLocalizedRecommendation(result, lang) {
  // Prefer the backend-supplied recommendation (it can vary by familiarity
  // calibration etc.). Fall back to a static per-verdict message only when the
  // server didn't provide one (e.g. older builds, network errors).
  const text = getText(lang);
  const serverRec = String(result.recommendation || "").trim();
  if (serverRec) {
    return serverRec;
  }
  const verdict = String(result.verdict || "").toLowerCase();

  if (verdict === "dangerous / do not open") {
    if (lang === LANG_HE) {
      return "אל תלחצו על קישורים ואל תפתחו קבצים מההודעה הזו.";
    }
    if (lang === LANG_ES) {
      return "No hagas clic en enlaces ni abras adjuntos de este mensaje.";
    }
    return "Do not click links or open attachments from this message.";
  }
  if (verdict === "suspicious") {
    if (result.familiarSenderCalibration) {
      if (lang === LANG_HE) {
        return "אם השולח מוכר והתוכן צפוי — אפשר להמשיך בזהירות. בספק, אמתו בערוץ אחר.";
      }
      if (lang === LANG_ES) {
        return "Abre enlaces o adjuntos solo si reconoces al remitente y esperabas el mensaje. Si dudas, verifica por otro canal.";
      }
      return "Open links or attachments only if you recognize this sender and expected the message. If unsure, verify through another channel.";
    }
    if (lang === LANG_HE) {
      return "לפני לחיצה או פתיחת קובץ — אמתו את זהות השולח בערוץ אחר.";
    }
    if (lang === LANG_ES) {
      return "Verifica al remitente por un canal de confianza antes de abrir enlaces o adjuntos.";
    }
    return "Verify the sender through a trusted channel before opening links or attachments.";
  }
  if (verdict === "safe") {
    if (lang === LANG_HE) {
      return "לא נמצאו סימני חשד מהותיים. שמרו על זהירות רגילה.";
    }
    if (lang === LANG_ES) {
      return "Sin señales claras de riesgo. Mantén las prácticas habituales.";
    }
    return "No clear risk signals. Keep standard email hygiene.";
  }
  return result.recommendation || text.noRecommendation;
}

// Maps the backend verdict string to label/banner/color used by the hero block.
function getRiskMeta(verdict, lang) {
  const text = getText(lang);
  const normalized = String(verdict || "").toLowerCase();
  if (normalized === "dangerous / do not open") {
    return {
      label: text.dangerous,
      bannerTitle: text.dangerousBanner,
      tone: "#d93025"
    };
  }

  if (normalized === "suspicious") {
    return {
      label: text.suspicious,
      bannerTitle: text.suspiciousBanner,
      tone: "#e37400"
    };
  }

  return {
    label: text.lowRisk,
    bannerTitle: text.safeBanner,
    tone: "#188038"
  };
}

// Best-effort detection from Gmail's userLocale. Defaults to English.
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

// Per-user preference persisted via PropertiesService — survives reloads but
// is scoped to this add-on for this user.
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