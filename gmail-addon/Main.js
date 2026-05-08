function buildHomePage(e) {
  const lang = getPreferredLanguage(e);
  return buildHomePageCard(lang);
}

function hasOpenGmailMessageContext(e) {
  return !!(e && e.gmail && e.gmail.messageId);
}

function buildEmailCard(e) {
  try {
    const lang = getPreferredLanguage(e);
    const emailData = extractEmailData(e);
    const result = sendToBackend(emailData);

    return buildResultCard(result, lang);
  } catch (error) {
    return buildErrorCard(error, getPreferredLanguage(e));
  }
}

function getPreferredLanguage(e) {
  const stored = getStoredLanguage();
  if (stored) return stored;
  return getUserLanguage(e);
}

function switchLanguage(e) {
  const lang = e.commonEventObject.parameters.lang;
  setStoredLanguage(lang);

  const nextCard = hasOpenGmailMessageContext(e)
    ? buildEmailCard(e)
    : buildHomePageCard(lang);

  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().updateCard(nextCard)
    )
    .build();
}