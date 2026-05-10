/**
 * Apps Script entry points for the Gmail add-on.
 *
 * The Gmail host invokes buildHomePage / buildEmailCard based on whether a
 * message is open. switchLanguage is wired up from the language toggle buttons
 * and re-renders whichever card is currently visible.
 */

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
    // Surface backend / extraction failures in-place so the user sees a real
    // message instead of Gmail's generic "add-on error".
    return buildErrorCard(error, getPreferredLanguage(e));
  }
}

function getPreferredLanguage(e) {
  // User-selected language wins; fall back to Gmail UI locale.
  return getStoredLanguage() || getUserLanguage(e);
}

function switchLanguage(e) {
  const lang = e.commonEventObject.parameters.lang;
  setStoredLanguage(lang);

  // Re-render whichever card is currently on screen so the language change is
  // immediate without forcing the user to reopen the message.
  const nextCard = hasOpenGmailMessageContext(e)
    ? buildEmailCard(e)
    : buildHomePageCard(lang);

  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().updateCard(nextCard)
    )
    .build();
}
