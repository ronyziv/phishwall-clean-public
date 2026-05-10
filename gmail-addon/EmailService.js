/**
 * Pulls the open Gmail message into the JSON shape the backend expects.
 *
 * Uses the per-event accessToken instead of the user's full Gmail scope so the
 * add-on can stay on the lightweight metadata.readonly + currentMessage scopes.
 */

function extractSenderMailbox(fromHeader) {
  // Strip the optional "Display Name <addr>" wrapper and any "mailto:" prefix.
  const raw = String(fromHeader || "").trim();
  const angled = raw.match(/<([^>]+)>/);
  const inner = (angled ? angled[1] : raw).replace(/^mailto:/i, "").trim();
  return inner.toLowerCase();
}

function countPriorThreadsForSender(mailboxEmail) {
  if (!mailboxEmail || mailboxEmail.indexOf("@") === -1) return 0;
  // Escape backslashes and quotes so an email containing them can't break the
  // GmailApp.search query syntax.
  const escaped = mailboxEmail.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const query = "from:\"" + escaped + "\" newer_than:180d";
  try {
    // Cap at 50 — the backend only needs "few" vs "many" for the familiarity gate.
    const threads = GmailApp.search(query, 0, 50);
    return threads ? threads.length : 0;
  } catch (err) {
    // Search can throw on quota / scope errors; treat as "no history" instead of
    // failing the whole scan.
    return 0;
  }
}

function extractEmailData(e) {
  // setCurrentMessageAccessToken authorizes GmailApp for *this* message only.
  const accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);

  const message = GmailApp.getMessageById(e.gmail.messageId);

  const subject = message.getSubject() || "";
  const from = message.getFrom() || "";
  const body = message.getPlainBody() || "";
  const mailbox = extractSenderMailbox(from);

  return {
    subject: subject,
    from: from,
    body: body,
    // body_snippet is sent separately so the backend can show a short preview
    // without re-truncating the full body.
    body_snippet: body.substring(0, 500),
    urls: extractUrlsFromText(body),
    attachments: extractAttachments(message),
    sender_prior_thread_count: countPriorThreadsForSender(mailbox)
  };
}

function extractAttachments(message) {
  // Include inline images: QR phishing often hides QR codes in inline images
  // that getAttachments() would skip by default.
  const gmailAttachments = message.getAttachments({
    includeInlineImages: true,
    includeAttachments: true
  });

  return gmailAttachments.map(function(att) {
    return {
      filename: att.getName() || "unknown",
      mimeType: att.getContentType() || "",
      // Backend expects base64 — Apps Script gives us bytes directly.
      contentBase64: Utilities.base64Encode(att.getBytes())
    };
  });
}

function extractUrlsFromText(text) {
  if (!text) return [];
  // Same URL pattern the backend uses; client-side extraction means small
  // requests for plain-text emails with many links.
  return text.match(/https?:\/\/[^\s"'<>]+/g) || [];
}
