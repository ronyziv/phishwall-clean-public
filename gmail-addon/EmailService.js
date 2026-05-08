function extractEmailData(e) {
  const accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);

  const messageId = e.gmail.messageId;
  const message = GmailApp.getMessageById(messageId);

  const subject = message.getSubject() || "";
  const from = message.getFrom() || "";
  const body = message.getPlainBody() || "";
  const bodySnippet = body.substring(0, 500);
  const urls = extractUrlsFromText(body);
  const attachments = extractAttachments(message);

  return {
    subject: subject,
    from: from,
    body: body,
    body_snippet: bodySnippet,
    urls: urls,
    attachments: attachments
  };
}

function extractAttachments(message) {
  const attachments = [];
  const gmailAttachments = message.getAttachments({
    includeInlineImages: false,
    includeAttachments: true
  });

  for (const att of gmailAttachments) {
    attachments.push({
      filename: att.getName() || "unknown",
      mimeType: att.getContentType() || "",
      contentBase64: Utilities.base64Encode(att.getBytes())
    });
  }

  return attachments;
}

function extractUrlsFromText(text) {
  if (!text) return [];
  const matches = text.match(/https?:\/\/[^\s"'<>]+/g);
  return matches || [];
}

function normalizeUrls(urlsValue, bodyText) {
  let urls = [];

  if (Array.isArray(urlsValue)) {
    for (const rawValue of urlsValue) {
      const value = String(rawValue).trim();
      if (value) {
        urls.push(value);
      }
    }
  }

  if (!urls.length) {
    urls = extractUrlsFromText(bodyText || "");
  }

  return urls;
}