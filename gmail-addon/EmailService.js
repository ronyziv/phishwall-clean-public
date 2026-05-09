function extractSenderMailbox(fromHeader) {
  const raw = String(fromHeader || "").trim();
  const angled = raw.match(/<([^>]+)>/);
  const inner = (angled ? angled[1] : raw).replace(/^mailto:/i, "").trim();
  return inner.toLowerCase();
}

function countPriorThreadsForSender(mailboxEmail) {
  if (!mailboxEmail || mailboxEmail.indexOf("@") === -1) return 0;
  const escaped = mailboxEmail.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const query = "from:\"" + escaped + "\" newer_than:180d";
  try {
    const threads = GmailApp.search(query, 0, 50);
    return threads ? threads.length : 0;
  } catch (err) {
    return 0;
  }
}

function extractEmailData(e) {
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
    body_snippet: body.substring(0, 500),
    urls: extractUrlsFromText(body),
    attachments: extractAttachments(message),
    sender_prior_thread_count: countPriorThreadsForSender(mailbox)
  };
}

function extractAttachments(message) {
  const gmailAttachments = message.getAttachments({
    includeInlineImages: true,
    includeAttachments: true
  });

  return gmailAttachments.map(function(att) {
    return {
      filename: att.getName() || "unknown",
      mimeType: att.getContentType() || "",
      contentBase64: Utilities.base64Encode(att.getBytes())
    };
  });
}

function extractUrlsFromText(text) {
  if (!text) return [];
  return text.match(/https?:\/\/[^\s"'<>]+/g) || [];
}
