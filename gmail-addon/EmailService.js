function extractSenderMailbox(fromHeader) {
  var raw = String(fromHeader || "").trim();
  var angled = raw.match(/<([^>]+)>/);
  var inner = angled ? angled[1].trim() : raw;
  inner = inner.replace(/^mailto:/i, "").trim();
  return inner.toLowerCase();
}

function countPriorThreadsForSender(mailboxEmail) {
  if (!mailboxEmail || mailboxEmail.indexOf("@") === -1) return 0;
  var escaped = mailboxEmail.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  var query = "from:\"" + escaped + "\" newer_than:180d";
  try {
    var threads = GmailApp.search(query, 0, 50);
    return threads ? threads.length : 0;
  } catch (err) {
    return 0;
  }
}

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
  var mailbox = extractSenderMailbox(from);
  var priorThreads = countPriorThreadsForSender(mailbox);

  return {
    subject: subject,
    from: from,
    body: body,
    body_snippet: bodySnippet,
    urls: urls,
    attachments: attachments,
    sender_prior_thread_count: priorThreads
  };
}

function extractAttachments(message) {
  const attachments = [];
  const gmailAttachments = message.getAttachments({
    includeInlineImages: true,
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