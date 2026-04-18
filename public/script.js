const scanForms = document.querySelectorAll(".scan-card");
const sampleButtons = document.querySelectorAll(".sample-trigger");
const reportButtons = document.querySelectorAll(".report-btn");
const chatToggle = document.getElementById("chatToggle");
const chatClose = document.getElementById("chatClose");
const assistantPanel = document.getElementById("assistantPanel");
const assistantMessages = document.getElementById("assistantMessages");
const assistantForm = document.getElementById("assistantForm");
const assistantInput = document.getElementById("assistantInput");
const suggestionButtons = document.querySelectorAll(".assistant-suggestion");

const emailInput = document.getElementById("emailContent");
const messageInput = document.getElementById("messageContent");
const urlInput = document.getElementById("urlInput");

const dashboardDefaults = {
  email: {
    title: "Awaiting Email Scan",
    explanation: "Scan an email to see confidence, phishing signals, and highlighted language.",
    highlightMessage: "Suspicious email phrases will appear here.",
    findingsMessage: "Embedded email links and domains will be listed here.",
    reachabilityStatus: "Reachability details for extracted links will appear here.",
    reachabilityReason: "DNS and HTTP checks for embedded links will be summarized here.",
    noUrlStatus: "No URL was available for reachability checks in this email scan.",
    noUrlReason: "Reachability checks run only when the scan includes a URL.",
    tags: ["Header checks", "AI scoring", "Embedded link review"]
  },
  sms: {
    title: "Awaiting SMS Scan",
    explanation: "Scan an SMS to see risky phrasing, suspicious links, and confidence.",
    highlightMessage: "Suspicious SMS phrases will appear here.",
    findingsMessage: "Linked destinations in the message will be listed here.",
    reachabilityStatus: "Reachability details for extracted links will appear here.",
    reachabilityReason: "DNS and HTTP checks for linked destinations will be summarized here.",
    noUrlStatus: "No URL was available for reachability checks in this SMS scan.",
    noUrlReason: "Reachability checks run only when the scan includes a URL.",
    tags: ["Short-link checks", "Urgency scoring", "Scam language review"]
  },
  url: {
    title: "Awaiting URL Scan",
    explanation: "Scan a URL to see lookalike domains, protocol issues, and malicious patterns.",
    highlightMessage: "URL-specific suspicious terms will appear here.",
    findingsMessage: "Domain and path findings will be listed here.",
    reachabilityStatus: "Website reachability details will appear here.",
    reachabilityReason: "DNS and HTTP checks will be summarized here.",
    noUrlStatus: "Enter a URL and run a scan to see reachability results.",
    noUrlReason: "Reachability checks run only when the scan includes a URL.",
    tags: ["Domain analysis", "Lookalike detection", "Path inspection"]
  }
};

const dashboards = Object.fromEntries(
  Array.from(document.querySelectorAll(".scan-dashboard")).map((dashboard) => {
    const scanType = dashboard.dataset.dashboardFor;

    return [
      scanType,
      {
        root: dashboard,
        title: dashboard.querySelector(".result-title"),
        explanation: dashboard.querySelector(".result-explanation"),
        status: dashboard.querySelector(".result-status"),
        confidence: dashboard.querySelector(".result-confidence"),
        meterRing: dashboard.querySelector(".meter-ring"),
        highlights: dashboard.querySelector(".result-highlights"),
        urlFindings: dashboard.querySelector(".result-url-findings"),
        modelInfo: dashboard.querySelector(".result-model-info"),
        meterFill: dashboard.querySelector(".meter-fill"),
        tags: dashboard.querySelector(".result-tags"),
        reachabilityPanel: dashboard.querySelector(".result-reachability"),
        reachabilityBadge: dashboard.querySelector(".result-reachability-badge"),
        reachabilityStatus: dashboard.querySelector(".result-reachability-status"),
        reachabilityCode: dashboard.querySelector(".result-reachability-code"),
        reachabilityReasons: dashboard.querySelector(".result-reachability-reasons"),
        reachabilityWarning: dashboard.querySelector(".result-reachability-warning")
      }
    ];
  })
);

const samples = {
  email:
    "Dear customer, your mailbox will be suspended today due to unusual activity. Click now to verify account access and confirm your password using the secure portal below: http://paypa1-security-check.com/login",
  sms:
    "Bank alert: payment failed. Act immediately and confirm your account now at bit.ly/secure-update to avoid suspension.",
  url: "http://192.168.0.44/login/verify-account"
};

const lastScanState = {
  email: null,
  sms: null,
  url: null
};
const chatState = {
  isOpen: false,
  latestScanContext: null
};
const assistantKeywords = [
  "phishing",
  "suspicious",
  "urgent",
  "verify",
  "password",
  "otp",
  "login",
  "bank",
  "link",
  "fake",
  "domain",
  "scam",
  "credential",
  "malicious"
];

function getScanLabel(scanType) {
  if (scanType === "sms") return "SMS";
  return `${scanType.charAt(0).toUpperCase()}${scanType.slice(1)}`;
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setLoading(scanType, isLoading) {
  const form = document.querySelector(`.scan-card[data-scan-type="${scanType}"]`);
  const loadingState = document.querySelector(`[data-loading-for="${scanType}"]`);
  const dashboard = dashboards[scanType]?.root;

  if (form) {
    form.querySelectorAll("button").forEach((button) => {
      button.disabled = isLoading;
    });
  }

  if (loadingState) {
    loadingState.classList.toggle("visible", isLoading);
    loadingState.setAttribute("aria-hidden", String(!isLoading));
  }

  if (dashboard) {
    dashboard.classList.toggle("is-loading", isLoading);
  }
}

function getStatusClass(status) {
  const normalized = status.toLowerCase();
  if (normalized === "safe") return "safe";
  if (normalized === "suspicious") return "suspicious";
  if (normalized === "phishing") return "phishing";
  if (normalized === "invalid url") return "phishing";
  return "neutral";
}

function getMeterColor(status) {
  if (status === "Safe") return "#69e6bd";
  if (status === "Suspicious") return "#ffd46f";
  if (status === "Phishing") return "#ff8cc7";
  return "#8fd8ff";
}

function updateMeter(score, status, meterFill) {
  if (!meterFill) return;

  const circumference = 289;
  const offset = circumference - (score / 100) * circumference;
  meterFill.style.strokeDashoffset = String(offset);
  meterFill.style.stroke = getMeterColor(status);
}

function renderFindings(items, scanType, elements) {
  if (!elements?.urlFindings) return;

  if (!items?.length) {
    elements.urlFindings.innerHTML = `<li>${escapeHtml(
      dashboardDefaults[scanType].findingsMessage
    )}</li>`;
    return;
  }

  elements.urlFindings.innerHTML = items
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");
}

function renderHighlights(highlights, scanType, elements) {
  if (!elements?.highlights) return;

  const segments = [];

  if (highlights?.email) {
    segments.push(`<strong>Email</strong><br>${highlights.email}`);
  }

  if (highlights?.message) {
    segments.push(`<strong>Message</strong><br>${highlights.message}`);
  }

  if (highlights?.url) {
    segments.push(`<strong>URL</strong><br>${highlights.url}`);
  }

  if (!segments.length) {
    elements.highlights.classList.add("empty");
    elements.highlights.innerHTML = dashboardDefaults[scanType].highlightMessage;
    return;
  }

  elements.highlights.classList.remove("empty");
  elements.highlights.innerHTML = segments.join("<hr>");
}

function renderSummaryTags(indicators = [], scanType, elements) {
  if (!elements?.tags) return;

  const items = indicators.length
    ? indicators.slice(0, 4)
    : dashboardDefaults[scanType].tags;

  elements.tags.innerHTML = items
    .map((item) => `<span>${escapeHtml(item)}</span>`)
    .join("");
}

function buildChatScanContext(result) {
  if (!result) return null;

  return {
    scanTypeLabel: result.scanTypeLabel,
    status: result.status,
    confidence: result.confidence,
    explanation: result.explanation,
    reasons: result.reasons || [],
    indicators: result.indicators || [],
    url: result.url || null
  };
}

function isInvalidUrlResult(result) {
  return result?.scanType === "url" && result?.exists === false;
}

function highlightAssistantKeywords(text = "") {
  if (!text) return "";

  let formatted = escapeHtml(text).replace(/\n/g, "<br>");
  assistantKeywords.forEach((keyword) => {
    const pattern = new RegExp(`\\b(${keyword})\\b`, "gi");
    formatted = formatted.replace(pattern, '<span class="assistant-keyword">$1</span>');
  });

  return formatted;
}

function scrollAssistantToBottom() {
  if (!assistantMessages) return;
  assistantMessages.scrollTop = assistantMessages.scrollHeight;
}

function renderAssistantMessage(role, content, { html = false, typing = false } = {}) {
  if (!assistantMessages) return null;

  const message = document.createElement("article");
  message.className = `assistant-message ${role}`;
  if (typing) {
    message.classList.add("is-typing");
  }

  const avatar = document.createElement("div");
  avatar.className = "assistant-avatar";
  avatar.textContent = role === "user" ? "You" : "AI";

  const bubble = document.createElement("div");
  bubble.className = "assistant-bubble";

  if (typing) {
    bubble.innerHTML =
      '<span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span>';
  } else if (html) {
    bubble.innerHTML = content;
  } else {
    bubble.textContent = content;
  }

  message.append(avatar, bubble);
  assistantMessages.append(message);
  scrollAssistantToBottom();
  return message;
}

function setChatOpen(isOpen) {
  chatState.isOpen = isOpen;

  if (!assistantPanel || !chatToggle) return;

  assistantPanel.hidden = !isOpen;
  chatToggle.setAttribute("aria-expanded", String(isOpen));
  assistantPanel.classList.toggle("open", isOpen);

  if (isOpen) {
    assistantInput?.focus();
    scrollAssistantToBottom();
  }
}

async function requestAssistantReply(message) {
  const response = await fetch("/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      message,
      scanContext: chatState.latestScanContext
    })
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Assistant request failed.");
  }

  return response.json();
}

async function sendAssistantMessage(message) {
  const cleaned = message.trim();
  if (!cleaned) return;

  setChatOpen(true);
  renderAssistantMessage("user", cleaned);
  if (assistantInput) {
    assistantInput.value = "";
  }

  const typingMessage = renderAssistantMessage("assistant", "", { typing: true });

  try {
    const result = await requestAssistantReply(cleaned);
    typingMessage?.remove();
    renderAssistantMessage("assistant", highlightAssistantKeywords(result.reply), { html: true });
  } catch (error) {
    typingMessage?.remove();
    renderAssistantMessage(
      "assistant",
      "I could not reach the assistant right now. Review the sender, links, and any password request before trusting the message."
    );
  }
}

function renderReachability(result, scanType, elements) {
  if (!elements?.reachabilityPanel) return;

  const {
    reachabilityPanel,
    reachabilityBadge,
    reachabilityStatus,
    reachabilityCode,
    reachabilityReasons,
    reachabilityWarning
  } = elements;
  const urlChecked = result?.urlChecked;
  const urlResult = result?.url || null;
  const reachability = urlResult?.reachability || urlResult?.liveCheck;
  const hasUrl = Boolean(urlResult?.value || reachability?.finalUrl || reachability?.hostname);
  const hasCheck =
    Boolean(reachability) &&
    Boolean(reachability.checked || reachability.blocked || reachability.dnsChecked);

  if (urlChecked === false) {
    reachabilityPanel.hidden = true;
    reachabilityWarning.hidden = true;
    return;
  }

  reachabilityPanel.hidden = false;
  reachabilityPanel.classList.remove("is-reachable", "is-unreachable", "is-blocked");

  if (!hasCheck) {
    reachabilityPanel.classList.add("is-empty");
    reachabilityBadge.textContent = hasUrl ? "Pending" : "No URL";
    reachabilityBadge.className = "status-badge result-reachability-badge neutral";
    reachabilityStatus.textContent = hasUrl
      ? dashboardDefaults[scanType].reachabilityStatus
      : dashboardDefaults[scanType].noUrlStatus;
    reachabilityCode.textContent = "Status code: --";
    reachabilityReasons.innerHTML = `<li>${escapeHtml(
      hasUrl
        ? dashboardDefaults[scanType].reachabilityReason
        : dashboardDefaults[scanType].noUrlReason
    )}</li>`;
    reachabilityWarning.hidden = true;
    return;
  }

  const isReachable = Boolean(reachability.reachable);
  const isBlocked = Boolean(reachability.blocked);
  const isUnreachable = !isReachable && !isBlocked;
  const statusCode = Number(reachability.statusCode || reachability.status || 0);
  const reasonItems =
    Array.isArray(reachability.reason) && reachability.reason.length
      ? reachability.reason
      : [reachability.summary || dashboardDefaults[scanType].reachabilityReason];

  reachabilityPanel.classList.remove("is-empty");
  reachabilityPanel.classList.toggle("is-reachable", isReachable);
  reachabilityPanel.classList.toggle("is-unreachable", isUnreachable);
  reachabilityPanel.classList.toggle("is-blocked", isBlocked);

  reachabilityBadge.textContent = isReachable ? "Reachable" : isBlocked ? "Blocked" : "Unreachable";
  reachabilityBadge.className = `status-badge result-reachability-badge ${
    isReachable ? "safe" : isBlocked ? "suspicious" : "phishing"
  }`;
  reachabilityStatus.textContent = isReachable
    ? "Website Reachable"
    : isBlocked
      ? "Reachability Check Blocked"
      : "Not Reachable";
  reachabilityCode.textContent = statusCode ? `Status code: ${statusCode}` : "Status code: Not available";
  reachabilityReasons.innerHTML = reasonItems
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");
  reachabilityWarning.hidden = !isUnreachable;
}

function animateDashboard(root) {
  if (!root) return;

  root.classList.remove("animated");
  void root.offsetWidth;
  root.classList.add("animated");
}

function buildPayload(scanType) {
  if (scanType === "email") {
    return {
      scanType,
      emailContent: emailInput.value.trim(),
      messageContent: "",
      url: "",
      input: emailInput.value.trim()
    };
  }

  if (scanType === "sms") {
    return {
      scanType,
      emailContent: "",
      messageContent: messageInput.value.trim(),
      url: "",
      input: messageInput.value.trim()
    };
  }

  return {
    scanType: "url",
    emailContent: "",
    messageContent: "",
    url: urlInput.value.trim(),
    input: urlInput.value.trim()
  };
}

function validatePayload(payload) {
  if (payload.scanType === "email" && !payload.emailContent) {
    return "Paste email content before scanning.";
  }

  if (payload.scanType === "sms" && !payload.messageContent) {
    return "Paste an SMS or message before scanning.";
  }

  if (payload.scanType === "url" && !payload.url) {
    return "Enter a URL before scanning.";
  }

  return "";
}

async function scanThreat(payload) {
  const response = await fetch("/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Scan request failed.");
  }

  return response.json();
}

async function reportThreat(scanType) {
  const scan = lastScanState[scanType];

  if (!scan) {
    window.alert(`Run a ${getScanLabel(scanType)} scan before reporting suspicious content.`);
    return;
  }

  try {
    const response = await fetch("/api/report", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        source: `${scanType}-dashboard`,
        content: JSON.stringify({
          payload: scan.payload,
          result: scan.result
        }),
        status: scan.result.status
      })
    });

    if (!response.ok) {
      window.alert("Unable to report this sample right now.");
      return;
    }

    const result = await response.json();
    window.alert(result.message);
  } catch (error) {
    window.alert(error.message || "Unable to report this sample right now.");
  }
}

function loadSample(scanType) {
  if (scanType === "email") {
    emailInput.value = samples.email;
  } else if (scanType === "sms") {
    messageInput.value = samples.sms;
  } else if (scanType === "url") {
    urlInput.value = samples.url;
  }
}

function renderDashboardResult(scanType, result) {
  const elements = dashboards[scanType];

  if (!elements) return;

  const invalidUrl = isInvalidUrlResult(result);

  const latencyText =
    typeof result?.diagnostics?.latencyMs === "number"
      ? `${result.diagnostics.latencyMs}ms`
      : "timing unavailable";
  const providerParts = [];

  if (result?.model?.searchEngine?.checked || result?.url?.searchEngine?.checked) {
    providerParts.push("Search engine check");
  }

  if (result?.dataset?.loaded) {
    providerParts.push(result.dataset.matched ? "CEAS dataset match" : "CEAS dataset");
  }

  if (result?.model?.liveUrlCheck?.checked || result?.url?.liveCheck?.checked || result?.url?.liveCheck?.blocked) {
    providerParts.push("Live URL check");
  }

  if (result?.model?.threatIntel?.enabled) {
    providerParts.push("Phishing.Database intel");
  }

  if (result?.model?.localEmailModel?.name) {
    providerParts.push(result.model.localEmailModel.name);
  }

  if (Array.isArray(result?.model?.textModels) && result.model.textModels.length) {
    providerParts.push("HF text ensemble");
  }

  if (result?.model?.urlModel) {
    providerParts.push("HF URL classifier");
  }

  const modelSummary = providerParts.length ? providerParts.join(" + ") : result.model.provider;
  const scoreSummary =
    result?.sources &&
    typeof result.sources.dataset === "number" &&
    typeof result.sources.ai === "number" &&
    typeof result.sources.rules === "number"
      ? `Dataset ${result.sources.dataset}% | AI ${result.sources.ai}% | Rules ${result.sources.rules}%`
      : latencyText;

  elements.root.classList.toggle("invalid-url", invalidUrl);
  elements.title.textContent = invalidUrl
    ? "URL validation result"
    : `${result.scanTypeLabel} threat assessment`;
  elements.explanation.textContent = invalidUrl ? "Invalid or Unreachable URL" : result.explanation;
  elements.status.textContent = result.status;
  elements.status.className = `status-badge result-status ${getStatusClass(result.status)}`;
  elements.confidence.textContent = invalidUrl ? "" : `${result.confidence}%`;
  elements.modelInfo.textContent = invalidUrl
    ? `URL validation stopped before risk scoring | ${latencyText}`
    : result.model.used
      ? `${modelSummary} active | ${scoreSummary} | ${latencyText}`
      : `Local hybrid analysis active | ${scoreSummary}`;

  if (!invalidUrl) {
    updateMeter(result.confidence, result.status, elements.meterFill);
  }

  renderHighlights(result.highlights, scanType, elements);
  renderFindings(result?.reasons?.length ? result.reasons : result?.url?.findings, scanType, elements);
  renderReachability(result, scanType, elements);
  renderSummaryTags(
    invalidUrl ? ["Invalid URL", "Validation stopped"] : result.indicators,
    scanType,
    elements
  );
  animateDashboard(elements.root);
  chatState.latestScanContext = buildChatScanContext(result);
}

function renderDashboardError(scanType, errorMessage) {
  const elements = dashboards[scanType];

  if (!elements) return;

  elements.root.classList.remove("invalid-url");
  elements.title.textContent = `${getScanLabel(scanType)} scan failed`;
  elements.explanation.textContent =
    "The scanner could not complete the analysis. Please try again.";
  elements.status.textContent = "Error";
  elements.status.className = "status-badge result-status neutral";
  elements.confidence.textContent = "0%";
  elements.modelInfo.textContent = errorMessage;

  updateMeter(0, "Idle", elements.meterFill);
  renderHighlights({}, scanType, elements);
  renderFindings([], scanType, elements);
  renderReachability(null, scanType, elements);
  renderSummaryTags([], scanType, elements);
}

sampleButtons.forEach((button) => {
  button.addEventListener("click", () => {
    loadSample(button.dataset.sampleType);
  });
});

reportButtons.forEach((button) => {
  button.addEventListener("click", () => {
    reportThreat(button.dataset.reportFor);
  });
});

chatToggle?.addEventListener("click", () => {
  setChatOpen(!chatState.isOpen);
});

chatClose?.addEventListener("click", () => {
  setChatOpen(false);
});

assistantForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  await sendAssistantMessage(assistantInput?.value || "");
});

suggestionButtons.forEach((button) => {
  button.addEventListener("click", async () => {
    await sendAssistantMessage(button.dataset.chatQuestion || "");
  });
});

scanForms.forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const scanType = form.dataset.scanType;
    const payload = buildPayload(scanType);
    const validationError = validatePayload(payload);

    if (validationError) {
      window.alert(validationError);
      return;
    }

    try {
      setLoading(scanType, true);
      const result = await scanThreat(payload);

      lastScanState[scanType] = {
        payload,
        result
      };

      renderDashboardResult(scanType, result);
    } catch (error) {
      renderDashboardError(scanType, error.message);
    } finally {
      setLoading(scanType, false);
    }
  });
});
