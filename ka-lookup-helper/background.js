const USER_INFO_FILTER = { urls: ["https://fe-online-gateway.ghn.vn/order-tracking/public-api/internal/user-info*"] };
const LOOKUP_ORIGIN = "https://tracuunoibo.ghn.vn";
const DEFAULT_ORDER_CODE = "GYANE7Y8";
const PENDING_TTL_MS = 60000;
const area = chrome.storage.session || chrome.storage.local;

function headerValue(headers, name) {
  const found = (headers || []).find(h => String(h.name).toLowerCase() === name);
  return found && found.value ? String(found.value) : "";
}

function safeOrderCode(code) {
  const text = String(code || "").trim();
  return /^[A-Za-z0-9]{6,20}$/.test(text) ? text.toUpperCase() : DEFAULT_ORDER_CODE;
}

function notify(tabId, message) {
  if (typeof tabId !== "number") return Promise.resolve();
  return Promise.resolve(chrome.tabs.sendMessage(tabId, message)).catch(() => { });
}

async function deliver(cfg) {
  const data = await area.get("kaPending");
  const pending = data && data.kaPending;
  if (!pending) return;
  await area.remove("kaPending");
  if (Date.now() - pending.startedAt > PENDING_TTL_MS) return;
  await notify(pending.replyTabId, {
    type: "KA_CONFIG",
    reqId: pending.reqId,
    ok: true,
    token: cfg.token,
    userAgent: cfg.userAgent,
    capturedAt: cfg.capturedAt
  });
  if (typeof pending.helperTabId === "number") {
    Promise.resolve(chrome.tabs.remove(pending.helperTabId)).catch(() => { });
  }
}

chrome.webRequest.onSendHeaders.addListener(
  details => {
    const token = headerValue(details.requestHeaders, "token");
    if (!token) return;
    const userAgent = headerValue(details.requestHeaders, "user-agent") || navigator.userAgent;
    const cfg = { token, userAgent, capturedAt: Date.now() };
    area.set({ kaCfg: cfg }).then(() => deliver(cfg));
  },
  USER_INFO_FILTER,
  ["requestHeaders", "extraHeaders"]
);

async function startCapture(message, replyTabId) {
  const url = `${LOOKUP_ORIGIN}/internal?order_code=${safeOrderCode(message.orderCode)}`;
  await notify(replyTabId, { type: "KA_PROGRESS", reqId: message.reqId, stage: "opening" });
  const tab = await chrome.tabs.create({ url, active: false });
  await area.set({
    kaPending: { replyTabId, helperTabId: tab && tab.id, reqId: message.reqId, startedAt: Date.now() }
  });
  await notify(replyTabId, { type: "KA_PROGRESS", reqId: message.reqId, stage: "waiting" });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "KA_CAPTURE" && sender && sender.tab) {
    startCapture(message, sender.tab.id)
      .then(() => sendResponse({ ok: true }))
      .catch(err => sendResponse({ ok: false, error: String(err && err.message || err) }));
    return true;
  }
  return false;
});
