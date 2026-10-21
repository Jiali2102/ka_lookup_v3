document.documentElement.dataset.kaHelper = "1";

function toPage(payload) {
  window.postMessage(Object.assign({ source: "ka-helper" }, payload), location.origin);
}

window.addEventListener("message", event => {
  if (event.source !== window || event.origin !== location.origin) return;
  const data = event.data;
  if (!data || data.source !== "ka-lookup-page" || data.type !== "KA_CAPTURE") return;
  const reqId = data.reqId;
  if (!navigator.userActivation || !navigator.userActivation.isActive) {
    toPage({ type: "KA_CONFIG", reqId, ok: false, error: "need_click" });
    return;
  }
  try {
    chrome.runtime.sendMessage({ type: "KA_CAPTURE", reqId, orderCode: data.orderCode }, response => {
      if (chrome.runtime.lastError || !response || !response.ok) {
        toPage({ type: "KA_CONFIG", reqId, ok: false, error: "extension_error" });
      }
    });
  } catch (err) {
    toPage({ type: "KA_CONFIG", reqId, ok: false, error: "extension_error" });
  }
});

chrome.runtime.onMessage.addListener(message => {
  if (!message) return;
  if (message.type === "KA_PROGRESS") {
    toPage({ type: "KA_PROGRESS", reqId: message.reqId, stage: message.stage });
  } else if (message.type === "KA_CONFIG") {
    toPage({
      type: "KA_CONFIG",
      reqId: message.reqId,
      ok: !!message.ok,
      token: message.token,
      userAgent: message.userAgent,
      capturedAt: message.capturedAt
    });
  }
});
