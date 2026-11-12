const crypto = require("crypto");

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

let cachedToken = null;
let cachedTokenAt = 0;

async function getServiceAccountToken(scope) {
  const now = Date.now();
  if (cachedToken && now - cachedTokenAt < 50 * 60 * 1000) return cachedToken;

  const key = JSON.parse(process.env.GOOGLE_SA_KEY_JSON);
  const iat = Math.floor(now / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: key.client_email,
    scope: scope,
    aud: "https://oauth2.googleapis.com/token",
    iat: iat,
    exp: iat + 3600
  };
  const unsigned = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claim))}`;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsigned);
  const signature = signer.sign(key.private_key);
  const jwt = `${unsigned}.${b64url(signature)}`;

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt
    })
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) throw new Error("SA_TOKEN_ERR: " + JSON.stringify(data).slice(0, 300));
  cachedToken = data.access_token;
  cachedTokenAt = now;
  return cachedToken;
}

const SHEET_ID = process.env.QUEUE_SHEET_ID;
const TAB = "queue";

async function appendRequest(t, payload) {
  const token = await getServiceAccountToken("https://www.googleapis.com/auth/spreadsheets");
  const id = crypto.randomUUID();
  const row = [id, new Date().toISOString(), t, JSON.stringify(payload), "pending", "", ""];
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(TAB)}!A:G:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`;
  const res = await fetch(url, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ values: [row] })
  });
  const data = await res.json();
  if (!res.ok) throw new Error("SHEET_APPEND_ERR: " + JSON.stringify(data).slice(0, 300));
  const range = data.updates.updatedRange;
  const rowNum = Number(range.split("!")[1].match(/\d+/)[0]);
  return { id, rowNum };
}

async function readResult(rowNum) {
  const token = await getServiceAccountToken("https://www.googleapis.com/auth/spreadsheets.readonly");
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(TAB)}!E${rowNum}:F${rowNum}`;
  const res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  const data = await res.json();
  const vals = (data.values && data.values[0]) || [];
  const status = vals[0] || "pending";
  if (status === "pending" || !status) return null;
  if (status === "expired") return { ok: false, message: "Yêu cầu hết hạn do xử lý quá lâu, thử lại." };
  try { return JSON.parse(vals[1] || "{}"); } catch (e) { return { ok: false, message: "Lỗi đọc kết quả từ hàng đợi." }; }
}

async function callViaQueue(t, payload) {
  const { rowNum } = await appendRequest(t, payload);
  const start = Date.now();
  while (Date.now() - start < 95000) {
    await new Promise(r => setTimeout(r, 2500));
    const result = await readResult(rowNum);
    if (result) return result;
  }
  return { ok: false, message: "Hệ thống đang xử lý lâu hơn bình thường (lô lớn), vui lòng thử lại sau 1 phút." };
}

module.exports = { callViaQueue };
