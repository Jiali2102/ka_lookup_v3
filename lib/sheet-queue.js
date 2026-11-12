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

const TYPE_LABEL = {
  v1: "Xác thực", v2: "Đền bù", v3: "Quá hạn", v4: "Ticket", v5: "Fake Attempt",
  v6: "Miễn cước", v7: "Xin mật khẩu", v8: "Tổng hợp", v9: "Kiểm tra duyệt", v10: "Tra cứu BI"
};

function vnNow() {
  return new Date().toLocaleString("sv-SE", { timeZone: "Asia/Ho_Chi_Minh" });
}

async function appendRequest(t, payload) {
  const token = await getServiceAccountToken("https://www.googleapis.com/auth/spreadsheets");
  const id = crypto.randomUUID();
  const row = [id, vnNow(), TYPE_LABEL[t] || t, JSON.stringify(payload), "pending", "", ""];
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

function packPj(rowNum) {
  return Buffer.from(String(rowNum)).toString("base64url");
}

function unpackPj(pj) {
  const n = Number(Buffer.from(String(pj), "base64url").toString());
  return Number.isInteger(n) && n > 1 ? n : null;
}

async function callViaQueue(t, payload, pj) {
  let rowNum = pj ? unpackPj(pj) : null;

  if (!rowNum) {
    const appended = await appendRequest(t, payload);
    rowNum = appended.rowNum;
    await new Promise(r => setTimeout(r, 2500));
    const quick = await readResult(rowNum);
    if (quick) return quick;
  } else {
    const result = await readResult(rowNum);
    if (result) return result;
  }

  return { ok: null, pending: true, pj: packPj(rowNum) };
}

async function getAllowedEmails() {
  const token = await getServiceAccountToken("https://www.googleapis.com/auth/spreadsheets.readonly");
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/configmail!A:A`;
  const res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  const data = await res.json();
  const rows = data.values || [];
  return rows
    .map(r => String((r && r[0]) || "").trim().toLowerCase())
    .filter(v => v.includes("@"));
}

module.exports = { callViaQueue, getAllowedEmails };
