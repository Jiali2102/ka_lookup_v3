const crypto = require("crypto");
const { callViaQueue } = require("../lib/sheet-queue");

const KL2S_NAME = "kl2s";
const KL2S_TTL = 12 * 60 * 60;

function kl2sSign(payload) {
  return crypto.createHmac("sha256", process.env.N8N_LOOKUP_V2_KEY || "").update(payload).digest("base64url");
}

function kl2sIssue(res, email) {
  if (!process.env.N8N_LOOKUP_V2_KEY || !email) return;
  const exp = Math.floor(Date.now() / 1000) + KL2S_TTL;
  const payload = Buffer.from(`${String(email).toLowerCase()}|${exp}`).toString("base64url");
  res.setHeader("Set-Cookie", `${KL2S_NAME}=${payload}.${kl2sSign(payload)}; Path=/api; Max-Age=${KL2S_TTL}; HttpOnly; Secure; SameSite=Strict`);
}

function kl2sRead(req) {
  if (!process.env.N8N_LOOKUP_V2_KEY) return null;
  const m = String(req.headers.cookie || "").match(/(?:^|;\s*)kl2s=([^;]+)/);
  if (!m) return null;
  const [payload, sig] = m[1].split(".");
  if (!payload || !sig) return null;
  const expected = kl2sSign(payload);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const [email, exp] = Buffer.from(payload, "base64url").toString().split("|");
  if (!email || Number(exp) * 1000 < Date.now()) return null;
  return { email, exp: Number(exp) };
}

const LOOKUP_KEY_RAW = process.env.N8N_LOOKUP_V2_KEY || "";
const LOOKUP_KEY = LOOKUP_KEY_RAW.trim().replace(/^["']|["']$/g, "");
const AUTH_CHECK_TYPE = process.env.AUTH_CHECK_TYPE || "v3";

async function verifyByKacSupport(email, password) {
  let data = await callViaQueue(AUTH_CHECK_TYPE, { t: AUTH_CHECK_TYPE, c: "AUTHCHECK0", e: email, k: password });
  let tries = 0;
  while (data && data.pending === true && tries < 6) {
    await new Promise(r => setTimeout(r, 2500));
    data = await callViaQueue(AUTH_CHECK_TYPE, { t: AUTH_CHECK_TYPE, c: "AUTHCHECK0", e: email, k: password }, data.pj);
    tries++;
  }
  if (data === null || (data && data.pending === true)) return false;
  return Array.isArray(data) || data.ok !== false;
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  const missing = [
    ["N8N_LOOKUP_V2_KEY", LOOKUP_KEY],
    ["QUEUE_SHEET_ID", process.env.QUEUE_SHEET_ID],
    ["GOOGLE_SA_KEY_JSON", process.env.GOOGLE_SA_KEY_JSON]
  ].filter(([, v]) => !v).map(([k]) => k);
  if (req.method === "GET") {
    const s = kl2sRead(req);
    res.status(200).json({
      ok: missing.length === 0,
      version: "2026-11-12.1",
      missing,
      key_len: LOOKUP_KEY.length,
      key_fp: LOOKUP_KEY ? crypto.createHash("sha256").update(LOOKUP_KEY).digest("hex").slice(0, 8) : "",
      key_had_spaces_or_quotes: LOOKUP_KEY !== LOOKUP_KEY_RAW,
      session: s ? s.email : null
    });
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({ ok: false, message: "Chỉ hỗ trợ POST." });
    return;
  }
  if (missing.length) {
    res.status(500).json({ ok: false, message: `Vercel chưa có biến môi trường: ${missing.join(", ")}. Thêm ở Settings → Environment Variables (Production) rồi Redeploy.` });
    return;
  }
  const { c, e, k, q, kind, summary, pj } = req.body || {};
  const isLog = kind === "log";
  const email = String(e || "").toLowerCase();
  const codes = (Array.isArray(c) ? c : String(c || "").split(/[\s,;]+/)).filter(Boolean);
  if (!email) {
    res.status(401).json({ ok: false, message: "Phiên đăng nhập không hợp lệ, vui lòng đăng nhập lại." });
    return;
  }
  if (!isLog && !codes.length) {
    res.status(400).json({ ok: false, message: "Thiếu danh sách mã đơn." });
    return;
  }
  const session = kl2sRead(req);
  if (!session || session.email !== email) {
    let okUser = false;
    try {
      okUser = Boolean(k) && await verifyByKacSupport(email, String(k));
    } catch (err) {
      res.status(502).json({ ok: false, message: "Không xác thực được, thử lại." });
      return;
    }
    if (!okUser) {
      res.status(401).json({ ok: false, message: "Phiên đăng nhập không hợp lệ, vui lòng đăng xuất rồi đăng nhập lại." });
      return;
    }
    kl2sIssue(res, email);
  }
  try {
    const payload = isLog
      ? { t: "lookupv2", action: "log", email, summary: summary || {} }
      : { t: "lookupv2", codes, email, quiet: Boolean(q) };
    const data = await callViaQueue("lookupv2", payload, pj);
    res.status(200).json(data);
  } catch (err) {
    res.status(504).json({ ok: false, message: "Không kết nối được hệ thống, thử lại sau." });
  }
};

module.exports.config = { maxDuration: 20 };
