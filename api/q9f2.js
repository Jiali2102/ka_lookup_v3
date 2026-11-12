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

const LOOKUP_TYPES = new Set(["v1", "v2", "v3", "v4", "v5", "v6"]);

function kl2sRead(req) {
  const cookie = String(req.headers.cookie || "");
  const m = cookie.match(/(?:^|;\s*)kl2s=([^;]+)/);
  if (!m) return null;
  const [payload, sig] = decodeURIComponent(m[1]).split(".");
  if (!payload || !sig || !process.env.N8N_LOOKUP_V2_KEY) return null;
  const expected = kl2sSign(payload);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const [email, exp] = Buffer.from(payload, "base64url").toString().split("|");
  if (!email || Number(exp) * 1000 < Date.now()) return null;
  return email.toLowerCase();
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");

  if (!process.env.QUEUE_SHEET_ID || !process.env.GOOGLE_SA_KEY_JSON) {
    res.status(500).json({ ok: false, message: "Hệ thống chưa sẵn sàng, vui lòng báo admin." });
    return;
  }

  const qs = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
  const sp = new URLSearchParams(qs.slice(1));
  const q = Object.fromEntries(sp.entries());

  if (LOOKUP_TYPES.has(String(q.t || "")) && q.t !== "v1") {
    const sessionEmail = kl2sRead(req);
    if (!sessionEmail) {
      res.status(200).json({ ok: false, message: "Phiên đăng nhập đã hết hiệu lực hoặc đã bị thu hồi." });
      return;
    }
    q.e = sessionEmail;
  }

  try {
    const isPost = req.method === "POST";
    let body = null;
    if (isPost) {
      body = req.body;
      if (typeof body === "string") { try { body = JSON.parse(body); } catch (err) { body = null; } }
      if (!body || typeof body !== "object") body = {};
    }
    const safeBody = {};
    if (isPost && body) {
      if (body.c != null) safeBody.c = body.c;
      if (body.sum && typeof body.sum === "object") safeBody.sum = body.sum;
    }
    const payload = { ...q, ...safeBody };

    const data = await callViaQueue(q.t, payload, q.pj);

    try {
      if (LOOKUP_TYPES.has(String(q.t || "")) && q.e && data && data.pending !== true) {
        const passed = Array.isArray(data) || (data && data.ok !== false && (q.t !== "v1" || data.ok === true));
        if (passed) kl2sIssue(res, q.e);
      }
    } catch (err) {}

    res.status(200).json(data);
  } catch (err) {
    res.status(502).json({ ok: false, message: "Không kết nối được hệ thống, thử lại sau." });
  }
};

module.exports.config = { maxDuration: 20 };
