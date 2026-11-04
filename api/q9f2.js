const crypto = require("crypto");

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

const LOOKUP_TYPES = new Set(["v1", "v2", "v3", "v4", "v5", "v6"]);

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");

  const target = process.env.N8N_WEBHOOK_URL;

  if (!target) {
    res.status(500).json({ ok: false, message: "Hệ thống chưa sẵn sàng, vui lòng báo admin." });
    return;
  }

  const qs = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
  let fwdQs = qs;
  try {
    const sp = new URLSearchParams(qs.slice(1));
    if (sp.get("t") === "v7") {
      const vp = String(sp.get("vp") || "");
      const [payload, sig] = vp.split(".");
      let ok = false;
      if (payload && sig && process.env.N8N_LOOKUP_V2_KEY) {
        const expected = crypto.createHmac("sha256", process.env.N8N_LOOKUP_V2_KEY).update(`v7|${payload}`).digest("base64url");
        if (sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
          const [em, exp] = Buffer.from(payload, "base64url").toString().split("|");
          ok = em && em === String(sp.get("e") || "").toLowerCase() && Number(exp) * 1000 > Date.now();
        }
      }
      if (!ok) {
        res.status(200).json({ ok: false, message: "Yêu cầu không hợp lệ." });
        return;
      }
      sp.delete("vp");
      fwdQs = `?${sp.toString()}`;
    }
  } catch (err) {
    res.status(200).json({ ok: false, message: "Yêu cầu không hợp lệ." });
    return;
  }

  try {
    const key = String(process.env.N8N_LOOKUP_V2_KEY || "").trim().replace(/^["']|["']$/g, "");
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
    const headers = { ...(key ? { "x-kl-key": key } : {}), "content-type": "application/json" };
    const upstream = await fetch(`${target}${fwdQs}`, { method: "POST", headers, body: JSON.stringify(safeBody) });
    const text = await upstream.text();
    let q = {};
    try { q = Object.fromEntries(new URLSearchParams(qs.slice(1))); } catch (err) { }

    try {
      if (upstream.ok && LOOKUP_TYPES.has(String(q.t || "")) && q.e) {
        const data = JSON.parse(text);
        const passed = Array.isArray(data) || (data && data.ok !== false && (q.t !== "v1" || data.ok === true));
        if (passed) kl2sIssue(res, q.e);
      }
    } catch (err) {
    }

    res.status(upstream.status);
    res.setHeader(
      "Content-Type",
      upstream.headers.get("content-type") || "application/json"
    );
    res.send(text);
  } catch (err) {
    res.status(502).json({ ok: false, message: "Không kết nối được hệ thống, thử lại sau." });
  }
};

module.exports.config = { maxDuration: 60 };
