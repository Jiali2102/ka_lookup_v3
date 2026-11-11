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

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");

  const idToken = req.query.i;
  if (!idToken) {
    res.status(400).json({ ok: false, message: "Thiếu token." });
    return;
  }

  const ALLOWED_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || "ghn.vn";
  const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";

  try {
    const r = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`
    );

    if (!r.ok) {
      res.status(200).json({ ok: false, message: "Token Google không hợp lệ hoặc đã hết hạn." });
      return;
    }

    const data = await r.json();

    if (GOOGLE_CLIENT_ID && data.aud !== GOOGLE_CLIENT_ID) {
      res.status(200).json({ ok: false, message: "Token không hợp lệ." });
      return;
    }

    const emailVerified = data.email_verified === "true" || data.email_verified === true;
    const email = String(data.email || "").toLowerCase();
    const domain = email.split("@")[1] || "";

    if (!emailVerified || domain !== ALLOWED_DOMAIN.toLowerCase()) {
      res.status(200).json({ ok: false, message: `Chỉ chấp nhận email công ty @${ALLOWED_DOMAIN}.` });
      return;
    }

    kl2sIssue(res, email);
    res.status(200).json({ ok: true, email, name: String(data.name || "").slice(0, 80) });
  } catch (err) {
    res.status(502).json({ ok: false, message: "Không xác minh được, thử lại." });
  }
};

module.exports.config = { maxDuration: 20 };
