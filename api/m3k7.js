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

    let reqToken = null;
    const target = process.env.N8N_WEBHOOK_URL;
    if (target) {
      try {
        const key = String(process.env.N8N_LOOKUP_V2_KEY || "").trim().replace(/^["']|["']$/g, "");
        const params = new URLSearchParams({ t: "v7", e: email });
        const up = await fetch(`${target}?${params.toString()}`, { method: "GET", headers: key ? { "x-kl-key": key } : {} });
        const j = await up.json().catch(() => null);
        if (j && j.ok === false) {
          res.status(200).json({ ok: false, message: j.message || "Tài khoản này không được cấp quyền truy cập." });
          return;
        }
        reqToken = j && j.r ? String(j.r) : null;
      } catch (err) {
      }
    }

    res.status(200).json({ ok: true, email, name: String(data.name || "").slice(0, 80), r: reqToken });
  } catch (err) {
    res.status(502).json({ ok: false, message: "Không xác minh được, thử lại." });
  }
};
