module.exports = async (req, res) => {
  if (req.query && req.query.ping) {
    const target = process.env.N8N_WEBHOOK_URL;
    const key = String(process.env.N8N_LOOKUP_V2_KEY || "").trim().replace(/^["']|["']$/g, "");
    const out = { build: "m3k7-2026-11-04.11", at: new Date().toISOString(), hasUrl: Boolean(target), keyLen: key.length };
    if (target) {
      try {
        const host = new URL(target).host;
        out.host = host;
        const t0 = Date.now();
        const up = await fetch(`${target}?t=ping`, { method: "POST", headers: { ...(key ? { "x-kl-key": key } : {}), "content-type": "application/json", "accept": "application/json" }, body: "{}" });
        const raw = await up.text().catch(() => "");
        out.status = up.status;
        out.ms = Date.now() - t0;
        out.server = up.headers.get("server") || "";
        out.cfRay = up.headers.get("cf-ray") || "";
        out.cfMitigated = up.headers.get("cf-mitigated") || "";
        out.cloudflareChallenge = out.cfMitigated === "challenge" || /just a moment|cf-chl/i.test(raw);
        out.body = raw.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 200);
        out.verdict = out.cloudflareChallenge ? "Cloudflare vẫn đang chặn bằng trang kiểm tra" : up.status === 403 ? "Hệ thống từ chối (thường là sai mã khoá)" : up.status < 500 ? "Thông đường tới Hệ thống" : "Hệ thống lỗi";
      } catch (e) { out.error = String(e && e.message || e); }
    }
    res.setHeader("Cache-Control", "no-store");
    res.status(200).json(out);
    return;
  }

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
    let reqErr = "";
    const target = process.env.N8N_WEBHOOK_URL;
    if (!target) reqErr = "thiếu cấu hình hệ thống";
    else {
      const key = String(process.env.N8N_LOOKUP_V2_KEY || "").trim().replace(/^["']|["']$/g, "");
      const params = new URLSearchParams({ t: "v7", e: email });
      for (let attempt = 1; attempt <= 2 && !reqToken; attempt++) {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 12000);
        try {
          const up = await fetch(`${target}?${params.toString()}`, { method: "POST", headers: { ...(key ? { "x-kl-key": key } : {}), "content-type": "application/json", "accept": "application/json", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36" }, body: "{}", signal: ctrl.signal });
          const raw = await up.text().catch(() => "");
          let j = null;
          try { j = raw ? JSON.parse(raw) : null; } catch (e) { j = null; }
          if (j && j.ok === false) {
            clearTimeout(timer);
            res.status(200).json({ ok: false, message: j.message || "Tài khoản này không được cấp quyền truy cập." });
            return;
          }
          if (j && j.r) reqToken = String(j.r);
          else if (up.headers.get("cf-mitigated") === "challenge" || /just a moment|cf-chl/i.test(raw)) {
            reqErr = "lớp bảo vệ Cloudflare của Hệ thống chặn máy chủ Vercel";
            break;
          } else {
            const hint = String((j && (j.message || j.error)) || raw || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 90);
            reqErr = `hệ thống trả HTTP ${up.status}${hint ? `: ${hint}` : " không có dữ liệu"} · gọi POST · khoá ${key ? `${key.length} ký tự` : "TRỐNG"}`;
          }
        } catch (err) {
          reqErr = err && err.name === "AbortError" ? "hệ thống phản hồi quá 12 giây" : "không kết nối được hệ thống";
        } finally {
          clearTimeout(timer);
        }
      }
    }

        let vp = "";
    if (!reqToken && process.env.N8N_LOOKUP_V2_KEY) {
      const crypto = require("crypto");
      const exp = Math.floor(Date.now() / 1000) + 600;
      const payload = Buffer.from(`${email}|${exp}`).toString("base64url");
      vp = `${payload}.${crypto.createHmac("sha256", process.env.N8N_LOOKUP_V2_KEY).update(`v7|${payload}`).digest("base64url")}`;
    }
    res.status(200).json({ ok: true, email, name: String(data.name || "").slice(0, 80), r: reqToken, vp, rerr: reqToken ? "" : reqErr, build: "m3k7-2026-11-04.11" });
  } catch (err) {
    res.status(502).json({ ok: false, message: "Không xác minh được, thử lại." });
  }
};

module.exports.config = { maxDuration: 40 };
