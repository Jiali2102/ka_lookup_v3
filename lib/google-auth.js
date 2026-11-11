let cached = null;

async function getAccessToken() {
  const now = Date.now();
  if (cached && cached.exp > now + 60000) return cached.token;
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: process.env.GOOGLE_OAUTH_CLIENT_ID,
      client_secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
      refresh_token: process.env.GOOGLE_OAUTH_REFRESH_TOKEN,
      grant_type: "refresh_token"
    })
  });
  const data = await res.json().catch(() => null);
  if (!res.ok || !data || !data.access_token) {
    throw new Error("Không lấy được access token Google: " + ((data && (data.error_description || data.error)) || res.status));
  }
  cached = { token: data.access_token, exp: now + (Number(data.expires_in || 3600) * 1000) };
  return cached.token;
}

module.exports = { getAccessToken };
