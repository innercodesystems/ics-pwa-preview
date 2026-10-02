const PAYPAL_BASE = "https://api-m.sandbox.paypal.com";

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extra,
    },
  });

const cors = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "content-type",
};

async function ensureDb(env) {
  if (!env.DB) throw new Error("D1-Bindung DB fehlt");
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS access_tokens (
    token TEXT PRIMARY KEY,
    order_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
  )`).run();
}
function newAccessToken(){
  const a=new Uint8Array(32);crypto.getRandomValues(a);
  return Array.from(a,b=>b.toString(16).padStart(2,"0")).join("");
}

async function accessToken(env) {
  const credentials = btoa(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_SECRET}`);
  const r = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });
  if (!r.ok) throw new Error(`PayPal OAuth failed: ${r.status}`);
  return (await r.json()).access_token;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    try {
      if (url.pathname === "/" || url.pathname === "/health") {
        return json({
          ok: true,
          service: "INNER CODE PayPal",
          mode: "sandbox",
          configured: Boolean(env.PAYPAL_CLIENT_ID && env.PAYPAL_SECRET && env.DB),
        }, 200, cors);
      }

      if (url.pathname === "/api/paypal/client-id" && request.method === "GET") {
        if (!env.PAYPAL_CLIENT_ID) return json({ error: "PAYPAL_CLIENT_ID fehlt" }, 500, cors);
        return json({ clientId: env.PAYPAL_CLIENT_ID, currency: "EUR", amount: "49.00" }, 200, cors);
      }

      if (url.pathname === "/api/paypal/orders" && request.method === "POST") {
        const token = await accessToken(env);
        const r = await fetch(`${PAYPAL_BASE}/v2/checkout/orders`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
            "PayPal-Request-Id": crypto.randomUUID(),
          },
          body: JSON.stringify({
            intent: "CAPTURE",
            purchase_units: [{
              description: "INNER CODE – persönlicher Report",
              amount: { currency_code: "EUR", value: "49.00" },
            }],
          }),
        });
        const data = await r.json();
        return json(data, r.status, cors);
      }

      const capture = url.pathname.match(/^\/api\/paypal\/orders\/([^/]+)\/capture$/);
      if (capture && request.method === "POST") {
        const token = await accessToken(env);
        const orderId = encodeURIComponent(capture[1]);
        const r = await fetch(`${PAYPAL_BASE}/v2/checkout/orders/${orderId}/capture`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: "{}",
        });
        const data = await r.json();
        const paid = r.ok && data.status === "COMPLETED";
        if (!paid) return json({ paid: false, order: data }, r.status, cors);
        await ensureDb(env);
        const rawOrderId = capture[1];
        const payerEmail = String(data?.payer?.email_address || "").trim().toLowerCase();
        let row = await env.DB.prepare("SELECT token FROM access_tokens WHERE order_id = ?").bind(rawOrderId).first();
        let accessTokenValue = row?.token;
        if (!accessTokenValue) {
          accessTokenValue = newAccessToken();
          await env.DB.prepare("INSERT INTO access_tokens (token, order_id, created_at, status, payer_email) VALUES (?, ?, ?, 'active', ?)")
            .bind(accessTokenValue, rawOrderId, new Date().toISOString(), payerEmail || null).run();
        } else if (payerEmail) {
          await env.DB.prepare("UPDATE access_tokens SET payer_email=? WHERE order_id=?").bind(payerEmail, rawOrderId).run();
        }
        return json({ paid: true, accessToken: accessTokenValue, payerEmail }, 200, cors);
      }

      if (url.pathname === "/api/access/recover" && request.method === "POST") {
        const body = await request.json().catch(()=>({}));
        const email = String(body.email || "").trim().toLowerCase();
        if (!email || !email.includes("@")) return json({ found: false }, 200, cors);
        await ensureDb(env);
        let row = await env.DB.prepare("SELECT token FROM access_tokens WHERE payer_email = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1").bind(email).first();
        if (!row?.token) {
          const legacy = await env.DB.prepare("SELECT token, order_id FROM access_tokens WHERE (payer_email IS NULL OR payer_email = '') AND status = 'active' ORDER BY created_at DESC LIMIT 20").all();
          if (legacy.results?.length) {
            const ppToken = await accessToken(env);
            for (const item of legacy.results) {
              const pr = await fetch(PAYPAL_BASE + "/v2/checkout/orders/" + encodeURIComponent(item.order_id), {headers:{Authorization:"Bearer " + ppToken}});
              if (!pr.ok) continue;
              const pd = await pr.json();
              const pe = String(pd?.payer?.email_address || "").trim().toLowerCase();
              if (pe && pe === email) {
                await env.DB.prepare("UPDATE access_tokens SET payer_email=? WHERE order_id=?").bind(email,item.order_id).run();
                row = {token:item.token};
                break;
              }
            }
          }
        }
        return json({ found: Boolean(row?.token), accessToken: row?.token || null }, 200, cors);
      }

      if (url.pathname === "/api/access/verify" && request.method === "POST") {
        const body = await request.json().catch(()=>({}));
        const accessTokenValue = String(body.token || "");
        const email = String(body.email || "").trim().toLowerCase();
        if (!/^[a-f0-9]{64}$/.test(accessTokenValue) || !email) return json({ valid: false }, 200, cors);
        await ensureDb(env);
        const row = await env.DB.prepare("SELECT status, payer_email FROM access_tokens WHERE token = ?").bind(accessTokenValue).first();
        return json({ valid: Boolean(row && row.status === "active" && row.payer_email && row.payer_email === email) }, 200, cors);
      }

      return json({ error: "Not found" }, 404, cors);
    } catch (e) {
      return json({ error: "Serverfehler", detail: String(e?.message || e) }, 500, cors);
    }
  },
};
