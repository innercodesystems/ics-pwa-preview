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
          configured: Boolean(env.PAYPAL_CLIENT_ID && env.PAYPAL_SECRET),
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
        return json({ paid, order: data }, r.status, cors);
      }

      return json({ error: "Not found" }, 404, cors);
    } catch (e) {
      return json({ error: "Serverfehler", detail: String(e?.message || e) }, 500, cors);
    }
  },
};
