/**
 * 4K Shop - Cloudflare Workers API Gateway
 * Upstream: https://4k-shop.vercel.app
 *
 * Features:
 * - Allowlist API routes
 * - HTTP method restrictions
 * - Request body size limit
 * - Origin validation
 * - Security response headers
 * - Block arbitrary proxy destinations
 *
 * IMPORTANT:
 * This Worker does not replace backend authentication.
 * The original Vercel URL remains directly accessible.
 */

const UPSTREAM = "https://4k-shop.vercel.app";

const ALLOWED_ORIGINS = new Set([
  "https://4k-shop.vercel.app",
]);

// อนุญาตเฉพาะ API ที่กำหนดไว้
const ROUTES = new Map([
  ["/api/products", new Set(["GET", "HEAD"])],
  ["/api/site-status", new Set(["GET", "HEAD"])],
  ["/api/orders", new Set(["POST"])],
  ["/api/order-chat", new Set(["GET", "POST"])],
  ["/api/admin/login", new Set(["POST"])],
  ["/api/admin/data", new Set(["GET", "POST"])],
  ["/api/admin/payment", new Set(["GET", "POST"])],
  ["/api/admin/integration-test", new Set(["POST"])],
]);

const MAX_BODY_BYTES = 1_000_000;

const ALLOWED_METHODS = new Set([
  "GET",
  "HEAD",
  "POST",
  "OPTIONS",
]);

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      ...extraHeaders,
    },
  });
}

function addSecurityHeaders(headers) {
  const result = new Headers(headers);

  result.set("X-Content-Type-Options", "nosniff");
  result.set("X-Frame-Options", "DENY");
  result.set("Referrer-Policy", "no-referrer");
  result.set("Cache-Control", "no-store");

  result.delete("Server");

  return result;
}

export default {
  async fetch(request) {
    const incoming = new URL(request.url);
    const origin = request.headers.get("Origin");
    const method = request.method.toUpperCase();

    // 1. จำกัด HTTP methods
    if (!ALLOWED_METHODS.has(method)) {
      return json(
        { error: "Method not allowed" },
        405,
        { Allow: "GET, HEAD, POST, OPTIONS" }
      );
    }

    // 2. อนุญาตเฉพาะเส้นทาง API ที่กำหนด
    const allowedMethods = ROUTES.get(incoming.pathname);

    if (!allowedMethods) {
      return json({ error: "Not found" }, 404);
    }

    // 3. ตรวจสอบ Origin
    if (origin && !ALLOWED_ORIGINS.has(origin)) {
      return json({ error: "Origin not allowed" }, 403);
    }

    // 4. จัดการ CORS preflight
    if (method === "OPTIONS") {
      const headers = {
        "Access-Control-Allow-Methods":
          [...allowedMethods].join(", "),
        "Access-Control-Allow-Headers":
          "Content-Type, Authorization",
        "Access-Control-Max-Age": "600",
        "Vary": "Origin",
      };

      if (origin && ALLOWED_ORIGINS.has(origin)) {
        headers["Access-Control-Allow-Origin"] = origin;
        headers["Access-Control-Allow-Credentials"] = "true";
      }

      return new Response(null, {
        status: 204,
        headers,
      });
    }

    // 5. ตรวจสอบ HTTP method ของแต่ละ API
    if (!allowedMethods.has(method)) {
      return json(
        { error: "Method not allowed" },
        405,
        { Allow: [...allowedMethods].join(", ") }
      );
    }

    // 6. จำกัดขนาด request body
    const contentLength = Number(
      request.headers.get("Content-Length") || "0"
    );

    if (
      !Number.isFinite(contentLength) ||
      contentLength > MAX_BODY_BYTES
    ) {
      return json({ error: "Request body too large" }, 413);
    }

    // 7. ส่งคำขอไปยัง Vercel โดยใช้ host ที่กำหนดตายตัว
    const upstreamUrl = new URL(
      incoming.pathname + incoming.search,
      UPSTREAM
    );

    const headers = new Headers(request.headers);

    headers.delete("Host");
    headers.delete("Cookie");
    headers.delete("CF-Connecting-IP");
    headers.delete("X-Forwarded-Host");

    headers.set("X-Forwarded-Host", "4k-shop.vercel.app");

    // ไม่ส่ง body สำหรับ GET และ HEAD
    const body =
      method === "GET" || method === "HEAD"
        ? undefined
        : request.body;

    let upstreamResponse;

    try {
      upstreamResponse = await fetch(upstreamUrl, {
        method,
        headers,
        body,
        redirect: "manual",
      });
    } catch {
      return json({ error: "Upstream unavailable" }, 502);
    }

    // 8. ป้องกันการส่งต่อ redirect ไปยังปลายทางอื่น
    if (
      upstreamResponse.status >= 300 &&
      upstreamResponse.status < 400
    ) {
      return json({ error: "Upstream redirect blocked" }, 502);
    }

    // 9. เพิ่ม security headers
    const responseHeaders = addSecurityHeaders(
      upstreamResponse.headers
    );

    // 10. ตั้งค่า CORS สำหรับ Origin ที่อนุญาต
    if (origin && ALLOWED_ORIGINS.has(origin)) {
      responseHeaders.set(
        "Access-Control-Allow-Origin",
        origin
      );

      responseHeaders.set(
        "Access-Control-Allow-Credentials",
        "true"
      );

      responseHeaders.append("Vary", "Origin");
    }

    // 11. ส่งผลลัพธ์กลับ
    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });
  },
};