const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";

function parseKeyMap(name: string): Record<string, string> {
  try {
    const value = JSON.parse(Deno.env.get(name) ?? "{}");
    return value && typeof value === "object" ? value : {};
  } catch {
    return {};
  }
}

const publishableMap = parseKeyMap("SUPABASE_PUBLISHABLE_KEYS");
const secretMap = parseKeyMap("SUPABASE_SECRET_KEYS");
const SERVICE_KEY =
  secretMap["default"] ??
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ??
  Deno.env.get("SUPABASE_SECRET_KEY") ??
  "";
const PUBLIC_KEYS = [
  publishableMap["default"],
  ...Object.values(publishableMap),
  Deno.env.get("SUPABASE_ANON_KEY"),
  Deno.env.get("SUPABASE_PUBLISHABLE_KEY"),
  // The matching publishable key is already public in index.html. Keep it
  // accepted even when this project's legacy anon-key env var is also set.
  "sb_publishable_z70GOIzu3F_xdxdJiVa48A_SqvrA6-b",
].filter((value): value is string => typeof value === "string" && value.length > 0);

const allowedOrigins = new Set([
  "https://www.playswiper.com",
  "https://playswiper.com",
  "http://localhost:3000",
  "http://127.0.0.1:5500",
]);

const headersFor = (origin: string | null) => ({
  "Access-Control-Allow-Origin": origin && allowedOrigins.has(origin) ? origin : "https://www.playswiper.com",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin",
});

function reply(origin: string | null, status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...headersFor(origin), "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

async function hmac(value: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(SERVICE_KEY),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function serviceRpc(name: string, args: Record<string, unknown>) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`, {
    method: "POST",
    headers: { "apikey": SERVICE_KEY, "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(args),
  });
  const raw = await response.text();
  let data: unknown = null;
  try { data = raw ? JSON.parse(raw) : null; } catch { data = null; }
  if (!response.ok) {
    const message = typeof data === "object" && data && "message" in data
      ? String((data as { message: unknown }).message)
      : "Backend request failed.";
    throw new Error(message);
  }
  return data;
}

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin");
  if (req.method === "OPTIONS") return new Response("ok", { status: 200, headers: headersFor(origin) });
  if (req.method !== "POST") return reply(origin, 405, { error: "Method not allowed." });
  if (origin && !allowedOrigins.has(origin)) return reply(origin, 403, { error: "Origin not allowed." });

  if (!SUPABASE_URL || !SERVICE_KEY || PUBLIC_KEYS.length === 0) {
    return reply(origin, 503, { error: "Sign-in is temporarily unavailable." });
  }
  const suppliedKey = req.headers.get("apikey") ?? "";
  if (!PUBLIC_KEYS.includes(suppliedKey)) {
    return reply(origin, 401, { error: "Sign-in request could not be verified." });
  }

  const length = Number(req.headers.get("content-length") ?? 0);
  if (length > 4096) return reply(origin, 413, { error: "Request is too large." });

  let body: { username?: unknown; password?: unknown; captchaToken?: unknown };
  try { body = await req.json(); }
  catch { return reply(origin, 400, { error: "Enter your username and password." }); }

  const username = typeof body.username === "string" ? body.username.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const captchaToken = typeof body.captchaToken === "string" ? body.captchaToken.trim() : "";
  if (!captchaToken || captchaToken.length > 8192) return reply(origin, 400, { error: "Complete the security check and try again." });
  if (!/^[a-z0-9_]{3,20}$/.test(username) || password.length < 1 || password.length > 1024) {
    return reply(origin, 400, { error: "Enter a valid username and password." });
  }

  try {
    const ip = (
      req.headers.get("cf-connecting-ip") ??
      req.headers.get("x-real-ip") ??
      req.headers.get("x-forwarded-for")?.split(",")[0] ??
      "unknown"
    ).trim().slice(0, 100);

    const [ipBucket, accountBucket, accountHash] = await Promise.all([
      hmac("swiper-username-login-ip:" + ip),
      hmac("swiper-username-login-account:" + ip + ":" + username),
      hmac("swiper-username-login-global-account:" + username),
    ]);
    const [ipAllowed, accountAllowed, globalAccountAllowed] = await Promise.all([
      serviceRpc("swiper_username_login_rate_limit", { p_bucket_key: ipBucket, p_limit: 40, p_window_seconds: 900 }),
      serviceRpc("swiper_username_login_rate_limit", { p_bucket_key: accountBucket, p_limit: 8, p_window_seconds: 900 }),
      serviceRpc("swiper_username_login_rate_limit", { p_bucket_key: accountHash, p_limit: 20, p_window_seconds: 900 }),
    ]);
    const auditAttempt = async (outcome: "success" | "invalid_credentials" | "unknown_account" | "rate_limited") => {
      try {
        await serviceRpc("swiper_auth_log_attempt", {
          p_account_hash: accountHash,
          p_ip_hash: ipBucket,
          p_outcome: outcome,
        });
      } catch {
        // An audit write must never expose account details or block sign-in.
      }
    };
    if (ipAllowed !== true || accountAllowed !== true || globalAccountAllowed !== true) {
      await auditAttempt("rate_limited");
      return reply(origin, 429, { error: "Too many sign-in attempts. Wait 15 minutes and try again." });
    }

    const email = await serviceRpc("swiper_auth_email_for_username", { p_username: username });
    if (typeof email !== "string" || !email.includes("@")) {
      await auditAttempt("unknown_account");
      return reply(origin, 401, { error: "Invalid username or password." });
    }

    // Use the public API key only in the apikey header. This works with both
    // legacy anon keys and the newer publishable keys without treating a
    // non-JWT publishable key as a Bearer token.
    const authResponse = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { "apikey": suppliedKey, "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, gotrue_meta_security: { captcha_token: captchaToken } }),
    });
    const session = await authResponse.json().catch(() => null);
    if (!authResponse.ok || !session?.access_token || !session?.refresh_token) {
      await auditAttempt("invalid_credentials");
      return reply(origin, 401, { error: "Invalid username or password." });
    }

    await auditAttempt("success");
    return reply(origin, 200, {
      access_token: session.access_token,
      refresh_token: session.refresh_token,
      token_type: session.token_type,
      expires_at: session.expires_at,
    });
  } catch (error) {
    console.error("Username sign-in backend failure:", error instanceof Error ? error.message : "Unknown error");
    return reply(origin, 503, { error: "Sign-in is temporarily unavailable. Try your email address." });
  }
});