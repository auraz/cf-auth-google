/** Drop-in Google OAuth for Cloudflare Workers — issue and verify session cookies, gate handlers behind sign-in. */

import { clearCookie, parseCookies, serialize } from "./cookies";
import { AuthError, verifyIdToken } from "./idtoken";
import { buildAuthorizeUrl, exchangeCode, generatePkce, generateState } from "./oauth";
import { issue, verify, type SessionPayload } from "./session";

export type { SessionPayload } from "./session";
export { AuthError } from "./idtoken";
export { issue as issueSession, verify as verifySession } from "./session";
export { parseCookies } from "./cookies";

export type GoogleAuthConfig = {
  clientId: string;
  clientSecret: string;
  sessionKey: string;
  allowedEmails: string[];
  profileMap: Record<string, string>;
  loginPath?: string;
  callbackPath?: string;
  logoutPath?: string;
  sessionMaxAgeSeconds?: number;
  cookieName?: string;
  flowCookieName?: string;
  sessionCookieDomain?: string;
  origin?: string;
  fetcher?: typeof fetch;
};

const DEFAULTS = {
  loginPath: "/auth/login",
  callbackPath: "/auth/callback",
  logoutPath: "/auth/logout",
  cookieName: "kino_session",
  flowCookieName: "kino_flow",
  sessionMaxAgeSeconds: 7 * 24 * 60 * 60,
};

export type AuthHandle = {
  handle(req: Request): Promise<Response | null>;
  session(req: Request): Promise<SessionPayload | null>;
  protect(req: Request, handler: (session: SessionPayload) => Response | Promise<Response>): Promise<Response>;
  logoutResponse(): Response;
};

export function googleAuth(cfg: GoogleAuthConfig): AuthHandle {
  const opts = { ...DEFAULTS, ...cfg };
  const fetcher = cfg.fetcher ?? fetch;

  async function handle(req: Request): Promise<Response | null> {
    const url = new URL(req.url);
    if (url.pathname === opts.loginPath) return startLogin(req, url);
    if (url.pathname === opts.callbackPath) return finishLogin(req, url);
    if (url.pathname === opts.logoutPath) return logout();
    return null;
  }

  async function session(req: Request): Promise<SessionPayload | null> {
    const cookies = parseCookies(req.headers.get("cookie"));
    const token = cookies[opts.cookieName];
    if (!token) return null;
    return await verify(token, opts.sessionKey);
  }

  async function protect(req: Request, handler: (s: SessionPayload) => Response | Promise<Response>): Promise<Response> {
    const s = await session(req);
    if (s) return await handler(s);
    if (acceptsHtml(req)) return redirect(req, opts.loginPath);
    return new Response("unauthorized", { status: 401, headers: { "WWW-Authenticate": "Session" } });
  }

  function logoutResponse(): Response {
    return new Response(null, {
      status: 302,
      headers: { Location: "/", "Set-Cookie": clearCookie(opts.cookieName, { domain: opts.sessionCookieDomain }) },
    });
  }

  async function startLogin(req: Request, url: URL): Promise<Response> {
    const next = url.searchParams.get("next") || "/";
    const state = generateState();
    const { verifier, challenge } = await generatePkce();
    const flowPayload = b64encodeJson({ state, verifier, next });
    const redirectUri = `${origin(req)}${opts.callbackPath}`;
    const authorize = buildAuthorizeUrl({
      clientId: opts.clientId,
      redirectUri,
      state,
      codeChallenge: challenge,
    });
    return new Response(null, {
      status: 302,
      headers: {
        Location: authorize,
        "Set-Cookie": serialize(opts.flowCookieName, flowPayload, { maxAge: 600, sameSite: "Lax" }),
      },
    });
  }

  async function finishLogin(req: Request, url: URL): Promise<Response> {
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    if (!code || !state) return errorResponse("bad_request", "missing code or state");

    const cookies = parseCookies(req.headers.get("cookie"));
    const flowRaw = cookies[opts.flowCookieName];
    if (!flowRaw) return errorResponse("bad_request", "missing flow cookie");
    let flow: { state: string; verifier: string; next: string };
    try {
      flow = b64decodeJson(flowRaw);
    } catch {
      return errorResponse("bad_request", "corrupt flow cookie");
    }
    if (flow.state !== state) return errorResponse("bad_request", "state mismatch");

    let tokens;
    try {
      tokens = await exchangeCode(
        {
          clientId: opts.clientId,
          clientSecret: opts.clientSecret,
          redirectUri: `${origin(req)}${opts.callbackPath}`,
          code,
          codeVerifier: flow.verifier,
        },
        fetcher,
      );
    } catch (e) {
      return errorResponse("token_exchange_failed", String(e));
    }

    let claims;
    try {
      claims = await verifyIdToken(tokens.id_token, opts.clientId);
    } catch (e) {
      return errorResponse("invalid_id_token", String(e));
    }

    if (!claims.email || !claims.email_verified) return errorResponse("forbidden", "email not verified");
    const email = claims.email.toLowerCase();
    if (!opts.allowedEmails.map((e) => e.toLowerCase()).includes(email)) {
      return errorResponse("forbidden", `${email} is not in the allowlist`);
    }

    const profile = opts.profileMap[email];
    if (!profile) return errorResponse("forbidden", `no profile mapping for ${email}`);

    const exp = Math.floor(Date.now() / 1000) + opts.sessionMaxAgeSeconds;
    const cookie = await issue({ email, profile, exp }, opts.sessionKey);
    const headers = new Headers({ Location: flow.next || "/" });
    headers.append("Set-Cookie", serialize(opts.cookieName, cookie, { domain: opts.sessionCookieDomain, maxAge: opts.sessionMaxAgeSeconds }));
    headers.append("Set-Cookie", clearCookie(opts.flowCookieName));
    return new Response(null, { status: 302, headers });
  }

  function logout(): Response {
    return logoutResponse();
  }

  function origin(req: Request): string {
    if (opts.origin) return opts.origin;
    const url = new URL(req.url);
    return `${url.protocol}//${url.host}`;
  }

  function redirect(req: Request, location: string): Response {
    const next = encodeURIComponent(new URL(req.url).pathname + new URL(req.url).search);
    return new Response(null, { status: 302, headers: { Location: `${location}?next=${next}` } });
  }

  return { handle, session, protect, logoutResponse };
}

function acceptsHtml(req: Request): boolean {
  const accept = req.headers.get("accept") ?? "";
  return accept.includes("text/html");
}

function errorResponse(code: string, detail: string): Response {
  return new Response(`${code}: ${detail}`, { status: code === "forbidden" ? 403 : 400, headers: { "Content-Type": "text/plain" } });
}

function b64encodeJson(value: unknown): string {
  return btoa(unescape(encodeURIComponent(JSON.stringify(value))));
}

function b64decodeJson<T>(s: string): T {
  return JSON.parse(decodeURIComponent(escape(atob(s)))) as T;
}
