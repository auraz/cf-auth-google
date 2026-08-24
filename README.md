# cf-auth-google

Drop-in Google OAuth for Cloudflare Workers. Sign-in with Google, signed session cookies, email allowlist plus profile mapping. ~400 lines, zero runtime dependencies.

## Install

```sh
npm install github:auraz/cf-auth-google
```

## Usage

```ts
import { googleAuth } from "cf-auth-google";

export interface Env {
  DB: D1Database;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  SESSION_KEY: string;
  ALLOWED_EMAILS: string;   // "kryklia@gmail.com,vira@gmail.com"
  PROFILE_MAP: string;      // '{"kryklia@gmail.com":"oleksandr","vira@gmail.com":"vira"}'
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const auth = googleAuth({
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      sessionKey: env.SESSION_KEY,
      allowedEmails: env.ALLOWED_EMAILS.split(","),
      profileMap: JSON.parse(env.PROFILE_MAP),
      sessionCookieDomain: "kryklia.com",
      appCallbackScheme: "morningedition",
    });

    const handled = await auth.handle(req);
    if (handled) return handled;

    return auth.protect(req, async (session) => {
      return new Response(`hello ${session.profile} (${session.email})`);
    });
  },
};
```

## Endpoints exposed

- `GET /auth/login?next=/some/path` — start the Google sign-in flow.
- `GET /auth/callback` — exchange the authorization code, set the session cookie, redirect to `next`.
- `GET /auth/logout` — clear the session cookie.

Override paths via `loginPath` / `callbackPath` / `logoutPath`.

## Configuration

| Field | Required | Description |
|---|---|---|
| `clientId` | yes | Google OAuth client ID |
| `clientSecret` | yes | Google OAuth client secret |
| `sessionKey` | yes | HMAC key for signing session cookies. ≥32 random bytes |
| `allowedEmails` | yes | Email addresses permitted to sign in |
| `profileMap` | yes | Email → profile string mapping (used by your handlers) |
| `loginPath` | no | default `/auth/login` |
| `callbackPath` | no | default `/auth/callback` |
| `logoutPath` | no | default `/auth/logout` |
| `cookieName` | no | default `kino_session` |
| `flowCookieName` | no | default `kino_flow` |
| `sessionCookieDomain` | no | parent domain used to share the session across sibling apps |
| `appCallbackScheme` | no | exact native callback scheme allowed as `next`, receiving the signed session token |
| `sessionMaxAgeSeconds` | no | default 7 days |
| `origin` | no | override the redirect_uri origin (useful for proxying) |

## Google Cloud setup (one time)

1. Open https://console.cloud.google.com/apis/credentials.
2. Create OAuth client ID, type **Web application**.
3. Authorized redirect URIs: `https://your-domain/auth/callback`.
4. Copy Client ID and Client Secret into your Worker secrets.
5. Generate a session key: `openssl rand -base64 32`.

## Security notes

- Session cookies are HTTP-only, Secure, SameSite=Lax by default; `sessionCookieDomain` can share them across trusted sibling hosts.
- ID tokens are verified against Google's JWK set (signature, issuer, audience, expiry, `email_verified`).
- PKCE (S256) is used for the authorization-code flow — not strictly required for confidential web clients, but doesn't hurt and prepares for future SPA usage.
- The flow cookie carries state + PKCE verifier and is cleared on success.
- Browser returns are restricted to same-origin paths; a configured native callback receives the session through its exact `scheme://auth` URL for system-browser login.
- `protect()` redirects browsers to `/auth/login`; API/JSON callers get `401 Unauthorized`.

## Testing

```sh
npm test
```

24 tests cover session signing/verification, cookie parsing/serialization, redirect validation, OAuth helpers, and PKCE generation.
