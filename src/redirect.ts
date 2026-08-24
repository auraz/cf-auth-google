/** Validate OAuth return locations and attach native session tokens only to the configured app callback. */

export function safeNext(raw: string | null, appScheme?: string): string {
  if (!raw) return "/";
  if (raw.startsWith("/") && !raw.startsWith("//")) return raw;
  if (!appScheme) return "/";
  try {
    const url = new URL(raw);
    return url.protocol === `${appScheme}:` && url.host === "auth" && (url.pathname === "" || url.pathname === "/") && !url.search && !url.hash ? raw : "/";
  } catch {
    return "/";
  }
}

export function sessionLocation(next: string, token: string, appScheme?: string): string {
  if (!appScheme || safeNext(next, appScheme) !== next || next.startsWith("/")) return next || "/";
  const url = new URL(next);
  url.searchParams.set("session", token);
  return url.toString();
}
