import { describe, expect, it } from "vitest";
import { clearCookie, parseCookies, serialize } from "../src/cookies";

describe("cookies", () => {
  it("parses a multi-cookie header", () => {
    expect(parseCookies("a=1; b=hello%20world; c=")).toEqual({ a: "1", b: "hello world", c: "" });
  });

  it("returns empty object for null/empty", () => {
    expect(parseCookies(null)).toEqual({});
    expect(parseCookies("")).toEqual({});
  });

  it("serializes safe defaults: HttpOnly, Secure, SameSite=Lax, Path=/", () => {
    const cookie = serialize("session", "abc");
    expect(cookie).toContain("session=abc");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
  });

  it("includes Max-Age when set", () => {
    expect(serialize("x", "1", { maxAge: 60 })).toContain("Max-Age=60");
  });

  it("includes Domain when set", () => {
    expect(serialize("x", "1", { domain: "kryklia.com" })).toContain("Domain=kryklia.com");
  });

  it("clearCookie produces Max-Age=0", () => {
    expect(clearCookie("x")).toContain("Max-Age=0");
  });

  it("URL-encodes the value", () => {
    expect(serialize("x", "a b/c=")).toContain("x=a%20b%2Fc%3D");
  });
});
