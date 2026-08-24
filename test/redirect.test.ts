import { describe, expect, it } from "vitest";
import { safeNext, sessionLocation } from "../src/redirect";

describe("OAuth redirects", () => {
  it("keeps same-origin paths", () => {
    expect(safeNext("/api/me?fresh=1", "morningedition")).toBe("/api/me?fresh=1");
  });

  it("rejects external and protocol-relative redirects", () => {
    expect(safeNext("https://evil.example", "morningedition")).toBe("/");
    expect(safeNext("//evil.example", "morningedition")).toBe("/");
  });

  it("accepts only the configured native auth callback", () => {
    expect(safeNext("morningedition://auth", "morningedition")).toBe("morningedition://auth");
    expect(safeNext("other://auth", "morningedition")).toBe("/");
    expect(safeNext("morningedition://other", "morningedition")).toBe("/");
  });

  it("returns the signed session only through the native callback", () => {
    const location = new URL(sessionLocation("morningedition://auth", "signed.token", "morningedition"));
    expect(location.searchParams.get("session")).toBe("signed.token");
    expect(sessionLocation("/api/me", "signed.token", "morningedition")).toBe("/api/me");
  });
});
