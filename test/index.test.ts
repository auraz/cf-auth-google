import { describe, expect, it } from "vitest";
import { googleAuth } from "../src/index";

describe("googleAuth", () => {
  it("clears the session cookie on its configured parent domain", () => {
    const auth = googleAuth({
      clientId: "client",
      clientSecret: "secret",
      sessionKey: "test-secret-32-chars-long-aaaaaaa",
      allowedEmails: ["o@example.com"],
      profileMap: { "o@example.com": "oleksandr" },
      sessionCookieDomain: "kryklia.com",
    });
    expect(auth.logoutResponse().headers.get("set-cookie")).toContain("Domain=kryklia.com");
  });
});
