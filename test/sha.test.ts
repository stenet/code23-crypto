import { describe, it, expect } from "vitest";
import { CryptoFallback, CryptoSha } from "../src/index";
import crypto from "crypto";

CryptoFallback.crypto = crypto as any;

describe("SHA256", () => {
  it("ArrayBuffer", async () => {
    const v1 = await CryptoSha.sha256("hello");
    expect(v1).toBeInstanceOf(ArrayBuffer);
  });

  it("Base64", async () => {
    const v1 = await CryptoSha.sha256ToBase64("hello");
    expect(v1).toBe("LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
  });

  it("HEX", async () => {
    const v1 = await CryptoSha.sha256ToHex("hello");
    expect(v1).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });
})