import { describe, it, expect } from "vitest";
import { CryptoFallback, CryptoAes } from "../src/index";
import crypto from "crypto";

CryptoFallback.crypto = crypto as any;

describe("AES", () => {
  it("Encrypt/Decrypt", async () => {
    const key = await CryptoAes.getKey("Hello");

    const text = "Hello World";
    const enc = await CryptoAes.encrypt(key, text);
    const dec = await CryptoAes.decrypt(key, enc);

    expect(dec).toBe(text);
  });
})