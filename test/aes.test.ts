import { describe, it, expect } from "vitest";
import { CryptoAes } from "../src/index";

describe("AES", () => {
  it("Encrypt/Decrypt", async () => {
    const key = await CryptoAes.getKey("Hello");

    const text = "Hello World";
    const enc = await CryptoAes.encrypt(key, text);
    const dec = await CryptoAes.decrypt(key, enc);

    expect(dec).toBe(text);
  });
})