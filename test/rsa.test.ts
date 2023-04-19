import { describe, it, expect } from "vitest";
import { CryptoFallback, CryptoRsa } from "../src/index";
import crypto from "crypto";

CryptoFallback.crypto = crypto as any;

describe("RSA", () => {
  it("Encode/Decode", async () => {
    const keys = await CryptoRsa.generateKeys();

    const text = "Hello World";
    const enc = await CryptoRsa.encrypt(keys.publicKey, text);
    const dec = await CryptoRsa.decrypt(keys.privateKey, enc);

    expect(dec).toBe(text);
  });

  it("Import/Export-Key", async () => {
    const keys = await CryptoRsa.generateKeys();

    const text = "Hello World";

    const publicKey = await CryptoRsa.getPublicKeyFromBase64(keys.publicKeyBase64);
    const enc = await CryptoRsa.encrypt(publicKey, text);

    const privateKey = await CryptoRsa.getPrivateKeyFromBase64(keys.privateKeyBase64);
    const dec = await CryptoRsa.decrypt(privateKey, enc);

    expect(dec).toBe(text);
  });
})