const rsaAlgorithm: RsaHashedKeyAlgorithm = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: {name: "SHA-256"}
}

export const CryptoFallback = {
  crypto: undefined satisfies Crypto | undefined
}

export const CryptoAes = {
  async getKey(password: string) {
    const subtle = await getSubtleImpl();
    
    const passwordHash = await CryptoSha.sha256(password);

    return await subtle.importKey(
      "raw",
      passwordHash,
      {name: "AES-GCM"},
      false,
      ["encrypt", "decrypt"]);
  },

  async encrypt(key: CryptoKey, message: string) {
    const subtle = await getSubtleImpl();
    const getRandomValues: Function = await getRandomValuesImpl();
    const Buffer = await getBufferImpl();

    const encodedMessage = new TextEncoder().encode(message);

    const iv = getRandomValues(new Uint8Array(12));
    const encryptedMessage = await subtle.encrypt(
      {
        name: "AES-GCM", 
        iv: iv
      }, 
      key, 
      encodedMessage);

    return Buffer.from(iv).toString("hex")
      + Buffer.from(encryptedMessage).toString("base64");
  },
  async decrypt(key: CryptoKey, encrypted: string) {
    const subtle = await getSubtleImpl();
    const Buffer = await getBufferImpl();

    const iv = Buffer.from(encrypted.slice(0, 24), "hex");
    const encodedMessage = Buffer.from(encrypted.slice(24), "base64");
    
    const decryptedMessage = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      key,
      encodedMessage);
    
    return Buffer.from(decryptedMessage).toString();
  }
}

export const CryptoRsa = {
  async generateKeys() {
    const subtle = await getSubtleImpl();
    const Buffer = await getBufferImpl();

    const key = await subtle.generateKey(
      rsaAlgorithm,
      true,
      ["encrypt", "decrypt"]
    );
    
    const publicKey = await subtle.exportKey(
      "spki", 
      key.publicKey);
    
    const privateKey = await subtle.exportKey(
      "pkcs8",
      key.privateKey);

    return {
      privateKey: key.privateKey,
      privateKeyBase64: Buffer.from(privateKey).toString("base64"),
      publicKey: key.publicKey,
      publicKeyBase64: Buffer.from(publicKey).toString("base64")
    }
  },

  async getPublicKeyFromBase64(publicKeyBase64: string) {
    const subtle = await getSubtleImpl();
    const Buffer = await getBufferImpl();

    return await subtle.importKey(
      "spki",
      Buffer.from(publicKeyBase64, "base64"),
      rsaAlgorithm,
      true,
      ["encrypt"])
  },
  async getPrivateKeyFromBase64(privateKeyBase64: string) {
    const subtle = await getSubtleImpl();
    const Buffer = await getBufferImpl();

    return await subtle.importKey(
      "pkcs8",
      Buffer.from(privateKeyBase64, "base64"),
      rsaAlgorithm,
      true,
      ["decrypt"])
  },
  
  async encrypt(publicKey: CryptoKey, message: string) {
    const subtle = await getSubtleImpl();
    const Buffer = await getBufferImpl();

    const encrypted = await subtle.encrypt(
      rsaAlgorithm,
      publicKey,
      Buffer.from(message));

    return Buffer.from(encrypted).toString("base64");
  },
  async decrypt(privateKey: CryptoKey, encrypted: string) {
    const subtle = await getSubtleImpl();
    const Buffer = await getBufferImpl();

    const decrypted = await subtle.decrypt(
      rsaAlgorithm,
      privateKey,
      Buffer.from(encrypted, "base64"));

      return Buffer.from(decrypted).toString()
  }
}

export const CryptoSha = {
  async sha256(text: string) {
    const subtle = await getSubtleImpl();

    return await subtle.digest(
      "SHA-256", 
      new TextEncoder().encode(text));
  },
  async sha256ToBase64(text: string) {
    const Buffer = await getBufferImpl();

    const r = await CryptoSha.sha256(text);
    return Buffer.from(r).toString("base64");
  },
  async sha256ToHex(text: string) {
    const Buffer = await getBufferImpl();
    
    const r = await CryptoSha.sha256(text);
    return Buffer.from(r).toString("hex");
  }
}

async function getSubtleImpl() {
  const crypto = await getCryptoImpl();
  return crypto.subtle;
}
async function getRandomValuesImpl() {
  const crypto = await getCryptoImpl();
  return crypto.getRandomValues;
}
async function getCryptoImpl() {
  if (typeof crypto !== "undefined") {
    return crypto;
  }

  if (typeof window !== "undefined") {
    return window.crypto;
  }

  if (typeof globalThis !== "undefined" && globalThis.crypto) {
    return globalThis.crypto;
  }

  return await import("crypto");
}
async function getBufferImpl() {
  if (typeof Buffer !== "undefined") {
    return Buffer;
  }

  if (typeof window !== "undefined") {
    return window.Buffer;
  }

  if (typeof globalThis !== "undefined" && globalThis.Buffer) {
    return globalThis.Buffer;
  }

  const r = await import("node:buffer");
  return r.Buffer;
}