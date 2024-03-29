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

    const encodedMessage = new TextEncoder().encode(message);

    const iv = getRandomValues(new Uint8Array(12));
    const encryptedMessage = await subtle.encrypt(
      {
        name: "AES-GCM", 
        iv: iv
      }, 
      key, 
      encodedMessage);

    return convertArrayBufferToHex(iv) + convertArrayBufferToBase64(encryptedMessage);
  },
  async decrypt(key: CryptoKey, encrypted: string) {
    const subtle = await getSubtleImpl();

    const iv = convertHexToArrayBuffer(encrypted.slice(0, 24));
    const encodedMessage = convertBase64ToArrayBuffer(encrypted.slice(24));
    
    const decryptedMessage = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      key,
      encodedMessage);
    
    return new TextDecoder().decode(decryptedMessage);
  }
}

export const CryptoRsa = {
  async generateKeys() {
    const subtle = await getSubtleImpl();

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
      privateKeyBase64: convertArrayBufferToBase64(privateKey),
      publicKey: key.publicKey,
      publicKeyBase64: convertArrayBufferToBase64(publicKey)
    }
  },

  async getPublicKeyFromBase64(publicKeyBase64: string) {
    const subtle = await getSubtleImpl();

    return await subtle.importKey(
      "spki",
      convertBase64ToArrayBuffer(publicKeyBase64),
      {
        name: rsaAlgorithm.name,
        hash: rsaAlgorithm.hash
      },
      false,
      ["encrypt"])
  },
  async getPrivateKeyFromBase64(privateKeyBase64: string) {
    const subtle = await getSubtleImpl();

    return await subtle.importKey(
      "pkcs8",
      convertBase64ToArrayBuffer(privateKeyBase64),
      {
        name: rsaAlgorithm.name,
        hash: rsaAlgorithm.hash
      },
      false,
      ["decrypt"])
  },
  
  async encrypt(publicKey: CryptoKey, message: string) {
    const subtle = await getSubtleImpl();

    const encrypted = await subtle.encrypt(
      rsaAlgorithm,
      publicKey,
      new TextEncoder().encode(message));

    return convertArrayBufferToBase64(encrypted);
  },
  async decrypt(privateKey: CryptoKey, encrypted: string) {
    const subtle = await getSubtleImpl();

    const decrypted = await subtle.decrypt(
      rsaAlgorithm,
      privateKey,
      convertBase64ToArrayBuffer(encrypted));

      return new TextDecoder().decode(decrypted);
  }
}

export const CryptoSha = {
  async sha256(text: string) {
    const subtle = await getSubtleImpl();

    return await subtle.digest(
      "SHA-256", 
      new TextEncoder().encode(text));
  },
  async sha256Base64(text: string) {
    const r = await CryptoSha.sha256(text);
    return convertArrayBufferToBase64(r);
  },
  async sha256Hex(text: string) {
    const r = await CryptoSha.sha256(text);
    return convertArrayBufferToHex(r);
  }
}

async function getSubtleImpl() {
  const crypto = await getCryptoImpl();
  return crypto.subtle;
}
async function getRandomValuesImpl() {
  const crypto = await getCryptoImpl();
  return crypto.getRandomValues.bind(crypto);
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

  return await import("node:crypto");
}

function convertArrayBufferToHex(buffer: ArrayBuffer) {
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}
function convertArrayBufferToBase64(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  
  let binary = "";
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  
  return btoa(binary);
}
function convertHexToArrayBuffer(hex: string) {
  return Uint8Array.from(hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
}
function convertBase64ToArrayBuffer(base64: string) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}