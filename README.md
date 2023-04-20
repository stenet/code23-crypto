# code23-crypto

Simple WebCrypto for Browser and Node. Supports simple functions
for encrypting and decrypting data (RSA, AES) and hashing (SHA).

## Installation

```bash
npm install code23-crypto -S
```

```typescript
import { CryptoAes, CryptoRsa, CryptoSha } from "code23-crypto";
```

## Usage

### AES (Advanced Encryption Standard, symmetric encryption)

```typescript
const key = await CryptoAes.getKey("password");
const encrypted = await CryptoAes.encrypt(key, "Hello World");
const decrypted = await CryptoAes.decrypt(key, encrypted);
```

### RSA (Rivest–Shamir–Adleman, asymmetric encryption)

```typescript
const keys = await CrytoRsa.generateKeys();
const encrypted = await CrytoRsa.encrypt(key.publicKey, "Hello World");
const decrypted = await CrytoRsa.decrypt(key.privateKey, encrypted);

const publicKeyBase64 = keys.publicKeyBase64;
const publicKey = await CrytoRsa.getPublicKeyFromBase64(publicKeyBase64);

const privateKeyBase64 = keys.privateKeyBase64;
const privateKey = await CrytoRsa.getPrivateKeyFromBase64(privateKeyBase64);
```

### SHA (Secure Hash Algorithm, hashing)

```typescript
const sha = await CrytoSha.sha256("Hello World");
const shaBase64 = await CrytoSha.sha256ToBase64("Hello World");
const shaHex = await CrytoSha.sha256ToHex("Hello World");
```