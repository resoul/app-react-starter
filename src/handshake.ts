/**
 * Low-level handshake primitives — direct port of the original
 * web/src/crypto/handshake.ts. Wire format is unchanged: see
 * HANDSHAKE_SPEC.md for the exact byte layout.
 *
 * These are stateless functions operating on Web Crypto API types
 * (CryptoKey, ArrayBuffer). Most consumers should use `createHandshakeClient`
 * from `./client.ts` instead — it wraps these into a stateful, easier-to-use
 * client. Use this module directly only if you need fine-grained control
 * over each stage.
 */

export function bufToHex(buffer: ArrayBuffer | Uint8Array): string {
    return Array.prototype.map
        .call(new Uint8Array(buffer as ArrayBuffer), (x: number) =>
            ("0" + x.toString(16)).slice(-2)
        )
        .join("");
}

/**
 * Imports a base64-encoded DER (SPKI) RSA public key for signature
 * verification. This is the server's PUBLIC key — it is not a secret, but
 * make sure you obtain it authentically (pin it, ship it with your app
 * config, etc.) rather than trusting an unauthenticated source at runtime.
 */
export async function importServerRSAKey(
    serverPublicKeyB64: string
): Promise<CryptoKey> {
    const binaryDerString = atob(serverPublicKeyB64);
    const binaryDer = new Uint8Array(binaryDerString.length);
    for (let i = 0; i < binaryDerString.length; i++) {
        binaryDer[i] = binaryDerString.charCodeAt(i);
    }
    return crypto.subtle.importKey(
        "spki",
        binaryDer.buffer,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
    );
}

export function generateClientNonce(): Uint8Array {
    const nonce = new Uint8Array(16);
    crypto.getRandomValues(nonce);
    return nonce;
}

export function buildStage1Packet(clientNonce: Uint8Array): ArrayBuffer {
    const packet = new Uint8Array(4 + 16);
    new DataView(packet.buffer).setUint32(0, 1, true);
    packet.set(clientNonce, 4);
    return packet.buffer;
}

export function parseStage1Response(
    responseBytes: Uint8Array
): { serverNonce: Uint8Array; signature: Uint8Array } | null {
    if (responseBytes.length < 16 + 256) return null;
    return {
        serverNonce: responseBytes.slice(0, 16),
        signature: responseBytes.slice(16, 16 + 256),
    };
}

export async function verifyServerSignature(
    rsaKey: CryptoKey,
    clientNonce: Uint8Array,
    serverNonce: Uint8Array,
    signature: Uint8Array
): Promise<boolean> {
    const dataToVerify = new Uint8Array(32);
    dataToVerify.set(clientNonce, 0);
    dataToVerify.set(serverNonce, 16);
    return crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        rsaKey,
        signature.buffer as ArrayBuffer,
        dataToVerify.buffer
    );
}

export interface ECDHKeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

export async function generateECDHKeyPair(): Promise<ECDHKeyPair> {
    const pair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey", "deriveBits"]
    );
    return pair as ECDHKeyPair;
}

export async function buildStage2Packet(
    keyPair: ECDHKeyPair
): Promise<ArrayBuffer> {
    const rawPubKey = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const packet = new Uint8Array(4 + rawPubKey.byteLength);
    new DataView(packet.buffer).setUint32(0, 2, true);
    packet.set(new Uint8Array(rawPubKey), 4);
    return packet.buffer;
}

export interface DerivedAESKey {
    sharedAESKey: CryptoKey;
    sharedAESKeyRaw: ArrayBuffer;
}

export async function deriveSharedAESKey(
    serverPubKeyRaw: ArrayBuffer,
    clientPrivateKey: CryptoKey,
    clientNonce: Uint8Array,
    serverNonce: Uint8Array
): Promise<DerivedAESKey> {
    const serverPubKey = await crypto.subtle.importKey(
        "raw",
        serverPubKeyRaw,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
    );

    const sharedBits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: serverPubKey },
        clientPrivateKey,
        256
    );

    const kdfMaterial = new Uint8Array(32 + 16 + 16);
    kdfMaterial.set(new Uint8Array(sharedBits), 0);
    kdfMaterial.set(clientNonce, 32);
    kdfMaterial.set(serverNonce, 32 + 16);

    const finalKeyHash = await crypto.subtle.digest("SHA-256", kdfMaterial.buffer);

    const sharedAESKey = await crypto.subtle.importKey(
        "raw",
        finalKeyHash,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );

    return { sharedAESKey, sharedAESKeyRaw: finalKeyHash };
}

export async function encryptSecure(
    key: CryptoKey,
    seq: number | bigint,
    payload: Uint8Array
): Promise<ArrayBuffer> {
    const seqBytes = new Uint8Array(8);
    new DataView(seqBytes.buffer).setBigUint64(0, BigInt(seq), false);

    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);

    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: seqBytes },
        key,
        payload as BufferSource
    );

    const packet = new Uint8Array(8 + 12 + ciphertext.byteLength);
    packet.set(seqBytes, 0);
    packet.set(nonce, 8);
    packet.set(new Uint8Array(ciphertext), 20);
    return packet.buffer;
}

export async function decryptSecure(
    key: CryptoKey,
    responseBytes: Uint8Array
): Promise<{ plaintext: Uint8Array; seq: bigint }> {
    const seqBytes = responseBytes.slice(0, 8);
    const nonce = responseBytes.slice(8, 20);
    const ciphertext = responseBytes.slice(20);

    const plaintextBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: seqBytes },
        key,
        ciphertext.buffer as ArrayBuffer
    );

    const seq = new DataView(
        seqBytes.buffer,
        seqBytes.byteOffset,
        8
    ).getBigUint64(0, false);

    return { plaintext: new Uint8Array(plaintextBuf), seq };
}

export async function importAsHMACKey(rawKey: ArrayBuffer): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
}

/**
 * Computes the two-step HMAC resume proof a client presents to resume a
 * previous session without re-running the full handshake.
 *
 * Wire note: authKeyID is encoded **little-endian** here — this differs
 * from the big-endian seq used in the AEAD framing above. See
 * HANDSHAKE_SPEC.md for the full byte layout and why this discrepancy is
 * intentional (matches the existing Swift/web implementations).
 *
 * sessionSalt is an app-specific secret/config value shared out-of-band
 * with your server (previously read from `VITE_SESSION_KEY` — now passed
 * in explicitly so this package has no bundler-specific dependency).
 */
export async function computeResumeProof(
    authKeyID: bigint,
    masterHmacKey: CryptoKey,
    serverNonce: Uint8Array,
    sessionSalt: string
): Promise<{ authKeyIDBytes: Uint8Array; proofA: Uint8Array; proofB: Uint8Array }> {
    const authKeyIDBytes = new Uint8Array(8);
    new DataView(authKeyIDBytes.buffer).setBigUint64(0, authKeyID, true);

    const salt = new TextEncoder().encode(sessionSalt);
    const proofA = new Uint8Array(
        await crypto.subtle.sign("HMAC", masterHmacKey, salt as BufferSource)
    );

    const keyA = await crypto.subtle.importKey(
        "raw",
        proofA,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const dataToSign = new Uint8Array(8 + 16);
    dataToSign.set(authKeyIDBytes, 0);
    dataToSign.set(serverNonce, 8);
    const proofB = new Uint8Array(
        await crypto.subtle.sign("HMAC", keyA, dataToSign)
    );

    return { authKeyIDBytes, proofA, proofB };
}