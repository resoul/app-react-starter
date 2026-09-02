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

// --- Protocol v1 (DEPRECATED) ---
//
// v1's stage-1 signature covers only client_nonce ‖ server_nonce — it never
// signs the ECDH public keys exchanged in stage 2, so it does not
// authenticate the key exchange itself. An active network attacker can
// substitute either party's ECDH public key without invalidating this
// signature. wireauth must run inside TLS if v1 is used at all. v1 is kept
// here only for talking to servers mid-migration; new code should use the
// v2 functions below. See the security advisory in HANDSHAKE_SPEC.md.

/** @deprecated use buildStage1PacketV2 — see the security advisory in HANDSHAKE_SPEC.md */
export function buildStage1Packet(clientNonce: Uint8Array): ArrayBuffer {
    const packet = new Uint8Array(4 + 16);
    new DataView(packet.buffer).setUint32(0, 1, true);
    packet.set(clientNonce, 4);
    return packet.buffer;
}

/** @deprecated use parseStage1ResponseV2 — see the security advisory in HANDSHAKE_SPEC.md */
export function parseStage1Response(
    responseBytes: Uint8Array
): { serverNonce: Uint8Array; signature: Uint8Array } | null {
    if (responseBytes.length !== 16 + 256) return null;
    return {
        serverNonce: responseBytes.slice(0, 16),
        signature: responseBytes.slice(16, 16 + 256),
    };
}

/** @deprecated the v1 signature never covered the ECDH public keys; verifying
 * it provides no protection against a substituted key. See the security
 * advisory in HANDSHAKE_SPEC.md and use verifyTranscriptSignature instead. */
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
        signature as BufferSource,
        dataToVerify as BufferSource
    );
}

/** @deprecated use buildStage2PacketV2 — see the security advisory in HANDSHAKE_SPEC.md */
export async function buildStage2Packet(
    keyPair: ECDHKeyPair
): Promise<ArrayBuffer> {
    const rawPubKey = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const packet = new Uint8Array(4 + rawPubKey.byteLength);
    new DataView(packet.buffer).setUint32(0, 2, true);
    packet.set(new Uint8Array(rawPubKey), 4);
    return packet.buffer;
}

// --- Protocol v2 (current) ---
//
// Fixes the v1 gap above by signing the full transcript — both nonces AND
// both ECDH public keys — once, after stage 2, before the client trusts the
// exchange. Substituting either public key now invalidates the signature.
// Same single RSA-verify cost as v1, just checked over more data and later
// in the flow. See HANDSHAKE_SPEC.md for the exact wire layout.

export function buildStage1PacketV2(clientNonce: Uint8Array): ArrayBuffer {
    const packet = new Uint8Array(4 + 16);
    new DataView(packet.buffer).setUint32(0, 101, true);
    packet.set(clientNonce, 4);
    return packet.buffer;
}

/** v2 stage-1 response is just the server nonce — no signature yet. */
export function parseStage1ResponseV2(
    responseBytes: Uint8Array
): { serverNonce: Uint8Array } | null {
    if (responseBytes.length !== 16) return null;
    return { serverNonce: responseBytes.slice(0, 16) };
}

export async function buildStage2PacketV2(
    keyPair: ECDHKeyPair
): Promise<ArrayBuffer> {
    const rawPubKey = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const packet = new Uint8Array(4 + rawPubKey.byteLength);
    new DataView(packet.buffer).setUint32(0, 102, true);
    packet.set(new Uint8Array(rawPubKey), 4);
    return packet.buffer;
}

/** v2 stage-2 response: server_pubkey (65 bytes) ‖ transcript signature (256 bytes). */
export function parseStage2ResponseV2(
    responseBytes: Uint8Array
): { serverPubKeyRaw: Uint8Array; signature: Uint8Array } | null {
    if (responseBytes.length !== 65 + 256) return null;
    return {
        serverPubKeyRaw: responseBytes.slice(0, 65),
        signature: responseBytes.slice(65, 65 + 256),
    };
}

/**
 * Verifies the v2 transcript signature: RSA-PKCS1v15-SHA256 over
 * client_nonce ‖ server_nonce ‖ client_pubkey_raw ‖ server_pubkey_raw. This
 * is the actual fix for the v1 gap — a substituted public key on either
 * side now invalidates the signature. Call this and check the result
 * BEFORE deriving or trusting the shared secret from deriveSharedAESKey.
 */
export async function verifyTranscriptSignature(
    rsaKey: CryptoKey,
    clientNonce: Uint8Array,
    serverNonce: Uint8Array,
    clientPubKeyRaw: Uint8Array,
    serverPubKeyRaw: Uint8Array,
    signature: Uint8Array
): Promise<boolean> {
    const dataToVerify = new Uint8Array(
        clientNonce.length + serverNonce.length + clientPubKeyRaw.length + serverPubKeyRaw.length
    );
    let offset = 0;
    dataToVerify.set(clientNonce, offset); offset += clientNonce.length;
    dataToVerify.set(serverNonce, offset); offset += serverNonce.length;
    dataToVerify.set(clientPubKeyRaw, offset); offset += clientPubKeyRaw.length;
    dataToVerify.set(serverPubKeyRaw, offset);
    return crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        rsaKey,
        signature as BufferSource,
        dataToVerify as BufferSource
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

export interface DerivedDirectionalAESKeys {
    clientToServerKey: CryptoKey;
    serverToClientKey: CryptoKey;
    clientToServerKeyRaw: ArrayBuffer;
    serverToClientKeyRaw: ArrayBuffer;
}

export async function deriveDirectionalAESKeys(
    serverPubKeyRaw: ArrayBuffer | Uint8Array,
    clientPrivateKey: CryptoKey,
    clientNonce: Uint8Array,
    serverNonce: Uint8Array
): Promise<DerivedDirectionalAESKeys> {
    const serverPubKey = await crypto.subtle.importKey(
        "raw",
        serverPubKeyRaw as BufferSource,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
    );

    const sharedBits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: serverPubKey },
        clientPrivateKey,
        256
    );

    const salt = new Uint8Array(clientNonce.length + serverNonce.length);
    salt.set(clientNonce, 0);
    salt.set(serverNonce, clientNonce.length);
    const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveBits"]);
    const derive = (info: string) => crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(info) },
        hkdfKey,
        256
    );
    const [clientToServerKeyRaw, serverToClientKeyRaw] = await Promise.all([
        derive("wireauth/v2/client-to-server"),
        derive("wireauth/v2/server-to-client"),
    ]);
    const importAES = (raw: ArrayBuffer) => crypto.subtle.importKey(
        "raw", raw,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
    const [clientToServerKey, serverToClientKey] = await Promise.all([
        importAES(clientToServerKeyRaw), importAES(serverToClientKeyRaw),
    ]);
    return { clientToServerKey, serverToClientKey, clientToServerKeyRaw, serverToClientKeyRaw };
}

export interface DerivedAESKey {
    sharedAESKey: CryptoKey;
    sharedAESKeyRaw: ArrayBuffer;
}

/** @deprecated v1 key derivation. v2 callers need direction-separated keys; use deriveDirectionalAESKeys. */
export async function deriveSharedAESKey(
    serverPubKeyRaw: ArrayBuffer | Uint8Array,
    clientPrivateKey: CryptoKey,
    clientNonce: Uint8Array,
    serverNonce: Uint8Array
): Promise<DerivedAESKey> {
    const serverPubKey = await crypto.subtle.importKey(
        "raw",
        serverPubKeyRaw as BufferSource,
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

    const finalKeyHash = await crypto.subtle.digest("SHA-256", kdfMaterial);

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
    if (responseBytes.length < 8 + 12 + 16) {
        throw new Error("wireauth: encrypted packet too short");
    }
    const seqBytes = responseBytes.slice(0, 8);
    const nonce = responseBytes.slice(8, 20);
    const ciphertext = responseBytes.slice(20);

    const plaintextBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: seqBytes },
        key,
        ciphertext as BufferSource
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
