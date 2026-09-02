import {
    importServerRSAKey,
    generateClientNonce,
    buildStage1Packet,
    parseStage1Response,
    verifyServerSignature,
    buildStage1PacketV2,
    parseStage1ResponseV2,
    generateECDHKeyPair,
    buildStage2Packet,
    buildStage2PacketV2,
    parseStage2ResponseV2,
    verifyTranscriptSignature,
    deriveDirectionalAESKeys,
    deriveSharedAESKey,
    encryptSecure,
    decryptSecure,
    importAsHMACKey,
    computeResumeProof,
} from "./handshake.js";

/**
 * A minimal transport abstraction: given a packet to send, resolve with the
 * next packet the server sends back. This package doesn't assume WebSocket,
 * fetch, or anything else — implement this however your transport works.
 *
 * For a WebSocket, a typical implementation queues incoming binary frames
 * and resolves the returned promise with the next one after send() is
 * called. See README.md for a full example.
 */
export interface HandshakeTransport {
    /** Send a binary packet and resolve with the server's next response. */
    sendAndReceive(packet: ArrayBuffer): Promise<ArrayBuffer>;
}

export interface HandshakeClientConfig {
    /** Base64-encoded DER (SPKI) RSA public key of the server. Not a secret
     * — but make sure you obtain it authentically (pin it / ship it in your
     * app config) rather than trusting it from an unauthenticated source. */
    serverPublicKeyB64: string;
    /** App-specific salt used in the resume-proof HMAC chain. Shared
     * out-of-band with your server (was previously read from
     * `VITE_SESSION_KEY` — now explicit so this package has no
     * bundler-specific dependency). Only needed if you use
     * `computeResumeProofFor`. */
    sessionSalt?: string;
    /**
     * Speak the deprecated v1 protocol instead of v2. v1's signature does
     * not cover the ECDH public keys exchanged in stage 2, so it does not
     * authenticate the key exchange against an active network attacker —
     * see the security advisory in HANDSHAKE_SPEC.md. Only set this while
     * migrating a server that hasn't rolled out v2 yet, and only over TLS.
     * Defaults to false (v2).
     */
    useLegacyV1?: boolean;
}

export interface EstablishedSession {
    /** Direction-separated AES-256-GCM keys for this connection. */
    clientToServerKey: CryptoKey;
    serverToClientKey: CryptoKey;
    /** @deprecated In v2 keys are directional. Alias for clientToServerKey (in v1 both directions shared this key). */
    aesKey?: CryptoKey;
    /** Server nonce from stage 1 — needed later for resume-proof
     * computation if your app supports session resumption. */
    serverNonce: Uint8Array;
    /** Encrypts payload for sending. seq must be unique and increasing per
     * direction (a simple counter is enough) — do not reuse a seq number
     * with the same key. */
    encrypt(seq: number | bigint, payload: Uint8Array): Promise<ArrayBuffer>;
    /** Decrypts a packet received from the server. */
    decrypt(packet: Uint8Array): Promise<{ plaintext: Uint8Array; seq: bigint }>;
}

/**
 * Creates a handshake client bound to a specific server public key. The
 * returned object performs no I/O itself — call `establish` with a
 * transport to actually run the handshake over a connection.
 *
 * ```ts
 * const client = createHandshakeClient({ serverPublicKeyB64: "..." });
 * const session = await client.establish(transport);
 * const packet = await session.encrypt(1, new TextEncoder().encode("hi"));
 * ```
 */
export function createHandshakeClient(config: HandshakeClientConfig) {
    return {
        /**
         * Runs the full two-stage handshake over the given transport and
         * returns an EstablishedSession. Throws if the server's signature
         * fails to verify or the response is malformed at either stage.
         *
         * Uses protocol v2 by default (full-transcript signing — see the
         * security advisory in HANDSHAKE_SPEC.md). Set
         * `config.useLegacyV1 = true` only to talk to a server still on the
         * deprecated v1 protocol during a migration window.
         */
        async establish(transport: HandshakeTransport): Promise<EstablishedSession> {
            const rsaKey = await importServerRSAKey(config.serverPublicKeyB64);

            if (config.useLegacyV1) {
                return establishV1(rsaKey, transport);
            }
            return establishV2(rsaKey, transport);
        },

        /**
         * Computes a session-resume proof for a previously established
         * session, to send to the server instead of re-running the full
         * handshake. Requires `sessionSalt` to have been set in the config.
         */
        async computeResumeProofFor(
            authKeyID: bigint,
            masterHmacKeyRaw: ArrayBuffer,
            serverNonce: Uint8Array
        ) {
            if (!config.sessionSalt) {
                throw new Error(
                    "wireauth: sessionSalt is required in createHandshakeClient config to compute a resume proof"
                );
            }
            const masterHmacKey = await importAsHMACKey(masterHmacKeyRaw);
            return computeResumeProof(
                authKeyID,
                masterHmacKey,
                serverNonce,
                config.sessionSalt
            );
        },
    };
}

async function establishV2(
    rsaKey: CryptoKey,
    transport: HandshakeTransport
): Promise<EstablishedSession> {
    // --- Stage 1: nonce exchange (unsigned in v2 — the signature moves to
    // stage 2, once both ECDH public keys are known) ---
    const clientNonce = generateClientNonce();
    const stage1Response = await transport.sendAndReceive(
        buildStage1PacketV2(clientNonce)
    );
    const parsed1 = parseStage1ResponseV2(new Uint8Array(stage1Response));
    if (!parsed1) {
        throw new Error("wireauth: stage 1 (v2) response too short");
    }
    const { serverNonce } = parsed1;

    // --- Stage 2: ECDH key exchange + full-transcript signature ---
    const keyPair = await generateECDHKeyPair();
    const clientPubKeyRaw = new Uint8Array(
        await crypto.subtle.exportKey("raw", keyPair.publicKey)
    );
    const stage2Response = await transport.sendAndReceive(
        await buildStage2PacketV2(keyPair)
    );
    const parsed2 = parseStage2ResponseV2(new Uint8Array(stage2Response));
    if (!parsed2) {
        throw new Error("wireauth: stage 2 (v2) response too short");
    }
    const { serverPubKeyRaw, signature } = parsed2;

    // The fix: verify the signature over the FULL transcript (both nonces
    // AND both public keys) before trusting anything derived from them.
    const validSignature = await verifyTranscriptSignature(
        rsaKey,
        clientNonce,
        serverNonce,
        clientPubKeyRaw,
        serverPubKeyRaw,
        signature
    );
    if (!validSignature) {
        throw new Error(
            "wireauth: transcript signature verification failed (possible MITM, wrong server public key, or substituted ECDH key)"
        );
    }

    const { clientToServerKey, serverToClientKey } = await deriveDirectionalAESKeys(
        serverPubKeyRaw,
        keyPair.privateKey,
        clientNonce,
        serverNonce
    );

    return {
        clientToServerKey,
        serverToClientKey,
        aesKey: clientToServerKey,
        serverNonce,
        encrypt: (seq, payload) => encryptSecure(clientToServerKey, seq, payload),
        decrypt: (packet) => decryptSecure(serverToClientKey, packet),
    };
}

/** @deprecated see the security advisory in HANDSHAKE_SPEC.md — v1's
 * signature does not authenticate the ECDH key exchange. Only reachable via
 * `useLegacyV1: true`, for migrating an existing v1 server. */
async function establishV1(
    rsaKey: CryptoKey,
    transport: HandshakeTransport
): Promise<EstablishedSession> {
    const clientNonce = generateClientNonce();
    const stage1Response = await transport.sendAndReceive(
        buildStage1Packet(clientNonce)
    );
    const parsed = parseStage1Response(new Uint8Array(stage1Response));
    if (!parsed) {
        throw new Error("wireauth: stage 1 response too short");
    }
    const { serverNonce, signature } = parsed;

    const validSignature = await verifyServerSignature(
        rsaKey,
        clientNonce,
        serverNonce,
        signature
    );
    if (!validSignature) {
        throw new Error(
            "wireauth: server signature verification failed (possible MITM or wrong server public key)"
        );
    }

    const keyPair = await generateECDHKeyPair();
    const stage2Response = await transport.sendAndReceive(
        await buildStage2Packet(keyPair)
    );

    const { sharedAESKey } = await deriveSharedAESKey(
        stage2Response,
        keyPair.privateKey,
        clientNonce,
        serverNonce
    );

    return {
        clientToServerKey: sharedAESKey,
        serverToClientKey: sharedAESKey,
        aesKey: sharedAESKey,
        serverNonce,
        encrypt: (seq, payload) => encryptSecure(sharedAESKey, seq, payload),
        decrypt: (packet) => decryptSecure(sharedAESKey, packet),
    };
}
