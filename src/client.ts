import {
    importServerRSAKey,
    generateClientNonce,
    buildStage1Packet,
    parseStage1Response,
    verifyServerSignature,
    generateECDHKeyPair,
    buildStage2Packet,
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
}

export interface EstablishedSession {
    /** The derived AES-256-GCM key for this connection. */
    aesKey: CryptoKey;
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
         * fails to verify (stage 1) or the response is malformed at either
         * stage.
         */
        async establish(transport: HandshakeTransport): Promise<EstablishedSession> {
            const rsaKey = await importServerRSAKey(config.serverPublicKeyB64);

            // --- Stage 1: RSA challenge/response ---
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

            // --- Stage 2: ECDH key exchange ---
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
                aesKey: sharedAESKey,
                serverNonce,
                encrypt: (seq, payload) => encryptSecure(sharedAESKey, seq, payload),
                decrypt: (packet) => decryptSecure(sharedAESKey, packet),
            };
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