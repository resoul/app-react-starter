import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import {
    createHandshakeClient,
    type HandshakeTransport,
    encryptSecure,
    decryptSecure,
} from "../dist/esm/index.js";

function concat(...values: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(values.reduce((n, value) => n + value.length, 0));
    let offset = 0;
    for (const value of values) {
        out.set(value, offset);
        offset += value.length;
    }
    return out;
}

interface ServerState {
    publicKeyDerB64: string;
    privateKey: any;
    serverNonce: Uint8Array;
    serverECDH: CryptoKeyPair;
    serverPubRaw: Uint8Array;
}

async function setupTestServer(): Promise<ServerState> {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const der = publicKey.export({ type: "spki", format: "der" });
    const publicKeyDerB64 = der.toString("base64");

    const serverNonce = new Uint8Array(16);
    crypto.getRandomValues(serverNonce);

    const serverECDH = (await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
    )) as CryptoKeyPair;
    const serverPubRaw = new Uint8Array(
        await crypto.subtle.exportKey("raw", serverECDH.publicKey)
    );

    return { publicKeyDerB64, privateKey, serverNonce, serverECDH, serverPubRaw };
}

test("createHandshakeClient establishes v2 session and encrypts/decrypts bidirectionally", async () => {
    const server = await setupTestServer();
    let clientNonce: Uint8Array = new Uint8Array(0);
    let clientPubRaw: Uint8Array = new Uint8Array(0);

    const transport: HandshakeTransport = {
        async sendAndReceive(packet: ArrayBuffer): Promise<ArrayBuffer> {
            const data = new Uint8Array(packet);
            const cmd = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, true);

            if (cmd === 101) {
                // Stage 1: client sends client_nonce (16 bytes)
                assert.equal(data.length, 20);
                clientNonce = data.slice(4);
                // Server responds with server_nonce (16 bytes)
                return server.serverNonce.buffer as ArrayBuffer;
            }

            if (cmd === 102) {
                // Stage 2: client sends client_pubkey (65 bytes)
                assert.equal(data.length, 69);
                clientPubRaw = data.slice(4);

                // Server signs: client_nonce ‖ server_nonce ‖ client_pub ‖ server_pub
                const transcript = concat(
                    clientNonce,
                    server.serverNonce,
                    clientPubRaw,
                    server.serverPubRaw
                );
                const signature = new Uint8Array(nodeSign("sha256", transcript, server.privateKey));
                const response = concat(server.serverPubRaw, signature);
                return response.buffer as ArrayBuffer;
            }

            throw new Error(`Unexpected cmd: ${cmd}`);
        },
    };

    const client = createHandshakeClient({
        serverPublicKeyB64: server.publicKeyDerB64,
        sessionSalt: "app-salt",
    });

    const session = await client.establish(transport);
    assert.ok(session.clientToServerKey);
    assert.ok(session.serverToClientKey);
    assert.ok(session.aesKey); // backwards compatibility alias
    assert.deepEqual(session.serverNonce, server.serverNonce);

    // Derive the server's traffic keys to verify bidirectional communication
    const serverSharedBits = await crypto.subtle.deriveBits(
        {
            name: "ECDH",
            public: await crypto.subtle.importKey(
                "raw",
                clientPubRaw,
                { name: "ECDH", namedCurve: "P-256" },
                false,
                []
            ),
        },
        server.serverECDH.privateKey,
        256
    );

    const salt = concat(clientNonce, server.serverNonce);
    const hkdf = await crypto.subtle.importKey("raw", serverSharedBits, "HKDF", false, ["deriveBits"]);
    const derive = (info: string) =>
        crypto.subtle.deriveBits(
            { name: "HKDF", hash: "SHA-256", salt: salt.buffer as ArrayBuffer, info: new TextEncoder().encode(info) },
            hkdf,
            256
        );

    const [serverC2SRaw, serverS2CRaw] = await Promise.all([
        derive("wireauth/v2/client-to-server"),
        derive("wireauth/v2/server-to-client"),
    ]);

    const importAES = (raw: ArrayBuffer) =>
        crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    const [serverC2SKey, serverS2CKey] = await Promise.all([
        importAES(serverC2SRaw),
        importAES(serverS2CRaw),
    ]);

    // 1. Client sends encrypted message -> server decrypts with C2S key
    const clientPayload = new TextEncoder().encode("hello from client");
    const clientPacket = await session.encrypt(1n, clientPayload);
    const serverDecrypted = await decryptSecure(serverC2SKey, new Uint8Array(clientPacket));
    assert.equal(serverDecrypted.seq, 1n);
    assert.deepEqual(serverDecrypted.plaintext, clientPayload);

    // 2. Server sends encrypted message -> client decrypts with S2C key
    const serverPayload = new TextEncoder().encode("welcome from server");
    const serverPacket = await encryptSecure(serverS2CKey, 1n, serverPayload);
    const clientDecrypted = await session.decrypt(new Uint8Array(serverPacket));
    assert.equal(clientDecrypted.seq, 1n);
    assert.deepEqual(clientDecrypted.plaintext, serverPayload);
});

test("createHandshakeClient throws on invalid server transcript signature in v2", async () => {
    const server = await setupTestServer();

    const transport: HandshakeTransport = {
        async sendAndReceive(packet: ArrayBuffer): Promise<ArrayBuffer> {
            const data = new Uint8Array(packet);
            const cmd = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, true);

            if (cmd === 101) {
                return server.serverNonce.buffer as ArrayBuffer;
            }
            if (cmd === 102) {
                // Return server pubkey + an invalid/forged signature
                const fakeSignature = new Uint8Array(256);
                fakeSignature.fill(0xaa);
                const response = concat(server.serverPubRaw, fakeSignature);
                return response.buffer as ArrayBuffer;
            }
            throw new Error(`Unexpected cmd: ${cmd}`);
        },
    };

    const client = createHandshakeClient({
        serverPublicKeyB64: server.publicKeyDerB64,
    });

    await assert.rejects(
        () => client.establish(transport),
        /transcript signature verification failed/
    );
});

test("createHandshakeClient throws on malformed stage responses", async () => {
    const server = await setupTestServer();

    // Malformed stage 1
    const badTransport1: HandshakeTransport = {
        async sendAndReceive() {
            return new Uint8Array(10).buffer as ArrayBuffer;
        },
    };
    const client1 = createHandshakeClient({ serverPublicKeyB64: server.publicKeyDerB64 });
    await assert.rejects(
        () => client1.establish(badTransport1),
        /stage 1 \(v2\) response too short/
    );

    // Malformed stage 2
    const badTransport2: HandshakeTransport = {
        async sendAndReceive(packet: ArrayBuffer) {
            const data = new Uint8Array(packet);
            const cmd = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, true);
            if (cmd === 101) return server.serverNonce.buffer as ArrayBuffer;
            return new Uint8Array(100).buffer as ArrayBuffer;
        },
    };
    const client2 = createHandshakeClient({ serverPublicKeyB64: server.publicKeyDerB64 });
    await assert.rejects(
        () => client2.establish(badTransport2),
        /stage 2 \(v2\) response too short/
    );
});

test("createHandshakeClient supports legacy v1 handshake when useLegacyV1 is enabled", async () => {
    const server = await setupTestServer();
    let clientNonce: Uint8Array = new Uint8Array(0);
    let clientPubRaw: Uint8Array = new Uint8Array(0);

    const transport: HandshakeTransport = {
        async sendAndReceive(packet: ArrayBuffer): Promise<ArrayBuffer> {
            const data = new Uint8Array(packet);
            const cmd = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, true);

            if (cmd === 1) {
                // v1 stage 1: client sends client_nonce (16 bytes)
                clientNonce = data.slice(4);
                // v1 server signs: client_nonce ‖ server_nonce
                const toSign = concat(clientNonce, server.serverNonce);
                const signature = new Uint8Array(nodeSign("sha256", toSign, server.privateKey));
                const response = concat(server.serverNonce, signature);
                return response.buffer as ArrayBuffer;
            }

            if (cmd === 2) {
                // v1 stage 2: client sends client_pubkey (65 bytes)
                clientPubRaw = data.slice(4);
                // v1 server sends just server_pubkey (65 bytes)
                return server.serverPubRaw.buffer as ArrayBuffer;
            }

            throw new Error(`Unexpected cmd: ${cmd}`);
        },
    };

    const client = createHandshakeClient({
        serverPublicKeyB64: server.publicKeyDerB64,
        useLegacyV1: true,
    });

    const session = await client.establish(transport);
    assert.ok(session.clientToServerKey);
    assert.ok(session.serverToClientKey);
    assert.deepEqual(session.serverNonce, server.serverNonce);

    // Verify v1 server and client derived the same key
    const serverSharedBits = await crypto.subtle.deriveBits(
        {
            name: "ECDH",
            public: await crypto.subtle.importKey(
                "raw",
                clientPubRaw,
                { name: "ECDH", namedCurve: "P-256" },
                false,
                []
            ),
        },
        server.serverECDH.privateKey,
        256
    );
    const kdfMaterial = concat(new Uint8Array(serverSharedBits), clientNonce, server.serverNonce);
    const serverKeyHash = await crypto.subtle.digest("SHA-256", kdfMaterial);
    const serverAESKey = await crypto.subtle.importKey(
        "raw",
        serverKeyHash,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );

    // Client -> Server encrypted message
    const payload = new TextEncoder().encode("v1 handshake message");
    const encryptedByClient = await session.encrypt(1n, payload);
    const decryptedByServer = await decryptSecure(serverAESKey, new Uint8Array(encryptedByClient));
    assert.deepEqual(decryptedByServer.plaintext, payload);
});

test("computeResumeProofFor requires sessionSalt and computes valid proofs", async () => {
    const server = await setupTestServer();
    const rawKey = new Uint8Array(32);
    crypto.getRandomValues(rawKey);

    const clientWithoutSalt = createHandshakeClient({
        serverPublicKeyB64: server.publicKeyDerB64,
    });
    await assert.rejects(
        () => clientWithoutSalt.computeResumeProofFor(1n, rawKey.buffer as ArrayBuffer, server.serverNonce),
        /sessionSalt is required in createHandshakeClient config/
    );

    const clientWithSalt = createHandshakeClient({
        serverPublicKeyB64: server.publicKeyDerB64,
        sessionSalt: "my-session-salt",
    });
    const proof = await clientWithSalt.computeResumeProofFor(
        100n,
        rawKey.buffer as ArrayBuffer,
        server.serverNonce
    );
    assert.equal(proof.authKeyIDBytes.length, 8);
    assert.equal(proof.proofA.length, 32);
    assert.equal(proof.proofB.length, 32);
});
