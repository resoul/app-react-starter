import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import {
    bufToHex,
    buildStage1Packet,
    buildStage1PacketV2,
    buildStage2Packet,
    buildStage2PacketV2,
    computeResumeProof,
    decryptSecure,
    deriveDirectionalAESKeys,
    deriveSharedAESKey,
    encryptSecure,
    generateClientNonce,
    generateECDHKeyPair,
    importAsHMACKey,
    importServerRSAKey,
    parseStage1Response,
    parseStage1ResponseV2,
    parseStage2ResponseV2,
    verifyServerSignature,
    verifyTranscriptSignature,
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

test("bufToHex formats bytes as hexadecimal string", () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0x10, 0xff]);
    assert.equal(bufToHex(bytes), "000f10ff");
});

test("v2 authenticates the complete ECDH transcript", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const der = publicKey.export({ type: "spki", format: "der" });
    const rsaKey = await importServerRSAKey(der.toString("base64"));

    const clientNonce = generateClientNonce();
    const serverNonce = generateClientNonce();
    assert.equal(new Uint8Array(buildStage1PacketV2(clientNonce)).length, 20);
    assert.deepEqual(parseStage1ResponseV2(serverNonce)?.serverNonce, serverNonce);
    assert.equal(parseStage1ResponseV2(new Uint8Array(15)), null);

    const client = await generateECDHKeyPair();
    const server = (await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
    )) as CryptoKeyPair;
    const clientPub = new Uint8Array(await crypto.subtle.exportKey("raw", client.publicKey));
    const serverPub = new Uint8Array(await crypto.subtle.exportKey("raw", server.publicKey));

    const stage2Req = await buildStage2PacketV2(client);
    assert.equal(stage2Req.byteLength, 4 + 65);
    const view = new DataView(stage2Req);
    assert.equal(view.getUint32(0, true), 102);

    const transcript = concat(clientNonce, serverNonce, clientPub, serverPub);
    const signature = new Uint8Array(nodeSign("sha256", transcript, privateKey));
    const response = concat(serverPub, signature);
    const parsed = parseStage2ResponseV2(response);
    assert.ok(parsed);
    assert.equal(parsed.serverPubKeyRaw.length, 65);
    assert.equal(parsed.signature.length, 256);
    assert.equal(parseStage2ResponseV2(new Uint8Array(320)), null);

    // Valid transcript signature
    assert.equal(
        await verifyTranscriptSignature(
            rsaKey,
            clientNonce,
            serverNonce,
            clientPub,
            parsed.serverPubKeyRaw,
            parsed.signature
        ),
        true
    );

    // MITM attacker tries substituting public key
    const attacker = (await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
    )) as CryptoKeyPair;
    const attackerPub = new Uint8Array(await crypto.subtle.exportKey("raw", attacker.publicKey));
    assert.equal(
        await verifyTranscriptSignature(
            rsaKey,
            clientNonce,
            serverNonce,
            clientPub,
            attackerPub,
            parsed.signature
        ),
        false
    );

    // Subarray/offset safety check for Uint8Array
    const paddedBuffer = new Uint8Array(parsed.signature.length + 20);
    paddedBuffer.set(parsed.signature, 10);
    const slicedSignature = paddedBuffer.subarray(10, 10 + parsed.signature.length);
    assert.equal(slicedSignature.byteOffset, 10);
    assert.equal(
        await verifyTranscriptSignature(
            rsaKey,
            clientNonce,
            serverNonce,
            clientPub,
            parsed.serverPubKeyRaw,
            slicedSignature
        ),
        true
    );
});

test("v2 derives matching, direction-separated traffic keys", async () => {
    const client = await generateECDHKeyPair();
    const server = (await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
    )) as CryptoKeyPair;
    const clientNonce = generateClientNonce();
    const serverNonce = generateClientNonce();
    const serverPub = await crypto.subtle.exportKey("raw", server.publicKey);
    const clientKeys = await deriveDirectionalAESKeys(
        serverPub,
        client.privateKey,
        clientNonce,
        serverNonce
    );

    const clientPub = await crypto.subtle.exportKey("raw", client.publicKey);
    const serverBits = await crypto.subtle.deriveBits(
        {
            name: "ECDH",
            public: await crypto.subtle.importKey(
                "raw",
                clientPub,
                { name: "ECDH", namedCurve: "P-256" },
                false,
                []
            ),
        },
        server.privateKey,
        256
    );
    const salt = concat(clientNonce, serverNonce);
    const hkdf = await crypto.subtle.importKey("raw", serverBits, "HKDF", false, ["deriveBits"]);
    const derive = (info: string) =>
        crypto.subtle.deriveBits(
            { name: "HKDF", hash: "SHA-256", salt: salt.buffer as ArrayBuffer, info: new TextEncoder().encode(info) },
            hkdf,
            256
        );
    const [serverC2S, serverS2C] = await Promise.all([
        derive("wireauth/v2/client-to-server"),
        derive("wireauth/v2/server-to-client"),
    ]);

    assert.deepEqual(new Uint8Array(clientKeys.clientToServerKeyRaw), new Uint8Array(serverC2S));
    assert.deepEqual(new Uint8Array(clientKeys.serverToClientKeyRaw), new Uint8Array(serverS2C));
    assert.notDeepEqual(
        new Uint8Array(clientKeys.clientToServerKeyRaw),
        new Uint8Array(clientKeys.serverToClientKeyRaw)
    );
});

test("encryptSecure and decryptSecure roundtrip with AEAD framing and seq", async () => {
    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    const payload = new TextEncoder().encode("wireauth secure payload");
    const seq = 42n;

    const packet = await encryptSecure(key, seq, payload);
    assert.ok(packet.byteLength > 8 + 12 + 16);

    const packetBytes = new Uint8Array(packet);
    const decrypted = await decryptSecure(key, packetBytes);
    assert.equal(decrypted.seq, seq);
    assert.deepEqual(decrypted.plaintext, payload);

    // Reject truncated packets
    assert.rejects(
        () => decryptSecure(key, packetBytes.slice(0, 35)),
        /wireauth: encrypted packet too short/
    );

    // Reject tampered ciphertext / tag
    const tampered = new Uint8Array(packetBytes);
    tampered[tampered.length - 1] ^= 0x01;
    assert.rejects(() => decryptSecure(key, tampered));
});

test("v1 legacy flow functions derive correct key and verify signatures", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const der = publicKey.export({ type: "spki", format: "der" });
    const rsaKey = await importServerRSAKey(der.toString("base64"));

    const clientNonce = generateClientNonce();
    const serverNonce = generateClientNonce();

    const stage1Packet = buildStage1Packet(clientNonce);
    assert.equal(stage1Packet.byteLength, 20);
    const view = new DataView(stage1Packet);
    assert.equal(view.getUint32(0, true), 1);

    const dataToSign = concat(clientNonce, serverNonce);
    const signature = new Uint8Array(nodeSign("sha256", dataToSign, privateKey));
    const responseBytes = concat(serverNonce, signature);

    const parsed1 = parseStage1Response(responseBytes);
    assert.ok(parsed1);
    assert.deepEqual(parsed1.serverNonce, serverNonce);
    assert.equal(
        await verifyServerSignature(rsaKey, clientNonce, serverNonce, parsed1.signature),
        true
    );

    // Test v1 deriveSharedAESKey implementation against SHA-256 spec
    const client = await generateECDHKeyPair();
    const server = (await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
    )) as CryptoKeyPair;
    const serverPub = await crypto.subtle.exportKey("raw", server.publicKey);

    const v1Derived = await deriveSharedAESKey(
        serverPub,
        client.privateKey,
        clientNonce,
        serverNonce
    );

    // Independent calculation of v1 key: SHA256(sharedBits ‖ clientNonce ‖ serverNonce)
    const clientPub = await crypto.subtle.exportKey("raw", client.publicKey);
    const sharedBits = await crypto.subtle.deriveBits(
        {
            name: "ECDH",
            public: await crypto.subtle.importKey(
                "raw",
                clientPub,
                { name: "ECDH", namedCurve: "P-256" },
                false,
                []
            ),
        },
        server.privateKey,
        256
    );
    const kdfMaterial = concat(new Uint8Array(sharedBits), clientNonce, serverNonce);
    const expectedHash = await crypto.subtle.digest("SHA-256", kdfMaterial);
    assert.deepEqual(new Uint8Array(v1Derived.sharedAESKeyRaw), new Uint8Array(expectedHash));
});

test("computeResumeProof computes deterministic HMAC chain", async () => {
    const rawKey = new Uint8Array(32);
    crypto.getRandomValues(rawKey);
    const masterKey = await importAsHMACKey(rawKey.buffer as ArrayBuffer);
    const serverNonce = new Uint8Array(16);
    crypto.getRandomValues(serverNonce);
    const authKeyID = 0x0102030405060708n;
    const sessionSalt = "test-salt-secret";

    const proof = await computeResumeProof(authKeyID, masterKey, serverNonce, sessionSalt);
    assert.equal(proof.authKeyIDBytes.length, 8);
    assert.equal(proof.proofA.length, 32);
    assert.equal(proof.proofB.length, 32);

    // authKeyID is little-endian: 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
    const idView = new DataView(proof.authKeyIDBytes.buffer, proof.authKeyIDBytes.byteOffset, 8);
    assert.equal(idView.getBigUint64(0, true), authKeyID);
});
