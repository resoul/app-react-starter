export {
    createHandshakeClient,
    type HandshakeTransport,
    type HandshakeClientConfig,
    type EstablishedSession,
} from "./client.js";

export {
    bufToHex,
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
    type ECDHKeyPair,
    type DerivedAESKey,
} from "./handshake.js";