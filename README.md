# @resoul/wireauth

Browser/Node client for the `wireauth` handshake protocol: RSA-signed
challenge/response, ECDH (P-256) key exchange, and an AES-256-GCM secured
channel afterward — built entirely on the Web Crypto API. This is the
client-side companion to the [Go server package](../wireauth) that
implements the same protocol.

Like its Go counterpart, this is **transport security**, not end-to-end
encryption between users. It secures the link between this client and your
server (similar in spirit to TLS), and is meant to sit alongside your own
auth — not replace it. If you need E2E encryption between users, look at
libsignal instead.

The exact wire format is documented in
[`HANDSHAKE_SPEC.md`](./HANDSHAKE_SPEC.md) — read that if you're
implementing a server or another client from scratch.

> **Security note (protocol v2):** the handshake now signs the full
> transcript — both nonces *and* both ECDH public keys — closing a gap in
> the original protocol where the RSA signature covered only the nonces,
> leaving the ECDH exchange itself unauthenticated against an active
> network attacker. See the security advisory at the top of
> `HANDSHAKE_SPEC.md`. **`establish()` uses v2 by default.** If you're
> talking to a server still on the old protocol, pass `useLegacyV1: true`
> to `createHandshakeClient` — but only over TLS, and only as a temporary
> migration step; see "Migrating from v1" below.

## Install

```
npm install @resoul/wireauth
```

Requires an environment with the Web Crypto API: any modern browser, or
Node.js 18+ (uses `globalThis.crypto.subtle`).

## Quick start

You need the server's RSA **public** key, base64-encoded as SPKI/DER. This
is not a secret, but make sure your app obtains it authentically (bundle it
in your app config, pin it, etc.) rather than trusting an unauthenticated
source at runtime.

```ts
import { createHandshakeClient } from "@resoul/wireauth";

const client = createHandshakeClient({
  serverPublicKeyB64: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCg...", // from your server
});

// You provide the transport: given a packet to send, resolve with the
// server's next response. Works over WebSocket, a custom TCP framing,
// whatever you use.
const transport = {
  async sendAndReceive(packet: ArrayBuffer): Promise<ArrayBuffer> {
    ws.send(packet);
    return new Promise((resolve) => {
      ws.addEventListener("message", (e) => resolve(e.data), { once: true });
    });
  },
};

const session = await client.establish(transport);
// session.aesKey, session.serverNonce are now available if you need them
// directly, but usually you'll just use the helpers below:

const packet = await session.encrypt(1, new TextEncoder().encode("hello"));
ws.send(packet);

ws.addEventListener("message", async (e) => {
  const { plaintext, seq } = await session.decrypt(new Uint8Array(e.data));
  console.log(`message #${seq}:`, new TextDecoder().decode(plaintext));
});
```

### Full WebSocket example

```ts
import { createHandshakeClient } from "@resoul/wireauth";

function makeWebSocketTransport(ws: WebSocket) {
  const queue: ArrayBuffer[] = [];
  const waiters: ((v: ArrayBuffer) => void)[] = [];

  ws.binaryType = "arraybuffer";
  ws.addEventListener("message", (e) => {
    const data = e.data as ArrayBuffer;
    if (waiters.length > 0) waiters.shift()!(data);
    else queue.push(data);
  });

  return {
    async sendAndReceive(packet: ArrayBuffer): Promise<ArrayBuffer> {
      ws.send(packet);
      if (queue.length > 0) return queue.shift()!;
      return new Promise((resolve) => waiters.push(resolve));
    },
  };
}

const ws = new WebSocket("wss://your-server/ws");
await new Promise((resolve) => ws.addEventListener("open", resolve, { once: true }));

const client = createHandshakeClient({ serverPublicKeyB64: "..." });
const session = await client.establish(makeWebSocketTransport(ws));

const packet = await session.encrypt(1, new TextEncoder().encode("hello"));
ws.send(packet);
```

## API reference

```ts
const client = createHandshakeClient({
  serverPublicKeyB64: string, // required — server's RSA public key (SPKI/DER, base64)
  sessionSalt?: string,       // optional — only needed for computeResumeProofFor
  useLegacyV1?: boolean,      // optional, default false — see "Migrating from v1" below
});

// Runs the v2 handshake (nonce exchange, then ECDH exchange + a single
// full-transcript RSA signature) over the given transport. Throws if the
// signature fails to verify or a response is malformed.
const session = await client.establish(transport: HandshakeTransport);

session.clientToServerKey; // CryptoKey — derived AES-256-GCM key for client-to-server traffic
session.serverToClientKey; // CryptoKey — derived AES-256-GCM key for server-to-client traffic
session.aesKey;            // CryptoKey (deprecated) — alias for clientToServerKey
session.serverNonce;       // Uint8Array, 16 bytes — needed for resume proofs
session.encrypt(seq: number | bigint, payload: Uint8Array): Promise<ArrayBuffer>;
session.decrypt(packet: Uint8Array): Promise<{ plaintext: Uint8Array; seq: bigint }>;

// Only if your app supports session resumption without re-running the
// full handshake:
const { authKeyIDBytes, proofA, proofB } = await client.computeResumeProofFor(
  authKeyID: bigint,
  masterHmacKeyRaw: ArrayBuffer,
  serverNonce: Uint8Array,
);
```

Low-level primitives (`importServerRSAKey`, `buildStage1PacketV2`,
`verifyTranscriptSignature`, `deriveDirectionalAESKeys`, `encryptSecure`, etc.)
are also exported directly, for consumers who need finer control than the
stateful client provides — see `src/handshake.ts`. The deprecated v1
primitives (`buildStage1Packet`, `verifyServerSignature`, `deriveSharedAESKey`, etc.) remain
exported for the migration case but are marked `@deprecated`.

## Migrating from v1

`establish()` speaks protocol v2 by default (see the security note above).
To keep talking to a server that hasn't rolled out v2 yet:

```ts
const client = createHandshakeClient({
  serverPublicKeyB64: "...",
  useLegacyV1: true, // only for the migration window — remove once the
                      // server requires v2
});
```

Roll this out server-first: get the server accepting v2 (with v1 kept
available via its own explicit opt-in), confirm clients can speak v2, then
remove `useLegacyV1` from client config, and finally remove v1 support from
the server. Don't flip clients to `useLegacyV1: false` before the server
accepts v2 — that just breaks the connection.

## What you're responsible for

- **The transport.** This package doesn't assume WebSocket, fetch, or
  anything else — you implement `sendAndReceive` for whatever you're using.
- **Sequence numbers.** `seq` passed to `encrypt` must be unique and
  increasing per direction (a counter is enough). Reusing a seq with the
  same key is a nonce-reuse risk for GCM's associated data.
- **Session storage**, if you support resuming sessions later (e.g. across
  page reloads). This package computes the resume proof but doesn't decide
  where you persist `authKeyID`/the HMAC key — that's app-specific (the
  original implementation this was extracted from used IndexedDB; use
  whatever fits your app, keeping in mind this key should not be persisted
  somewhere a script from another origin could read it).
- **Obtaining `serverPublicKeyB64` authentically.** It's not a secret, but
  if an attacker can substitute their own key at runtime, the handshake's
  signature check protects you from nothing.

## FAQ

**Is this the Signal protocol?**
No — see the note at the top. No forward secrecy across messages, no
per-user identity keys, no E2E. It's a transport-security handshake, closer
to a lightweight custom TLS than to Signal.

**Does this work in React Native / non-browser environments?**
It needs `crypto.subtle` from the Web Crypto API. Most modern JS runtimes
(browsers, Node 18+, Deno, Bun) provide it globally. React Native doesn't by
default — you'd need a polyfill that implements the same subset of
`SubtleCrypto` used here (RSASSA-PKCS1-v1_5 verify, ECDH P-256, AES-GCM,
HMAC-SHA256, SHA-256 digest).

**Can I use this with plain `fetch` instead of WebSocket?**
The handshake needs two round-trips against the *same* connection/session on
the server (the server holds state — the nonces — between stage 1 and stage
2), so it doesn't fit a stateless request/response model like typical REST
`fetch` calls unless your server correlates the two stages via some session
token. WebSocket or a persistent TCP-like connection is the natural fit.

**What happens if `establish()` throws?**
Most commonly a signature verification failure — either a wrong
`serverPublicKeyB64`, or (worst case) a man-in-the-middle presenting a
different key. Treat it as fatal for that connection attempt; don't retry
silently without surfacing it, since retrying against the same attacker
won't help.