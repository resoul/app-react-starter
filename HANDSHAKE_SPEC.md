# Wire Handshake Protocol v2

All integers are little-endian unless stated otherwise. Every handshake message
is a binary WebSocket frame and must have the exact size shown.

## Handshake

| Direction | Bytes | Format |
|---|---:|---|
| Client → Server | 20 | `u32le(101) ‖ client_nonce[16]` |
| Server → Client | 16 | `server_nonce[16]` |
| Client → Server | 69 | `u32le(102) ‖ client_pubkey[65]` |
| Server → Client | 321 | `server_pubkey[65] ‖ rsa_signature[256]` |

The public keys are P-256 uncompressed X9.63 points. The signature is
RSA-2048 PKCS#1 v1.5 with SHA-256 over:

```
client_nonce ‖ server_nonce ‖ client_pubkey ‖ server_pubkey
```

Clients must verify that signature before deriving or using traffic keys.

## Traffic keys

```
shared_secret = ECDH(own_private, peer_public)
salt          = client_nonce ‖ server_nonce
c2s_key       = HKDF-SHA256(shared_secret, salt, "wireauth/v2/client-to-server", 32)
s2c_key       = HKDF-SHA256(shared_secret, salt, "wireauth/v2/server-to-client", 32)
```

The client encrypts with `c2s_key` and decrypts with `s2c_key`; the server
does the inverse.

## Encrypted frames

```
seq[8 big-endian] ‖ nonce[12 random] ‖ ciphertext_and_tag
```

`seq` is AES-GCM additional authenticated data. Maintain a separate,
strictly increasing receive counter for each direction and reject replayed or
out-of-order frames. TLS remains mandatory for the WebSocket endpoint.

## Resume Session (HMAC chain)

```
proof_A = HMAC-SHA256(key=master_key, data=session_salt)
proof_B = HMAC-SHA256(key=proof_A,   data=auth_key_id_bytes ‖ server_nonce)
```

`auth_key_id_bytes`: 8 bytes, **little-endian** (note: differs from the big-endian `seq` in encrypted frames above).

## Legacy v1

v1 (`cmd` 1/2) does not authenticate ECDH public keys. It is migration-only,
must be explicitly enabled, and must never be used outside TLS.

