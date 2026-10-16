# Vault Protocol

The wire protocol is implemented once in `vault-core`
([`core/src/protocol.rs`](../core/src/protocol.rs) for the message framing,
[`core/src/crypto.rs`](../core/src/crypto.rs) for the encryption format,
[`core/proto/protocol.proto`](../core/proto/protocol.proto) for the protobuf
schemas). All clients and the supernode share this implementation. This
document is a prose overview; the source is authoritative.

## Packet types

Every UDP datagram starts with a single type byte:

| Type | Value | Description |
|------|-------|-------------|
| `INIT` | 0x02 | Handshake (SPAKE2 PAKE + X25519 ECDH; the response also carries the assigned IP addresses and a confirmation MAC) |
| `REJECTED` | 0x03 | Unknown-peer rejection response |
| `HEARTBEAT` | 0x05 | Keepalive ping/pong (encrypted) |
| `DATA_INTERFACE` | 0x09 | Encrypted VPN data packets |
| `CLOSE` | 0xff | Connection termination (encrypted) |

Handshake (`INIT`) payloads are protobuf-encoded and unauthenticated at parse
time — the PAKE exchange and the confirmation MAC authenticate them
afterwards. All other payloads are AEAD-encrypted.

## Handshake flow

```
Client                           Server
  |                                |
  |-- HandshakeRequest ----------->|
  |   - ID (16 bytes)              |
  |   - SPAKE2 message A (PAKE)    |
  |   - X25519 public key          |
  |   - Algorithm list (with       |
  |     measured speeds)           |
  |   - Protocol version           |
  |   - Timestamp (±120s           |
  |     tolerance)                 |
  |   - Device name, platform      |
  |     (empty on old clients)     |
  |                                |
  |<-- HandshakeResponse ----------|
  |   - ID (16 bytes)              |
  |   - SPAKE2 message B (PAKE)    |
  |   - X25519 public key          |
  |   - Selected algorithm         |
  |   - Assigned IPv4/IPv6 + mask  |
  |   - Echo of request's public   |
  |     key                        |
  |   - Timestamp                  |
  |   - Confirmation MAC           |
  |     (HMAC-SHA256, PAKE-keyed)  |
  |                                |
  [Encrypted session established]
```

Security properties:

- **SPAKE2 PAKE** — no password-derived verifier crosses the wire, so captured
  handshakes do not enable offline dictionary attacks. The server temporarily
  bans source IPs after repeated handshake failures to bound online guessing.
- **X25519 ECDH** — ephemeral keys per session; session keys are HKDF-SHA256
  derived from the ECDH output, salted with the PAKE key and bound to both
  ephemeral public keys.
- **Confirmation MAC** — the client verifies the response with its PAKE key;
  a wrong password fails here, before any traffic is sent.
- **Replay protection** — handshake timestamps are accepted only within a
  ±120s clock-skew window, combined with per-ID monotonicity on the server.

## Encryption format

All encrypted packets use the following format:

```
+---------+---------+--------+
|  Extra  | Payload |  Tag   |
| 8 bytes | N bytes |16 bytes|
+---------+---------+--------+

Extra format:
- Bytes 0-7: packet counter (little-endian u64).
  The most significant bit is the direction flag:
  0 = client -> server, 1 = server -> client.

Nonce reconstruction (12 bytes):
- Bytes 0-3: 0x00000000
- Bytes 4-11: the 8-byte counter from Extra

Replay protection:
- The counter doubles as a sequence number; the receiver
  tracks authenticated counters in a 2048-bit sliding
  window and rejects duplicates and out-of-window packets.
```

Supported AEAD algorithms: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305. The
client offers its measured per-algorithm speeds in the handshake and the
server picks the fastest, so hardware-accelerated AES-GCM wins where
available and ChaCha20-Poly1305 elsewhere.

## Session maintenance

- Heartbeat ping every 10s; 30s without a pong triggers a reconnect.
- Reconnect uses exponential backoff from 1s up to 60s.
