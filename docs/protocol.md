# Vault Protocol

The wire protocol is implemented once in `vault-core`
([`core/src/protocol.rs`](../core/src/protocol.rs) for the message framing,
[`core/src/crypto.rs`](../core/src/crypto.rs) for the encryption format,
[`core/proto/protocol.proto`](../core/proto/protocol.proto) for the protobuf
schemas). All clients and the supernode share this implementation. This
document is a prose overview; the source is authoritative.

## Protocol compatibility

The current protocol version is `2` (`vault_core::PROTOCOL_VERSION`).
The supernode accepts only an exactly matching request version; it
drops unsupported-version requests without establishing a session. There is
no version negotiation or legacy-protocol fallback.

Changes within one wire version must preserve framing, authentication and
message semantics. Breaking changes must increment `PROTOCOL_VERSION`, update
this document and the changelog, and coordinate client/server upgrades. Rebuild
and deploy all affected peers for such an upgrade; the current handshake does
not support rolling upgrades across wire versions. Optional protobuf fields
may evolve without a bump only when omitted/default values remain compatible.
Version 2 always returns the server-observed source IP and authenticates the
exact INIT request payload along with the response. Upgrade the clients and
Supernode in the same maintenance window.

## Packet types

Every UDP datagram starts with a single type byte:

| Type | Value | Description |
|------|-------|-------------|
| `INIT` | 0x02 | Handshake (SPAKE2 PAKE + X25519 ECDH; the response also carries the assigned IP addresses and a confirmation MAC) |
| `REJECTED` | 0x03 | Unknown-peer rejection response |
| `HEARTBEAT` | 0x05 | Keepalive ping/pong (encrypted) |
| `DATA_INTERFACE` | 0x09 | Encrypted VPN data packets |
| `PEER_REGISTER` | 0x0b | Encrypted node-to-node path probes and acknowledgments |
| `FIND_PEER` | 0x0c | Encrypted peer queries, introductions, punch notices and mapping updates over the Supernode session |
| `CLOSE` | 0xff | Connection termination (encrypted) |

Handshake (`INIT`) payloads are protobuf-encoded and unauthenticated at parse
time — the PAKE exchange and the confirmation MAC authenticate them
afterwards. All other payloads are AEAD-encrypted, except `REJECTED`, which is
a single unauthenticated type byte with no payload.

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
  |     (optional)                 |
  |   - Optional peer key and      |
  |     LAN candidate              |
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
  |   - Server-observed outer      |
  |     source IP                  |
  |   - Peer session epoch         |
  |                                |
  [Encrypted session established]
```

The observed source IP contains no port and is covered by the confirmation MAC.
It is normally the client's NAT/public egress address, but can be a private or
loopback address in direct or test deployments, or a proxy address if a proxy
rewrites the UDP source.

Security properties:

- **SPAKE2 PAKE** — no password-derived verifier crosses the wire, so captured
  handshakes do not enable offline dictionary attacks. The server
  rate-limits INIT requests and temporarily bans source IPs after repeated invalid
  encrypted confirmations. Expired or abandoned handshakes do not count as
  authentication failures, since packet loss and cancelled connection candidates
  are normal behind shared NAT exits.
- **X25519 ECDH** — ephemeral keys per session; session keys are HKDF-SHA256
  derived from the ECDH output, salted with the PAKE key and bound to both
  ephemeral public keys.
- **Confirmation MAC** — the client verifies the response with its PAKE key;
  an incorrect password or modified transcript fails before any traffic is
  sent. The MAC is HMAC-SHA256 with the PAKE key over the concatenation of
  `vault handshake confirm v2`, SHA-256 of the raw request payload after its
  type byte, and the protobuf response with its confirmation MAC cleared.
  The server commits the lease and promotes the pending session after
  decrypting the client's first packet. Cancelling a pending attempt releases only addresses
  reserved by that attempt; a borrowed established lease is never revoked.
- **Replay protection** — handshake timestamps are accepted only within a
  ±120s clock-skew window. The server remembers each authenticated
  `(client ID, ephemeral public key)` for 600s after confirmation, allowing
  fresh handshakes in the same second while rejecting already confirmed keys.
  Unconfirmed requests cannot update this cache. If the bounded cache fills,
  new handshakes are refused until entries expire.

## Peer discovery

Confirmed P2P-capable edges on the same Supernode discover one another
automatically using Supernode-observed UDP endpoints. An edge offers a peer
key when its outer socket is prepared for P2P. Direct traffic bypasses
the Supernode's Linux `FORWARD` rules and relay accounting.

Supernode automatically exchanges LAN candidates between confirmed edges when
it observes the same IPv4 address for both and each offers a distinct RFC 1918
IPv4 address. Linux uses the selected physical exit. Android, iOS and macOS
offer LAN candidates on the selected Wi-Fi or Ethernet interface. Edges
verify that an introduced LAN address shares their physical prefix before
sending probes. Only authenticated probes confirm reachability.

The nonzero epoch from INIT identifies a registration attempt. The server
adds the attempt to its peer directory only after the first authenticated
heartbeat or data packet commits the lease. The edge starts discovery after
receiving authenticated Supernode traffic. Queries use the exact target VPN
address and the Supernode introduces the two authorized sessions using
independent request IDs in each direction. The two clients derive a separate
pair key from X25519 and use the same UDP socket for their Supernode session
and direct traffic. The first packet takes the relay path and can trigger
discovery on the receiving edge as well. Each candidate
starts with a 64-byte authenticated probe. Once the expected endpoint
acknowledges it, the edge sends a maximum-size probe. Its acknowledgement
allows that direction to send direct data up to the sender's TUN MTU.
Receivers use the same 1472-byte UDP payload ceiling for peer probes and
direct data, independent of their own TUN MTU. The first unanswered probe
suspends new direct sends and buffers them while later probes continue. After
three unanswered probes, the edge resumes relaying and replays up to six
seconds of recent direct packets followed by the waiting queue. Buffers are
bounded and waiting packets expire to relay after eight seconds. Replayed
packets can therefore arrive more than once. When a VPN address changes to a
different owner, buffered packets for the previous owner are discarded instead
of being relayed to the new owner.
An authenticated registration can reveal a changed source port on the
introduced address. The edge acknowledges requests at their actual source
and validates the new port before moving outgoing traffic to it.
After sending its first 64-byte probe, an edge with active traffic can send a
`PeerPunch` notice over its authenticated Supernode session. Supernode forwards
current peer information to the other edge for the same live pair, at most once
per direction per pair. The recipient can probe immediately, including
repeating an outstanding small probe with its original cookie. The
introduction and registration retries also work without a punch notice.
After an edge confirms a replacement session, the server discards its previous
pair state. New traffic can trigger discovery with the new session epoch.

Linux policy routing uses a socket mark for the outer transport and a separate
physical route table. The marked Vault transport and gateway sockets use this table. For IPv4,
the effective reverse-path filter on the physical interface must be 0 or 2.
The edge reads the current values and uses relay when direct routing is unavailable.
Android resolves the configured Supernode hostname on the selected non-VPN
`Network` and protects and binds the same UDP socket before INIT. Apple binds
that socket to the physical interface selected by the packet tunnel provider.
Both platforms refresh Supernode exclusions and rebuild candidates when their
physical network changes.

When ordinary IPv4 probes have not verified a direct path, Linux, Android,
iOS, and macOS can request a short PCP or NAT-PMP UDP lease on the physical
gateway for their current tunnel port. The lease is renewed before expiry
while it is needed, and released after 30 seconds without demand or on
transport shutdown when the gateway is still reachable.
The edge checks the mapped public IPv4 address against its authenticated
Supernode observation. An authenticated `PeerMapping` update can advertise
an extra port on that address or withdraw it. Supported Supernodes forward
the extra candidate to the current pair using `PeerInfo`, with a lifetime
bounded by the remaining pair and gateway leases. It goes through the same
authenticated probes as the observed endpoint. Peers check the mapping expiry
before using the endpoint and preserve a verified route on same-port renewal.

## Encryption format

The Supernode session and direct `DATA_INTERFACE` packets use the following format:

```
+---------+---------+--------+
|  Extra  | Payload |  Tag   |
| 8 bytes | N bytes |16 bytes|
+---------+---------+--------+

Extra format:
- Bytes 0-7: packet counter (little-endian u64).
  The most significant bit is the direction flag:
  Supernode session: 0 = client -> server, 1 = server -> client.
  Peer pair: 0 = sent by the smaller PeerId, 1 = sent by the larger PeerId.

Nonce reconstruction (12 bytes):
- Bytes 0-3: 0x00000000
- Bytes 4-11: the 8-byte counter from Extra

Replay protection:
- The counter doubles as a sequence number; the receiver
  tracks authenticated counters in a 2048-bit sliding
  window and rejects duplicates and out-of-window packets.
```

The outer one-byte packet type (`HEARTBEAT`, `DATA_INTERFACE`, `FIND_PEER` or `CLOSE`)
is passed as AEAD associated data. It is visible on the wire but authenticated
by the tag, so a packet cannot be relabeled as another type. Receivers use
the dispatched type for both established sessions and pending-handshake
confirmation; authentication failures do not advance the replay window.
Peer probes use a 33-byte associated-data header with the type and both
`PeerId`s, and share counters and replay state with direct data. See
the peer registration implementation in `core/src/protocol.rs`.

Supernode sessions support AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305. Both
sides measure their own per-algorithm speeds, the client offers its list in
the handshake, and the server picks the algorithm with the best worst-case
(the maximum, over the shared algorithms, of the minimum of the two sides'
speeds), so hardware-accelerated AES-GCM wins where available and
ChaCha20-Poly1305 elsewhere. Peer pairs always use ChaCha20-Poly1305.

## Session maintenance

- Clients ping the Supernode every 10s and reconnect after 30s without
  authenticated Supernode data or a pong. Direct traffic does not refresh
  this timer.
- Reconnect uses exponential backoff from 1s up to 60s.
