# Shared diagnostics engine

`vault_core::diagnostics::Engine` owns the diagnostic workflow. Android,
iOS and macOS execute its requests and render typed snapshots. Probe ordering,
retries, deadlines and verdicts are owned by the engine. The UniFFI entry is
`vault_bridge::diagnostics::DiagnosticEngine`.

Apple and Android use the same engine and synchronous Rust network transport.
Apple holds the engine in its app and forwards tunnel/host-default requests to
its provider over IPC. Android supplies the live VPN Network handle to Rust for
tunnel requests; its application and informational probes use default routing.
Both cancel on session/network changes. No platform implements a second plan,
protocol, retry loop or verdict calculation.

Apple's UI/IPC adapter is consolidated in
[`clients/apple/VaultCore/Sources/VaultCore/Diagnostics.swift`](../clients/apple/VaultCore/Sources/VaultCore/Diagnostics.swift). Android's adapter is in
`DiagnosticsViewModel.kt`; the fragment only renders typed Rust snapshots.

`DiagnosticTransport` owns DNS/UDP, TCP, ICMP, rustls handshakes, HTTP/1.1 and
response validation. It uses synchronous sockets, not another async runtime.
Tokio remains in the existing VPN client session independently of diagnostics.
TLS chain validation, hostname checks and trust anchors are fully Rust-owned:
`rustls` uses the bundled `webpki-roots` Mozilla roots. Android/Apple system or
user-installed trust stores do not affect diagnostic TLS decisions. There is no
platform verifier, JVM initialization or Kotlin/Swift TLS dependency.

Network binding is also performed in Rust: Apple `IP_BOUND_IF`/`IPV6_BOUND_IF`,
Android NDK `android_setsocknetwork`. Platform adapters provide only the live
interface address or VPN Network handle. They never change process-wide routing
or protect a diagnostic socket out of the VPN. Route observation is a Rust UDP
connect/local-address query without sending packets.

OS-specific network implementations and native library declarations live in
`clients/bridge/src/network.rs`; core exposes the `NetworkBinding` interface.
Android's cargo-ndk platform is taken from the same minSdk as Gradle. The final
bridge link rejects unresolved symbols, so a missing native library dependency
fails the build instead of breaking shared-library loading on a phone.

## Host contract

1. Create one engine per run using the **live** tunnel session ID and assigned
   addresses, configured resolvers and effective MTU. Empty domains/resolvers
   select the shared defaults. Addresses are validated numerically.
2. Call `next_request()` on a background worker. Execute its operation through
   `DiagnosticTransport` in the correct process/network, outside the engine lock.
   Only one request may be outstanding per engine.
3. Pass `deadline_ms - elapsed_ms()` as the remaining transport budget. Rust
   recomputes deadlines for socket I/O with at most 50ms cancellation polling.
   Cancel both the engine and active transport on a session change. OS resolver
   calls finish independently if their waiting caller has already timed out;
   certificate verification is handled by rustls against the shared root set.
   Apple IPC reply waits add three seconds to the transport budget for dispatch
   and result delivery; the Rust probe deadline itself is unchanged. A missing
   or invalid IPC reply invalidates the run, while a typed probe timeout does not.
4. Return the typed observation with `complete(id, response)`. Poll again to
   finalize the stage and obtain the next request. Publish `snapshot()` to UI.
   A `None` request means completion. A pending request can also expire when
   polled at its deadline; its subsequent completion is stale and rejected.
5. On disconnect, reconnect, tunnel replacement or changed assignment, cancel
   this engine and pending I/O. A new session uses a new engine. `cancel()`
   invalidates the outstanding request; it does not itself own native sockets.

The bridge supplies its own monotonic clock, and serializes mutation without
calling native code while locked. Core tests inject monotonic milliseconds;
production adapters must not supply epoch timestamps.

### Execution scopes

| Scope | Contract |
|---|---|
| Tunnel | Android VPN `Network` binding / Apple tunnel interface binding. DNS queries go to the specified resolver. TCP and HTTPS use the selected numeric address. |
| Application | System DNS and default routing in the user app process; never protect/bypass these sockets. Route observations are local addresses selected by unbound UDP connect/getsockname, without sending probe datagrams. |
| HostDefault | Optional unbound gateway ICMP in the VPN host; informational, not proof of path selection or MTU failure. |

Apple executes Application operations in the app process, where the engine
lives; tunnel and HostDefault operations are dispatched to the provider over
IPC. Executing Application operations in the NetworkExtension tests a different route. Android's default
resolver/socket operations must likewise remain distinct from VPN-bound ones.
Losing the bound VPN network invalidates the run rather than permitting a
fallback to an unbound socket.

## Workflow and Apple baseline

- Route assessment, then IPv4 DNS → TCP → HTTPS sweeps across all domains.
- IPv6 AAAA → TCP → HTTPS sweeps. IPv4 has a 25s window; IPv6 retains the
  remainder of a separate 50s tunnel deadline. Per-probe limits are DNS 3s,
  TCP 4s and HTTPS 6s, capped by the remaining phase window.
- DNS falls back through configured resolvers. TCP tries at most two addresses
  per domain; HTTPS uses the first successful TCP target.
- Without a live tunnel IPv6 assignment, IPv6 checks remain unmeasured. Empty
  successful AAAA answers do not fabricate TCP/HTTPS probes. If no domains have
  IPv6 targets, the corresponding transport checks remain incomplete.
- Optional gateway ICMP: two samples each at 64, min(1200, MTU), and MTU bytes;
  skip larger sizes if both baseline requests fail. Tunnel budget is 60s.
- Application HTTPS gets its own 16s window. Application Ping samples IPv4
  `1.1.1.1` and IPv6 `2606:4700:4700::1111` twice each at 64 bytes, with 2s probe
  limits and a 24s combined application window.

HTTPS is HTTP/1.1 GET `/`, with a bounded Range request and 64KiB response
sample. Use the original domain for SNI and hostname verification even for
fixed-IP connections. Use the shared Rust trust anchors. Rust reads and validates the raw response, rejecting truncated EOF bodies.
Only the validated status, byte count, TLS duration and leaf certificate SHA256
fingerprint cross FFI/IPC; raw response bodies stay in Rust. HTTP 200–599 responses
demonstrate connectivity; redirects and HTTP error statuses are observations,
not TLS/network failures. Disable HTTP/2 negotiation for this raw HTTP/1.1 probe.

The Rust transport validates DNS transactions/questions, CNAMEs and compressed
names, and rejects truncated UDP responses. Only `diagnostic_dns_query` is
exported separately for settings-domain validation; response parsing stays in
Rust. Platform UI code supplies live metadata and handles, while OS socket
binding is implemented in the Rust bridge.

## Result interpretation

Seven required checks: DNS/TCP/HTTPS for both families and application HTTPS.
All must have completed successfully, and route assessment must be available
without mismatches, for the run to pass. Missing required work is incomplete;
explicit failures remain visible in checks and probes even when the overall
state is incomplete. Route mismatch is a failure; missing live metadata is
incomplete. IPv6 default routing without a tunnel IPv6 assignment is a possible
bypass, never inferred from cached addresses.

DNS/TCP/HTTPS success counts domains, not candidate attempts. Failed candidates
remain in details and timing samples but do not fail a domain if a retry
succeeds. Durations average all attempts, including failed ones. Ping averages
reply RTT only; missing replies are informational and never alter the required
connectivity verdict. All states are typed; localization belongs in the UI.

## Verification

`cargo test -p vault-core -p vault-bridge` covers the engine, FFI, UDP DNS,
cancellation, timeout, IPv4/IPv6 echo replies and HTTP/DNS parsing. No local
HTTPS server, test certificate or private key is maintained.

Run real rustls HTTPS checks against `https://example.com` explicitly:

```sh
cargo test -p vault-core --test diagnostics_network -- --ignored
```

These remote checks validate HTTPS access and reject a mismatched TLS hostname.
They are excluded from the default test run because they depend on public DNS,
internet connectivity and the remote service. They use the production Rust root set and verification policy, with no
certificate-validation bypass.

Apple tests cover adapter/IPC roundtrips, cancellation and UI projection rather
than repeating protocol fixtures in Swift. Device-specific VPN interface binding,
permissions and routing still require device integration checks.
