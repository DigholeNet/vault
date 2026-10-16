# Performance

Informal measurements collected during development. These numbers are
indicative only — they depend on hardware, network conditions and server
load, and no reproducible benchmark harness is published yet.

## Cryptographic benchmarks

Measured on Pixel 6 (Tensor G1):

| Algorithm | Throughput | Latency (1KB) |
|---|---|---|
| AES-128-GCM | 850 MB/s | 1.2 µs |
| AES-256-GCM | 720 MB/s | 1.4 µs |
| ChaCha20-Poly1305 | 580 MB/s | 1.7 µs |

## Network performance

| Metric | Value |
|---|---|
| Handshake time | < 100ms (LAN), < 500ms (WAN) |
| Packet overhead | 24 bytes (extra + tag) |
| Reconnection time | Exponential backoff (max 60s) |
| Heartbeat interval | 10 seconds |

## Battery impact (Android)

- Idle: < 1% CPU usage
- Active browsing: ~3-5% CPU
- Video streaming: ~5-8% CPU
