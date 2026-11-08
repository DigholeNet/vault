# Performance

There is no reproducible throughput, latency, CPU or battery benchmark suite
published yet. Historical development notes lacked the exact source revision,
tool versions, commands, sampling method and raw results; their numerical
estimates are omitted until those conditions can be recorded and reproduced.
No throughput, connection-time or battery-life guarantee is made.

## Protocol costs and timers

These values describe implementation behavior, not measured performance:

| Item | Value |
|---|---|
| Encrypted packet framing | 25 bytes: 1 type byte + 8 counter bytes + 16 AEAD tag bytes |
| Outer network overhead | UDP adds 8 bytes; IP adds at least 20 bytes for IPv4 or 40 for IPv6 |
| Heartbeat interval | 10 seconds |
| Downstream inactivity timeout | 30 seconds without an authenticated data packet or pong |
| Automatic retry delay | Exponential backoff from 1 to 60 seconds |

The 60-second value limits the retry delay, not total reconnection time. DNS,
handshake attempts, network availability and platform lifecycle also affect
recovery. OS network-change notifications can interrupt the retry delay.

## Measuring an actual deployment

Choose a final HTTPS URL and use the same URL and options for both paths.
There are no default targets. For separate local runs, turn the VPN off for
the first command, then turn it on and wait until connected for the second:

```bash
scripts/test-https-vpn.sh -n 20 --mode direct --url 'https://example.com/'
scripts/test-https-vpn.sh -n 20 --mode vpn --url 'https://example.com/'
```

Replace `https://example.com/` with the target you want to measure. `--mode`
labels the report; it does not enable/disable the VPN or change routing. Repeat
`--url` for multiple targets, or pass URLs as positional arguments. Quote URLs
containing query parameters such as `?a=1&b=2`.

For an interleaved comparison using explicit VPN and physical interfaces:

```bash
scripts/test-https-vpn.sh -n 20 --vpn-interface vpn0 --direct-interface eth0 --url 'https://example.com/'
# IPv6:
scripts/test-https-vpn.sh -6 -n 20 --mode vpn --url 'https://example.com/'
```

Use the actual interface names. The script reports transport success and
p50/p95/max timings, HTTP status counts, downloaded bytes and transfer speed.
Each run prints a separate report directory containing `results.tsv`,
`errors.log`, `summary.txt`, and `config.txt` (UTC start time, request options,
path labels, targets, and curl version). Keep both reports for comparison.
Its direct-interface option binds the HTTPS socket; system DNS routing is
independent. Requests ignore proxy settings and `.curlrc`, use HTTP/1.1 and
fresh connections, and do not follow redirects. HTTP error responses count as
completed transport exchanges; check status codes and response sizes before
comparing speeds. `ttfb_s` measures the wait after TLS setup until the first
response byte, not cumulative time from request start.

For a download comparison, choose a fixed-size file URL and increase
`--timeout` if needed. Small pages mainly measure connection/request latency;
these checks alone do not establish bulk tunnel throughput or UDP/QUIC
performance. See `scripts/test-https-vpn.sh --help` for options.

For publishable results, record the commit, release/debug profile, device and
server hardware, OS/toolchain versions, link type, IP family, tunnel MTU,
negotiated cipher, workload, duration and sample count alongside raw data.
Measure CPU utilization and battery energy separately: CPU percentage alone is
not a battery-impact measurement. Avoid including credentials in shared reports.

## Runtime measurements

Client `VPN uplink metrics`, `VPN downlink metrics` and Apple `TUN write metrics`
summarize active traffic about every 30 seconds. Errors/backpressure produce
more detailed warnings at a minimum interval of five seconds. Successful
heartbeats are DEBUG-only; idle client windows are omitted.
Linux edge writes Rust metrics to `/var/log/vault/metrics.log` (or `--log-dir`);
Apple and Android keep them in `vault.log`.

| Fields | Interpretation |
|---|---|
| `payload_Bps`, `payload_bytes` | Inner-packet bytes per second and window total; uplink counts accepted UDP sends, downlink counts decrypted data |
| `queue_depth`, `queue_peak`, `queue_capacity` | Current occupancy, sampled peak and packet capacity |
| `queue_full_drops`, `queue_closed_drops`, `build_failures` | Local uplink drops before sending |
| `send_failures`, `send_emsgsize`, `send_enobufs`, `send_would_block` | UDP send failures; inspect packet size for `emsgsize`, local pressure for `enobufs`/`would_block` |
| `decrypt_failures`, `receive_errors` | Data authentication failures and UDP receive-call errors |
| `queue_waits`, `queue_wait_total_ms`, `queue_wait_max_ms` | Downlink delivery backpressure; completed waits, not measured packet loss |
| `batch_packets_avg`, `batch_packets_max`, `callback_avg_ms`, `callback_max_ms` | Packets per callback and synchronous delivery time, including platform work |
| Apple `calls`, `submitted_packets`, `packets_per_call_avg`, `packets_per_call_max` | System write calls and batching effectiveness; sparse traffic may use single-packet calls |
| Apple `failed_calls`, `failed_packets`, `write_mean_ms`, `write_max_ms` | Rejected write calls/packets and wall time per batch, including scheduling delays |

A queue near capacity plus uplink drops indicates send-side pressure; downlink
waits plus slow callbacks point to platform delivery. Compare throughput and
CPU alongside these counters. Batch write time cannot be compared directly
with the old per-packet time, and a successful write does not prove delivery.

`elapsed_s` is the actual window duration. Client and Apple windows are
independent; compare several windows rather than adjacent log lines. Core
`generation` identifies each transport, Apple session IDs identify providers,
and `final_window=true` marks a partial final window. Session failure totals
are cumulative and must not be added to window counts. `Transport ready`
records the outer IP family; an HTTPS test's `-4`/`-6` does not identify it.
These client counters do not measure kernel UDP overflow, server drops, TCP
retransmissions or end-to-end loss. Keep runtime logs with the HTTPS reports.

### Supernode forwarding diagnostics

`Supernode peer metrics` and `Supernode I/O metrics` appear in
`/var/log/vault/metrics.log` (or `--log-dir`). Normal windows are about 30 seconds;
application errors or targeted DEBUG reporting shorten them to about five.
Connected peers include zero-traffic windows; `final_window=true` marks a
partial final window on peer removal/replacement or shutdown.

For a short comparison, run `sudo systemctl edit supernode.service` and add:

```ini
[Service]
Environment="RUST_LOG=info,metrics=debug"
```

Apply it and watch the logs (restarting interrupts existing VPN connections):

```sh
sudo systemctl daemon-reload
sudo systemctl restart supernode.service
sudo tail -F /var/log/vault/metrics.log
```

This enables five-second reporting without per-packet DEBUG logs. Do not use
`--verbose`/`--quiet`, which override `RUST_LOG`. Afterwards, remove this
`Environment` override and repeat the reload/restart commands to restore normal reporting.
Linux metrics use the `metrics` target; normal and warning records go only to
`metrics.log`, with daily rotation and at most 30 files, including the current file.

| Fields | Interpretation |
|---|---|
| Peer `up_bytes`, `up_Bps` → `tun_written_bytes` | Decrypted client data → successful server TUN writes |
| Peer `down_bytes`, `down_Bps` → `udp_sent_payload_bytes` | TUN packets mapped to this client → successful UDP sends; gaps warrant checking build/send failures |
| Peer `last_up_s`, `last_down_s`, `last_heartbeat_s` | Seconds since decrypted data, successful data send or authenticated heartbeat; `None` means none yet |
| Peer `invalid_packets`, `spoofed_source`, `build_failures`, `tun_*`, `send_*` | Validation/build/write failures; `would_block`/`enobufs` suggest local pressure, `emsgsize` warrants MTU checks |
| I/O receive/read/parse/poll errors, `first_net_error` | Server-wide processing failures; some counters overlap, so do not sum them as dropped packets |
| I/O `socket_rx_drops_delta`, `socket_rx_queue_bytes`, `socket_tx_queue_bytes` | This UDP socket's Linux drop-counter delta and sampled queue memory; unavailable/reset samples are `None`, not zero |
| I/O `handler_*_ms`, `maintenance_*_ms` | Handling/maintenance wall time, including sampling/reporting but excluding poll waits; not process CPU time |

Peer records cover all traffic for one client; I/O records cover the entire
server. UDP send success means kernel acceptance, not client delivery. Kernel
drops are sampled at the reporting cadence, and queue sizes are not peaks.
Maintenance is counted when it finishes; a cycle that emits a report is included
in the next window.
Compare several timestamp-aligned client/server windows: continuing server
sends with falling client receives points to the outer path or client; falling
server TUN traffic calls for checking requests, routing and the upstream path.
