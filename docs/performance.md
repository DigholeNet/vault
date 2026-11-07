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

The shared client core emits `VPN uplink metrics` and `VPN downlink metrics`
to the existing runtime log about every five seconds when there is activity.
Apple providers additionally emit `TUN write metrics`. These are aggregate
records, not per-packet logs. `elapsed_s` is the actual monotonic time covered
by a window, so a delayed timer does not turn a longer interval into a claimed
one-second sample. Core maintenance still runs on a persistent one-second
timer for liveness checks; missed ticks do not cause a burst of reports.
Partial windows are flushed when tasks are cancelled or the provider stops.

At connection start, `Transport ready` records the selected UDP peer,
`outer_ip` (`IPv4` or `IPv6`), connection `generation`, queue capacities, and
the session's cumulative `session_not_connected_total`. Apple logs `Tunnel
settings applied` with the successfully applied MTU and configuration revision.
The MTU is the configured TUN MTU, not a measurement of the remote path MTU.
An HTTPS test's `-4`/`-6` option does not identify the outer tunnel IP family.

| Record / fields | Meaning |
|---|---|
| Uplink `packets`, `payload_bytes`, `payload_Bps` | Payload accepted by UDP sends in this window; not peer acknowledgements |
| `queue_depth`, `queue_peak`, `queue_capacity` | Current queue occupancy, sampled peak, and packet capacity; the peak can miss brief occupancy changes |
| Uplink `queue_full_drops`, `queue_closed_drops`, `build_failures` | Packets discarded locally because the queue is full/closed or packet construction fails |
| Uplink `send_failures`, `send_emsgsize`, `send_enobufs`, `send_would_block`, `send_unreachable`, `send_other`, `last_errno` | UDP data-send errors, grouped into mutually exclusive categories; errno uses the running OS's values |
| Downlink `decrypted_packets`, `payload_bytes`, `decrypt_failures` | Authenticated data packets and failed data decryption attempts before platform delivery |
| Downlink `queue_waits`, `queue_wait_total_ms`, `queue_wait_max_ms` | Completed waits for receive-channel space; **backpressure, not measured packet loss** |
| Downlink `receive_errors`, `last_receive_errno` | Errors returned by UDP receive calls |
| Downlink `batches`, `batch_packets_avg`, `batch_packets_max` | Actual batches handed to the platform callback |
| Downlink `callback_avg_ms`, `callback_max_ms` | Synchronous callback duration, including FFI/platform work before it returns |
| Apple `calls`, `submitted_packets`, `submitted_bytes` | Calls and data submitted to `packetFlow.writePackets` |
| Apple `packets_per_call_avg`, `packets_per_call_max` | Mean and largest packet count per system write call in this window |
| Apple `failed_calls`, `failed_packets` | Calls returning false and packets submitted in those calls; not an end-to-end loss count |
| Apple `write_mean_ms`, `write_max_ms` | Wall time per system write call, excluding protocol-array preparation and metrics recording; includes scheduling delays |

Apple forwards each existing Rust downlink batch to one `writePackets` call,
preserving packet order and the matching IPv4/IPv6 protocol entries. It does
not wait for more packets to fill a batch. Empty batches are ignored; calls
that return false are counted without retrying the batch. The core currently
delivers at most 32 packets per batch. Under load, `submitted_packets` should
exceed `calls` and `packets_per_call_avg` should rise above 1; sparse traffic
may still arrive as single packets. A metric update now occurs once per write
call rather than once per packet.

When comparing before and after batching, `write_mean_ms` and `write_max_ms`
now describe a whole batch rather than one packet. A larger per-call time
alone does not mean a regression. Compare call count, packets per call, Rust
callback duration, receive-queue waits, workload throughput and CPU together.
Rust and Apple report windows are independent, so adjacent records do not
necessarily cover the same packets or the same slow event.

Core records identify the peer and generation. Per-transport windows do not
reuse their predecessors' counters on reconnect. Apple counters belong to a
provider session, which may contain several transport generations. Core
`final_window=true` marks a partial final window. `VPN session uplink failure
totals` is emitted once at shutdown and includes `not_connected` attempts made
while no transport existed; it is cumulative and must not be added to the
interval counts. Shared atomic snapshots may place concurrent updates into
adjacent windows. If shutdown was requested from the client's own runtime,
`workers_joined=false` identifies a shutdown snapshot taken without waiting
for its worker tasks; their last updates may still be pending. An ongoing
queue wait/callback is timed only when it finishes.

To investigate a slow run, retain the runtime logs alongside the HTTPS report.
A queue peak near capacity plus increasing `queue_full_drops` indicates local
uplink pressure; downlink waits plus slow callbacks point to the delivery side.
`send_emsgsize` is useful evidence for packet-size/path-MTU investigation.
These counters do **not** measure kernel UDP receive overflow, server-side
drops, TCP retransmissions or end-to-end packet loss. Zero local errors alone
does not establish a lossless network, and low callback times alone do not
establish sufficient throughput. Compare them with workload, CPU and network
measurements before changing buffers or forwarding architecture.
