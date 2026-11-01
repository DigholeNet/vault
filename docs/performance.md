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

For repeated HTTPS exchanges and optional comparison with a physical interface:

```bash
scripts/test-https-vpn.sh -n 20 --vpn-interface vpn0
scripts/test-https-vpn.sh -n 20 --vpn-interface vpn0 --direct-interface eth0
# IPv6:
scripts/test-https-vpn.sh -6 -n 20 --vpn-interface vpn0
```

Use the actual interface names. The script reports transport success and
p50/p95/max timings, retaining raw TSV results and curl errors in its report
directory. Its direct-interface option binds the HTTPS socket; system DNS
routing is independent. See `scripts/test-https-vpn.sh --help` for defaults and
requirements. These HTTPS checks do not measure bulk tunnel throughput.

For publishable results, record the commit, release/debug profile, device and
server hardware, OS/toolchain versions, link type, IP family, tunnel MTU,
negotiated cipher, workload, duration and sample count alongside raw data.
Measure CPU utilization and battery energy separately: CPU percentage alone is
not a battery-impact measurement. Avoid including credentials in shared reports.
