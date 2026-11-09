#!/usr/bin/env bash
#
# Measures HTTPS reliability with a fresh curl process for every request.
# Reports transport success rate and p50/p95/max stage timings, and can
# compare the VPN path with a directly bound physical interface.
#
# Usage:
#   scripts/test-https-vpn.sh --mode direct --url https://example.com/
#   scripts/test-https-vpn.sh --mode vpn --url https://example.com/
#   scripts/test-https-vpn.sh --vpn-interface vpn --direct-interface wlo1 https://example.com/
#
# Exit status is 0 when every HTTPS exchange completes, or 2 when any
# transport/DNS/TLS/request failure occurs. HTTP error responses still count
# as successful network exchanges and remain visible in results.tsv.
# Exit status is 1 for usage errors: bad or missing option values, unknown
# options, missing curl/awk/sort, or a non-HTTPS URL.

set -euo pipefail
export LC_ALL=C

RUNS=10
TIMEOUT=20
CONNECT_TIMEOUT=5
INTERVAL=0.2
FAMILY=-4
VPN_INTERFACE=""
DIRECT_INTERFACE=""
MODE=""
URLS=()

usage() {
    cat <<'EOF'
Usage: scripts/test-https-vpn.sh [options] --url https://URL [--url https://URL ...]
       scripts/test-https-vpn.sh [options] https://URL [https://URL ...]

Options:
  -u, --url URL                HTTPS URL to request; repeat for multiple URLs
      --mode direct|vpn       Label the current path for separate test runs
  -n, --runs N                 Requests per URL and path (default: 10)
  -t, --timeout SECONDS        Total timeout per request (default: 20)
      --connect-timeout SEC    Connect timeout per request (default: 5)
      --interval SECONDS       Delay between requests (default: 0.2)
      --vpn-interface IFACE    Bind VPN requests to this interface
      --direct-interface IFACE Add an interleaved direct-path comparison
  -6, --ipv6                   Use IPv6 instead of the default IPv4
  -h, --help                   Show this help

At least one URL is required; there are no default targets. Quote URLs that
contain query parameters, for example --url 'https://example.com/?a=1&b=2'.
--mode only labels results: turn the VPN off/on yourself before each run.
Without --mode, the label is vpn with --vpn-interface, otherwise current.
Each request uses HTTP/1.1 over TCP, ignores .curlrc, and bypasses proxies.
Redirects are not followed; use the final HTTPS URL for a download test.
--direct-interface binds the HTTPS socket, but the system resolver still
controls which path DNS queries use. The report directory contains raw TSV
results, curl errors, test configuration, and the printed summary.
EOF
}

fail() {
    echo "error: $*" >&2
    exit 1
}

valid_seconds() {
    [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

while (($# > 0)); do
    case "$1" in
        -u|--url)
            (($# >= 2)) || fail "$1 requires a value"
            URLS+=("$2")
            shift 2
            ;;
        --url=*)
            URLS+=("${1#*=}")
            shift
            ;;
        --mode)
            (($# >= 2)) || fail "$1 requires a value"
            MODE=$2
            [[ "$MODE" == direct || "$MODE" == vpn ]] || fail "--mode must be direct or vpn"
            shift 2
            ;;
        -n|--runs)
            (($# >= 2)) || fail "$1 requires a value"
            RUNS=$2
            shift 2
            ;;
        -t|--timeout)
            (($# >= 2)) || fail "$1 requires a value"
            TIMEOUT=$2
            shift 2
            ;;
        --connect-timeout)
            (($# >= 2)) || fail "$1 requires a value"
            CONNECT_TIMEOUT=$2
            shift 2
            ;;
        --interval)
            (($# >= 2)) || fail "$1 requires a value"
            INTERVAL=$2
            shift 2
            ;;
        --vpn-interface)
            (($# >= 2)) || fail "$1 requires a value"
            VPN_INTERFACE=$2
            shift 2
            ;;
        --direct-interface)
            (($# >= 2)) || fail "$1 requires a value"
            DIRECT_INTERFACE=$2
            shift 2
            ;;
        -6|--ipv6)
            FAMILY=-6
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            while (($# > 0)); do
                URLS+=("$1")
                shift
            done
            ;;
        -*)
            fail "unknown option: $1"
            ;;
        *)
            URLS+=("$1")
            shift
            ;;
    esac
done

[[ "$RUNS" =~ ^[1-9][0-9]*$ ]] || fail "--runs must be a positive integer"
valid_seconds "$TIMEOUT" || fail "--timeout must be a non-negative number"
valid_seconds "$CONNECT_TIMEOUT" || fail "--connect-timeout must be a non-negative number"
valid_seconds "$INTERVAL" || fail "--interval must be a non-negative number"
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v awk >/dev/null 2>&1 || fail "awk is required"
command -v sort >/dev/null 2>&1 || fail "sort is required"

((${#URLS[@]} > 0)) || fail "specify at least one HTTPS URL with --url or as a positional argument"
for url in "${URLS[@]}"; do
    [[ "$url" == https://?* ]] || fail "only non-empty HTTPS URLs are supported: $url"
    [[ "$url" != *$'\t'* && "$url" != *$'\n'* && "$url" != *$'\r'* ]] \
        || fail "URLs must not contain tabs or newlines"
done

if [[ "$MODE" == direct && ( -n "$VPN_INTERFACE" || -n "$DIRECT_INTERFACE" ) ]]; then
    fail "--mode direct is for a standalone current-path run; omit interface comparison options"
fi
if [[ -z "$MODE" ]]; then
    MODE=current
    if [[ -n "$VPN_INTERFACE" ]]; then
        MODE=vpn
    fi
fi
MODES=("$MODE")
if [[ -n "$DIRECT_INTERFACE" ]]; then
    MODES+=(direct)
fi

REPORT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/vault-https-test.XXXXXX")
RESULTS="$REPORT_DIR/results.tsv"
ERRORS="$REPORT_DIR/errors.log"
SUMMARY="$REPORT_DIR/summary.txt"
ERROR_TMP="$REPORT_DIR/.current-curl-error"
: >"$ERRORS"
printf 'mode\trun\turl\tok\tcurl_rc\thttp_code\tremote_ip\thttp_version\tdns_s\ttcp_s\ttls_s\tttfb_s\ttotal_s\tspeed_Bps\tsize_bytes\n' >"$RESULTS"
{
    printf 'started_utc: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'modes: %s\nruns: %s\nfamily: %s\ntimeout_s: %s\nconnect_timeout_s: %s\ninterval_s: %s\n' \
        "${MODES[*]}" "$RUNS" "$FAMILY" "$TIMEOUT" "$CONNECT_TIMEOUT" "$INTERVAL"
    printf 'vpn_interface: %s\ndirect_interface: %s\n' "${VPN_INTERFACE:-system route}" "${DIRECT_INTERFACE:-none}"
    printf 'url: %s\n' "${URLS[@]}"
    curl --disable --version
} >"$REPORT_DIR/config.txt"
echo "Report: $REPORT_DIR"
echo "Path label: $MODE (does not change VPN state); IP family: $FAMILY"
FAILURES=0

format_dns() {
    awk -v value="$1" 'BEGIN {
        if (value == "") print "-";
        else printf "%.6f", value;
    }'
}

format_delta() {
    awk -v end="$1" -v start="$2" 'BEGIN {
        if (end == "" || end + 0 <= 0) print "-";
        else printf "%.6f", end - start;
    }'
}

run_request() {
    local mode=$1
    local run=$2
    local url=$3
    local raw rc
    local -a curl_args=(
        curl
        --disable
        --globoff
        -sS
        -o /dev/null
        --noproxy '*'
        --http1.1
        "$FAMILY"
        --connect-timeout "$CONNECT_TIMEOUT"
        --max-time "$TIMEOUT"
    )

    if [[ "$mode" == direct && -n "$DIRECT_INTERFACE" ]]; then
        curl_args+=(--interface "$DIRECT_INTERFACE")
    elif [[ -n "$VPN_INTERFACE" ]]; then
        curl_args+=(--interface "$VPN_INTERFACE")
    fi

    # A non-whitespace separator preserves empty fields (e.g. remote_ip on
    # DNS/connect failure); Bash read collapses consecutive tab separators.
    curl_args+=(-w '%{http_code}|%{remote_ip}|%{http_version}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{speed_download}|%{size_download}')

    if raw=$("${curl_args[@]}" "$url" 2>"$ERROR_TMP"); then
        rc=0
    else
        rc=$?
    fi

    local http_code remote_ip http_version
    local dns connect appconnect starttransfer total speed size
    IFS='|' read -r http_code remote_ip http_version dns connect appconnect starttransfer total speed size <<< "$raw"
    http_code=${http_code:-000}
    remote_ip=${remote_ip:--}
    http_version=${http_version:--}

    local ok=0
    if ((rc == 0)) && [[ "$http_code" != 000 ]]; then
        ok=1
    else
        ((FAILURES += 1))
        {
            printf '[%s run=%s url=%s] curl exit %s, HTTP %s\n' "$mode" "$run" "$url" "$rc" "$http_code"
            cat "$ERROR_TMP"
        } >>"$ERRORS"
    fi

    local dns_s tcp_s tls_s ttfb_s total_s
    dns_s=$(format_dns "${dns:-}")
    tcp_s=$(format_delta "${connect:-}" "${dns:-}")
    tls_s=$(format_delta "${appconnect:-}" "${connect:-}")
    ttfb_s=$(format_delta "${starttransfer:-}" "${appconnect:-}")
    total_s=$(format_dns "${total:-}")

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$mode" "$run" "$url" "$ok" "$rc" "$http_code" "$remote_ip" "$http_version" \
        "$dns_s" "$tcp_s" "$tls_s" "$ttfb_s" "$total_s" "${speed:-0}" "${size:-0}" >>"$RESULTS"

    printf '[%s %d/%d] %-4s rc=%-3s http=%-3s remote=%-15s dns=%-8s tcp=%-8s tls=%-8s ttfb=%-8s total=%ss url=%s\n' \
        "$mode" "$run" "$RUNS" "$([[ $ok == 1 ]] && echo ok || echo FAIL)" "$rc" "$http_code" "$remote_ip" \
        "$dns_s" "$tcp_s" "$tls_s" "$ttfb_s" "$total_s" "$url"
}

for ((run = 1; run <= RUNS; run++)); do
    for url in "${URLS[@]}"; do
        request_modes=("${MODES[@]}")
        if ((${#MODES[@]} == 2 && run % 2 == 0)); then
            request_modes=("${MODES[1]}" "${MODES[0]}")
        fi
        for mode in "${request_modes[@]}"; do
            run_request "$mode" "$run" "$url"
            if [[ "$INTERVAL" != 0 && "$INTERVAL" != 0.0 ]]; then
                sleep "$INTERVAL"
            fi
        done
    done
done
rm -f "$ERROR_TMP"

metric_stats() {
    local mode=$1
    local url=$2
    local column=$3
    awk -F '\t' -v mode="$mode" -v url="$url" -v column="$column" \
        'NR > 1 && $1 == mode && $3 == url && $4 == 1 && $column != "-" {print $column}' "$RESULTS" \
        | sort -n \
        | awk '{values[NR] = $1} END {
            if (NR == 0) {
                print "- - -";
            } else {
                p50 = int(NR * 0.50);
                if (p50 < NR * 0.50) p50++;
                p95 = int(NR * 0.95);
                if (p95 < NR * 0.95) p95++;
                if (p50 < 1) p50 = 1;
                if (p95 < 1) p95 = 1;
                printf "%.3f %.3f %.3f\n", values[p50], values[p95], values[NR];
            }
        }'
}

summarize() {
    local mode url counts total ok rate ips failures statuses
    local -a names=(dns tcp tls ttfb total bytes speed_Bps)
    local -a columns=(9 10 11 12 13 15 14)
    local i stats p50 p95 maximum

    echo
    echo "=== HTTPS reliability summary ==="
    echo "Timings are seconds; bytes and speed_Bps are download bytes and bytes/second."
    echo "Percentiles include successful transport exchanges only, including HTTP error responses."
    for mode in "${MODES[@]}"; do
        for url in "${URLS[@]}"; do
            counts=$(awk -F '\t' -v mode="$mode" -v url="$url" \
                'NR > 1 && $1 == mode && $3 == url {total++; if ($4 == 1) ok++} END {print total + 0, ok + 0}' "$RESULTS")
            read -r total ok <<< "$counts"
            ((total > 0)) || continue
            rate=$(awk -v ok="$ok" -v total="$total" 'BEGIN {printf "%.1f", 100 * ok / total}')
            ips=$(awk -F '\t' -v mode="$mode" -v url="$url" \
                'NR > 1 && $1 == mode && $3 == url && $7 != "-" {seen[$7] = 1} END {for (ip in seen) print ip}' "$RESULTS" \
                | sort | awk 'NR > 1 {printf ","} {printf "%s", $1} END {print ""}')
            failures=$(awk -F '\t' -v mode="$mode" -v url="$url" \
                'NR > 1 && $1 == mode && $3 == url && $4 == 0 {print $5}' "$RESULTS" \
                | sort -n | uniq -c | awk '{if (NR > 1) printf ", "; printf "rc=%s(%s)", $2, $1}')
            statuses=$(awk -F '\t' -v mode="$mode" -v url="$url" \
                'NR > 1 && $1 == mode && $3 == url {print $6}' "$RESULTS" \
                | sort | uniq -c | awk '{if (NR > 1) printf ", "; printf "%s(%s)", $2, $1}')

            echo
            echo "[$mode] $url"
            printf '  transport success: %d/%d (%s%%); failures: %s\n' "$ok" "$total" "$rate" "${failures:-none}"
            printf '  remote IPs: %s\n' "${ips:--}"
            printf '  HTTP codes (count): %s\n' "$statuses"
            printf '  %-10s %10s %10s %10s\n' metric p50 p95 max
            for i in "${!names[@]}"; do
                stats=$(metric_stats "$mode" "$url" "${columns[$i]}")
                read -r p50 p95 maximum <<< "$stats"
                printf '  %-10s %10s %10s %10s\n' "${names[$i]}" "$p50" "$p95" "$maximum"
            done
        done
    done
}

summarize | tee "$SUMMARY"
echo
echo "Report: $REPORT_DIR"
echo "  results: $RESULTS"
echo "  errors:  $ERRORS"

if ((FAILURES > 0)); then
    exit 2
fi
