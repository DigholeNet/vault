#!/usr/bin/env bash
# Real TUN lifecycle, sysctl/netfilter and client route checks in fresh netns.
# Requires Linux, sudo, unshare, iproute2, iptables, procps and Python 3.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Linux ]]; then
    echo "This integration test requires Linux." >&2
    exit 1
fi
for package in vault-core supernode edge; do
test_binary="$(cargo test --locked -p "$package" --features vault-core/test \
    --no-run --message-format=json | python3 -c '
import json, sys
executables = [item["executable"] for line in sys.stdin
               if (item := json.loads(line)).get("reason") == "compiler-artifact"
               and item.get("profile", {}).get("test")
               and item.get("target", {}).get("name") == sys.argv[1].replace("-", "_")
               and item.get("executable")]
if len(executables) != 1:
    sys.exit(f"Could not locate {sys.argv[1]} test executable")
print(executables[0])
' "$package")"
if [[ "$package" == vault-core ]]; then
    sudo unshare --net -- env VAULT_TUN_TEST_NAMESPACE=1 "$test_binary" \
        --exact device::tests::tun_lifecycle --ignored --nocapture
elif [[ "$package" == supernode ]]; then
    sudo unshare --net -- bash -c '
        set -e
        ip link set lo up
        sysctl -q -w net.ipv6.bindv6only=1
        exec "$1" --exact supernode::tests::dual_stack
    ' _ "$test_binary"
    sudo unshare --net -- env VAULT_NETWORK_TEST_ISOLATED=1 "$test_binary" \
        --exact network::tests::netns_setup --ignored --nocapture
else
    sudo unshare --net -- env VAULT_NETWORK_TEST_NAMESPACE=1 "$test_binary" \
        --exact routes::tests::netns_routes --ignored --nocapture
    sudo unshare --net -- env VAULT_NETWORK_TEST_NAMESPACE=1 "$test_binary" \
        --exact runner::tests::rpf_policy --ignored --nocapture
    sudo unshare --net -- env VAULT_EDGE_LOCK_TEST_NAMESPACE=1 "$test_binary" \
        --exact runner::tests::netns_lock --ignored --nocapture
fi
done
