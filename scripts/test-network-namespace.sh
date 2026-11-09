#!/usr/bin/env bash
# Real sysctl/netfilter and client route checks in fresh Linux netns instances.
# Requires Linux, sudo, unshare, iproute2, iptables, procps and Python 3.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Linux ]]; then
    echo "This integration test requires Linux." >&2
    exit 1
fi
for package in supernode edge; do
test_binary="$(cargo test --locked -p "$package" --features vault-core/test \
    --no-run --message-format=json | python3 -c '
import json, sys
executables = [item["executable"] for line in sys.stdin
               if (item := json.loads(line)).get("reason") == "compiler-artifact"
               and item.get("profile", {}).get("test")
               and item.get("target", {}).get("name") == sys.argv[1]
               and item.get("executable")]
if len(executables) != 1:
    sys.exit(f"Could not locate {sys.argv[1]} test executable")
print(executables[0])
' "$package")"
if [[ "$package" == supernode ]]; then
    sudo unshare --net -- bash -c '
        set -e
        ip link set lo up
        sysctl -q -w net.ipv6.bindv6only=1
        exec "$1" --exact supernode::tests::dual_stack
    ' _ "$test_binary"
    sudo unshare --net -- env VAULT_NETWORK_TEST_ISOLATED=1 "$test_binary" \
        --exact network::tests::linux_network_namespace --ignored --nocapture
else
    sudo unshare --net -- env VAULT_NETWORK_TEST_NAMESPACE=1 "$test_binary" \
        --exact routes::tests::linux_namespace_route_rollback --ignored --nocapture
fi
done
