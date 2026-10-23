#!/usr/bin/env bash
# Real sysctl/netfilter verification. All mutations stay in a fresh Linux netns.
# Requires Linux, sudo, unshare, iproute2, iptables, procps and Python 3.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Linux ]]; then
    echo "This integration test requires Linux." >&2
    exit 1
fi
test_binary="$(cargo test --locked -p supernode --features vault-core/test \
    --no-run --message-format=json | python3 -c '
import json, sys
executables = [item["executable"] for line in sys.stdin
               if (item := json.loads(line)).get("reason") == "compiler-artifact"
               and item.get("profile", {}).get("test")
               and item.get("target", {}).get("name") == "supernode"
               and item.get("executable")]
if len(executables) != 1:
    sys.exit("Could not locate supernode test executable")
print(executables[0])
')"
sudo unshare --net -- env VAULT_NETWORK_TEST_ISOLATED=1 "$test_binary" \
    --exact network::tests::linux_network_namespace --ignored --nocapture
