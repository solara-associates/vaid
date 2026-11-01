#!/usr/bin/env bash
# Starts the real spire-agent as a local background process, waits for its
# Workload API socket, runs the Python proof as a local process (so the
# agent's "unix" WorkloadAttestor resolves peer credentials the normal way,
# both processes sharing one mount/user namespace), then propagates the
# proof's exit code.
set -euo pipefail

JOIN_TOKEN="${SPIRE_JOIN_TOKEN:?SPIRE_JOIN_TOKEN must be set}"
SOCKET_PATH="/tmp/spire-agent/public/api.sock"

mkdir -p "$(dirname "$SOCKET_PATH")"

/opt/spire/bin/spire-agent run \
    -config /opt/spire/conf/agent/agent.conf \
    -joinToken "$JOIN_TOKEN" &
AGENT_PID=$!

cleanup() {
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
}
trap cleanup EXIT

for i in $(seq 1 30); do
    if [ -S "$SOCKET_PATH" ]; then
        break
    fi
    sleep 1
done
if [ ! -S "$SOCKET_PATH" ]; then
    echo "spire-agent did not expose a Workload API socket in time" >&2
    exit 1
fi

python /opt/vaid/python/vaid-spiffe/spire-proof/live_spire_proof.py
