#!/usr/bin/env bash
# Stands up a real SPIRE server in Docker, registers a workload entry, then
# runs a combined agent+proof container: a real spire-agent as a local
# background process, and live_spire_proof.py as a local process talking to
# its Workload API socket. Tears down and recreates the SPIRE server each
# run so the proof is not reusing state from a previous invocation.
set -euo pipefail

SPIRE_VERSION="1.9.6"
TRUST_DOMAIN="vaid-spiffe-live.test"
NETWORK="vaid-spire-proof-net"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
WORK_DIR="$(mktemp -d)"

mkdir -p "$WORK_DIR/server-conf" "$WORK_DIR/server-data" "$WORK_DIR/agent-conf"

cat > "$WORK_DIR/server-conf/server.conf" <<EOF
server {
    bind_address = "0.0.0.0"
    bind_port = "8081"
    trust_domain = "$TRUST_DOMAIN"
    data_dir = "/opt/spire/data"
    log_level = "INFO"
    ca_subject = {
        country = ["US"]
        organization = ["vaid-spiffe live proof"]
        common_name = ""
    }
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "/opt/spire/data/datastore.sqlite3"
        }
    }

    NodeAttestor "join_token" {
        plugin_data {
        }
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "/opt/spire/data/keys.json"
        }
    }
}
EOF

cat > "$WORK_DIR/agent-conf/agent.conf" <<EOF
agent {
    data_dir = "/opt/spire/data"
    log_level = "INFO"
    server_address = "spire-proof-server"
    server_port = "8081"
    socket_path = "/tmp/spire-agent/public/api.sock"
    trust_domain = "$TRUST_DOMAIN"
    insecure_bootstrap = true
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {
        }
    }

    KeyManager "memory" {
        plugin_data {}
    }

    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
EOF

cleanup_containers() {
    docker rm -f spire-proof-server >/dev/null 2>&1 || true
}
cleanup_all() {
    cleanup_containers
    rm -rf "$WORK_DIR"
}
trap cleanup_all EXIT

cleanup_containers
docker network create "$NETWORK" >/dev/null 2>&1 || true

echo "== starting SPIRE server $SPIRE_VERSION =="
docker run -d --name spire-proof-server --network "$NETWORK" \
    -v "$WORK_DIR/server-conf:/opt/spire/conf/server" \
    -v "$WORK_DIR/server-data:/opt/spire/data" \
    "ghcr.io/spiffe/spire-server:$SPIRE_VERSION" \
    run -config /opt/spire/conf/server/server.conf >/dev/null

server_healthy=false
for i in $(seq 1 30); do
    if docker exec spire-proof-server /opt/spire/bin/spire-server healthcheck \
        -socketPath /tmp/spire-server/private/api.sock >/dev/null 2>&1; then
        server_healthy=true
        break
    fi
    sleep 1
done
if [ "$server_healthy" != "true" ]; then
    echo "SPIRE server did not become healthy in time" >&2
    docker logs spire-proof-server >&2
    exit 1
fi

echo "== generating join token and registering workload entry =="
JOIN_TOKEN=$(docker exec spire-proof-server /opt/spire/bin/spire-server token generate \
    -spiffeID "spiffe://$TRUST_DOMAIN/agent/docker-host" \
    -socketPath /tmp/spire-server/private/api.sock | awk -F': ' '{print $2}')

docker exec spire-proof-server /opt/spire/bin/spire-server entry create \
    -parentID "spiffe://$TRUST_DOMAIN/agent/docker-host" \
    -spiffeID "spiffe://$TRUST_DOMAIN/workload/vaid-spiffe-proof" \
    -selector unix:uid:0 \
    -socketPath /tmp/spire-server/private/api.sock >/dev/null

echo "== building combined agent+proof image =="
docker build -q -f "$SCRIPT_DIR/Dockerfile.proof" -t vaid-spiffe-live-proof "$REPO_ROOT" >/dev/null

echo "== running spire-agent + live_spire_proof.py against the live SPIRE server =="
docker run --rm --network "$NETWORK" \
    -v "$WORK_DIR/agent-conf:/opt/spire/conf/agent:ro" \
    -e "SPIRE_JOIN_TOKEN=$JOIN_TOKEN" \
    vaid-spiffe-live-proof
