#!/usr/bin/env bash
# run_demo.sh — Two-phase demo: Transport Auth + Application Layer
#
# PHASE A: MCP server in bearer mode — proves anonymous callers are rejected
# PHASE B: Full application layer — compliant worker, rogue worker, tamper
#
# Usage: ./examples/demo/run_demo.sh
#
# Captures all output to demo_transcript.txt
# Exits non-zero if any expected outcome fails.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TRANSCRIPT="$SCRIPT_DIR/demo_transcript.txt"

export PYTHONPATH="$PROJECT_ROOT"
export GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
export RESOURCE_URL="${RESOURCE_URL:-http://localhost:8081}"
export FIRESTORE_ENABLED="${FIRESTORE_ENABLED:-}"

# Generate a demo bearer token for Phase A
export MCP_AUTH_TOKEN="demo-bearer-$(date +%s)"
export MCP_URL="http://localhost:8090/mcp"

# Track all PIDs for cleanup
PIDS=()

cleanup() {
    echo "" | tee -a "$TRANSCRIPT"
    echo "Stopping all services..." | tee -a "$TRANSCRIPT"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    PIDS=()
}
trap cleanup EXIT

wait_for_url() {
    local url="$1"
    local name="$2"
    local max_wait="${3:-15}"
    for i in $(seq 1 "$max_wait"); do
        if curl -s -o /dev/null -w "" "$url" 2>/dev/null; then
            echo "  $name ready." | tee -a "$TRANSCRIPT"
            return 0
        fi
        sleep 1
    done
    echo "  TIMEOUT waiting for $name at $url" | tee -a "$TRANSCRIPT"
    return 1
}

echo "Agent Authorization Gateway — Full Demo" | tee "$TRANSCRIPT"
echo "========================================" | tee -a "$TRANSCRIPT"
echo "Gateway:  $GATEWAY_URL" | tee -a "$TRANSCRIPT"
echo "Resource: $RESOURCE_URL" | tee -a "$TRANSCRIPT"
echo "MCP:      $MCP_URL" | tee -a "$TRANSCRIPT"
echo "" | tee -a "$TRANSCRIPT"

EXIT_CODE=0

# ============================================================================
# PHASE A: TRANSPORT AUTH (MCP server in bearer mode)
# ============================================================================

echo "" | tee -a "$TRANSCRIPT"
echo "============================================================" | tee -a "$TRANSCRIPT"
echo "  PHASE A: TRANSPORT AUTH (bearer mode)" | tee -a "$TRANSCRIPT"
echo "============================================================" | tee -a "$TRANSCRIPT"
echo "  Note: bearer auth runs on an identical code path in all modes;" | tee -a "$TRANSCRIPT"
echo "  production additionally uses MCP_AUTH_MODE=iam with DNS" | tee -a "$TRANSCRIPT"
echo "  rebinding protection enabled." | tee -a "$TRANSCRIPT"
echo "" | tee -a "$TRANSCRIPT"

# Start MCP server in bearer mode.
# GATEWAY_DEV_MODE=true is set to disable DNS rebinding protection for localhost,
# but MCP_AUTH_MODE=bearer is enforced regardless of dev mode — the middleware
# still rejects requests without a valid Authorization header.
echo "Starting MCP server (MCP_AUTH_MODE=bearer)..." | tee -a "$TRANSCRIPT"
(
    GATEWAY_DEV_MODE=true MCP_AUTH_MODE=bearer MCP_AUTH_TOKEN="$MCP_AUTH_TOKEN" \
        python3 "$PROJECT_ROOT/serve_mcp.py" 2>&1 &
    echo $!
) &
# The subshell backgrounds the server; get the actual server PID
sleep 2
MCP_PID=$(pgrep -f "serve_mcp.py" | head -1)
if [ -n "$MCP_PID" ]; then
    PIDS+=("$MCP_PID")
    echo "  MCP server PID: $MCP_PID" | tee -a "$TRANSCRIPT"
else
    echo "  FAILED to start MCP server" | tee -a "$TRANSCRIPT"
    exit 1
fi

# Health check: confirm the server is up and rejecting (401 = up + auth working)
echo "Waiting for MCP server..." | tee -a "$TRANSCRIPT"
for i in $(seq 1 10); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$MCP_URL" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "200" ]; then
        echo "  MCP server responding (HTTP $HTTP_CODE)." | tee -a "$TRANSCRIPT"
        break
    fi
    sleep 1
done
if [ "$HTTP_CODE" = "000" ]; then
    echo "  TIMEOUT: MCP server not responding." | tee -a "$TRANSCRIPT"
    exit 1
fi

echo "" | tee -a "$TRANSCRIPT"
echo "--- TRANSPORT AUTH ATTACKS ---" | tee -a "$TRANSCRIPT"
python3 "$SCRIPT_DIR/demo_transport_auth.py" 2>&1 | tee -a "$TRANSCRIPT" || EXIT_CODE=1

# Tear down Phase A MCP server
echo "" | tee -a "$TRANSCRIPT"
echo "Stopping Phase A MCP server..." | tee -a "$TRANSCRIPT"
kill "$MCP_PID" 2>/dev/null || true
wait "$MCP_PID" 2>/dev/null || true
PIDS=()
sleep 2  # allow port to release

# ============================================================================
# PHASE B: APPLICATION LAYER (DPoP + enforcement, existing demo scenes)
# ============================================================================

echo "" | tee -a "$TRANSCRIPT"
echo "============================================================" | tee -a "$TRANSCRIPT"
echo "  PHASE B: APPLICATION LAYER (DPoP + Enforcement)" | tee -a "$TRANSCRIPT"
echo "============================================================" | tee -a "$TRANSCRIPT"
echo "" | tee -a "$TRANSCRIPT"

# Phase B runs in dev mode (existing behavior — compliant/rogue workers
# talk to the REST API on port 8080, not the MCP server)
export GATEWAY_DEV_MODE="true"
export MCP_AUTH_MODE="none"

# Start Gateway (REST API on port 8080)
echo "Starting Gateway..." | tee -a "$TRANSCRIPT"
python3 "$PROJECT_ROOT/serve.py" --port 8080 &
GW_PID=$!
PIDS+=("$GW_PID")
sleep 2

# Start Protected Resource
echo "Starting Protected Resource..." | tee -a "$TRANSCRIPT"
python3 -m uvicorn examples.protected_resource.main:app --port 8081 --host 0.0.0.0 &
RES_PID=$!
PIDS+=("$RES_PID")
sleep 2

# Wait for services
echo "Waiting for services..." | tee -a "$TRANSCRIPT"
wait_for_url "$GATEWAY_URL/health" "Gateway" || exit 1
wait_for_url "$RESOURCE_URL/health" "Protected Resource" || exit 1

# Run existing demo scenes
echo "" | tee -a "$TRANSCRIPT"
echo "--- COMPLIANT WORKER ---" | tee -a "$TRANSCRIPT"
python3 "$SCRIPT_DIR/demo_compliant_worker.py" 2>&1 | tee -a "$TRANSCRIPT" || EXIT_CODE=1

echo "" | tee -a "$TRANSCRIPT"
echo "--- ROGUE WORKER ---" | tee -a "$TRANSCRIPT"
python3 "$SCRIPT_DIR/demo_rogue_worker.py" 2>&1 | tee -a "$TRANSCRIPT" || EXIT_CODE=1

echo "" | tee -a "$TRANSCRIPT"
echo "--- TAMPER DETECTION ---" | tee -a "$TRANSCRIPT"
python3 "$SCRIPT_DIR/demo_tamper.py" 2>&1 | tee -a "$TRANSCRIPT" || EXIT_CODE=1

# ============================================================================
# FINAL RESULT
# ============================================================================

echo "" | tee -a "$TRANSCRIPT"
echo "========================================" | tee -a "$TRANSCRIPT"
if [ $EXIT_CODE -eq 0 ]; then
    echo "ALL DEMOS PASSED (Phase A + Phase B)" | tee -a "$TRANSCRIPT"
else
    echo "SOME DEMOS FAILED" | tee -a "$TRANSCRIPT"
fi
echo "Transcript saved to: $TRANSCRIPT" | tee -a "$TRANSCRIPT"

exit $EXIT_CODE
