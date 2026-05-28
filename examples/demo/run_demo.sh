#!/usr/bin/env bash
# run_demo.sh — Orchestrates the full demo: Gateway, Resource, Compliant Worker,
# Rogue Worker, and Tamper Detection.
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
export GATEWAY_DEV_MODE="true"

echo "Agent Authorization Gateway — Full Demo" | tee "$TRANSCRIPT"
echo "========================================" | tee -a "$TRANSCRIPT"
echo "Gateway: $GATEWAY_URL" | tee -a "$TRANSCRIPT"
echo "Resource: $RESOURCE_URL" | tee -a "$TRANSCRIPT"
echo "" | tee -a "$TRANSCRIPT"

# Start Gateway
echo "Starting Gateway..." | tee -a "$TRANSCRIPT"
python3 "$PROJECT_ROOT/serve.py" --port 8080 &
GW_PID=$!
sleep 2

# Start Protected Resource
echo "Starting Protected Resource..." | tee -a "$TRANSCRIPT"
python3 -m uvicorn examples.protected_resource.main:app --port 8081 --host 0.0.0.0 &
RES_PID=$!
sleep 2

cleanup() {
    echo "Stopping services..." | tee -a "$TRANSCRIPT"
    kill $GW_PID $RES_PID 2>/dev/null || true
    wait $GW_PID $RES_PID 2>/dev/null || true
}
trap cleanup EXIT

# Wait for services
echo "Waiting for services..." | tee -a "$TRANSCRIPT"
for i in $(seq 1 10); do
    if curl -s "$GATEWAY_URL/health" > /dev/null 2>&1 && curl -s "$RESOURCE_URL/health" > /dev/null 2>&1; then
        echo "Services ready." | tee -a "$TRANSCRIPT"
        break
    fi
    sleep 1
done

EXIT_CODE=0

# Run Compliant Worker
echo "" | tee -a "$TRANSCRIPT"
echo "--- COMPLIANT WORKER ---" | tee -a "$TRANSCRIPT"
python3 "$SCRIPT_DIR/demo_compliant_worker.py" 2>&1 | tee -a "$TRANSCRIPT" || EXIT_CODE=1

# Run Rogue Worker
echo "" | tee -a "$TRANSCRIPT"
echo "--- ROGUE WORKER ---" | tee -a "$TRANSCRIPT"
python3 "$SCRIPT_DIR/demo_rogue_worker.py" 2>&1 | tee -a "$TRANSCRIPT" || EXIT_CODE=1

# Run Tamper Demo
echo "" | tee -a "$TRANSCRIPT"
echo "--- TAMPER DETECTION ---" | tee -a "$TRANSCRIPT"
python3 "$SCRIPT_DIR/demo_tamper.py" 2>&1 | tee -a "$TRANSCRIPT" || EXIT_CODE=1

echo "" | tee -a "$TRANSCRIPT"
echo "========================================" | tee -a "$TRANSCRIPT"
if [ $EXIT_CODE -eq 0 ]; then
    echo "ALL DEMOS PASSED" | tee -a "$TRANSCRIPT"
else
    echo "SOME DEMOS FAILED" | tee -a "$TRANSCRIPT"
fi
echo "Transcript saved to: $TRANSCRIPT" | tee -a "$TRANSCRIPT"

exit $EXIT_CODE
