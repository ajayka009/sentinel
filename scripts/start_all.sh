#!/bin/bash
# Sentinel one-command demo launcher: broker, sim world, operator, console.
# Run from anywhere: ./scripts/start_all.sh [options]  (see --help).
# Ctrl+C stops everything this script started. Kept bash-3.2 compatible
# (macOS system bash): no associative arrays, no wait -n.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OPERATOR="scripted"
GLIMMER_BACKEND="ollama"
GLIMMER_CYCLES="0"
ROGUE=0
CONSOLE=1
BIND="127.0.0.1"
PORT="8501"
BROKER=1
LOG_DIR="${LOG_DIR:-/tmp/sentinel-logs}"
PIDS=""

usage() {
    cat <<EOF
Usage: scripts/start_all.sh [options]

Starts, in order: broker (if needed) -> plc -> sensors -> yard ->
operator -> console. The rogue attack script stays OFF unless --rogue
is passed. Ctrl+C stops everything started by this script.

Options:
  --operator MODE      scripted (default) | glimmer | none
  --glimmer-backend B  ollama (default) | llama.cpp | stub
  --glimmer-cycles N   glimmer cycles, 0 = forever (default 0)
  --rogue              also start sim/rogue.py (attack script, off by default)
  --no-console         skip the Streamlit console
  --bind ADDR          console bind address (default 127.0.0.1;
                       use 0.0.0.0 for public-IP access + firewall rule)
  --port PORT          console port (default 8501)
  --no-broker          skip broker startup (assume one already runs)
  --help               print this help and exit

Logs go to $LOG_DIR. Python comes from .venv
when present, else the system python3.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --operator) OPERATOR="$2"; shift 2 ;;
        --operator=*) OPERATOR="${1#*=}"; shift ;;
        --glimmer-backend) GLIMMER_BACKEND="$2"; shift 2 ;;
        --glimmer-backend=*) GLIMMER_BACKEND="${1#*=}"; shift ;;
        --glimmer-cycles) GLIMMER_CYCLES="$2"; shift 2 ;;
        --glimmer-cycles=*) GLIMMER_CYCLES="${1#*=}"; shift ;;
        --bind) BIND="$2"; shift 2 ;;
        --bind=*) BIND="${1#*=}"; shift ;;
        --port) PORT="$2"; shift 2 ;;
        --port=*) PORT="${1#*=}"; shift ;;
        --rogue) ROGUE=1; shift ;;
        --no-console) CONSOLE=0; shift ;;
        --no-broker) BROKER=0; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

case "$OPERATOR" in
    scripted|glimmer|none) ;;
    *) echo "bad --operator: $OPERATOR (scripted|glimmer|none)" >&2; exit 2 ;;
esac

if [ -x "$ROOT/.venv/bin/python" ]; then
    PYTHON="$ROOT/.venv/bin/python"
else
    PYTHON="python3"
fi
if [ -x "$ROOT/.venv/bin/streamlit" ]; then
    STREAMLIT="$ROOT/.venv/bin/streamlit run"
else
    STREAMLIT="$PYTHON -m streamlit run"
fi

need() {
    for f in "$@"; do
        if [ ! -f "$ROOT/$f" ]; then
            echo "missing required file: $f (run from a full checkout)" >&2
            exit 1
        fi
    done
}

port_open() {
    "$PYTHON" -c 'import socket,sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2)
s.close()' "$1" "$2" 2>/dev/null
}

wait_for_port() {
    # wait_for_port NAME HOST PORT TIMEOUT_SECS; warns (exit 1) on timeout.
    local end=$((SECONDS + $4))
    while [ "$SECONDS" -lt "$end" ]; do
        if port_open "$2" "$3"; then
            echo "   $1 is up ($2:$3)"
            return 0
        fi
        sleep 1
    done
    echo "   WARNING: $1 not reachable at $2:$3 after $4s" >&2
    return 1
}

launch() {
    # launch NAME LOG CMD... — fail fast with the log tail if it dies.
    local name="$1" log="$2"; shift 2
    echo "-> starting $name (log: $log)"
    "$@" >>"$log" 2>&1 &
    local pid=$!
    PIDS="$PIDS $pid"
    sleep 1
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "FAILED to start $name — last log lines:" >&2
        tail -n 20 "$log" >&2 || true
        exit 1
    fi
    echo "   $name running as pid $pid"
}

cleanup() {
    echo ""
    echo "Stopping Sentinel components..."
    if [ -n "$PIDS" ]; then
        # shellcheck disable=SC2086: word-splitting the pid list is intended
        kill $PIDS 2>/dev/null || true
        wait 2>/dev/null || true
    fi
    echo "Stopped."
}
trap cleanup INT TERM EXIT

# --- pre-flight: every entry point we might launch must exist ---
need sim/plc.py sim/sensors.py sim/yard.py
[ "$OPERATOR" = "scripted" ] && need sim/agents.py
[ "$OPERATOR" = "glimmer" ] && need sim/glimmer_operator.py
[ "$ROGUE" = 1 ] && need sim/rogue.py
[ "$CONSOLE" = 1 ] && need console/app.py
mkdir -p "$LOG_DIR"

# --- broker: reuse a live one, else start via systemctl (VM) or docker ---
if [ "$BROKER" = 1 ]; then
    if port_open 127.0.0.1 1883; then
        echo "-> broker already listening on 127.0.0.1:1883, leaving it alone"
    elif command -v systemctl >/dev/null 2>&1 \
            && systemctl cat mosquitto.service >/dev/null 2>&1; then
        echo "-> starting mosquitto via systemctl"
        sudo systemctl enable --now mosquitto
        wait_for_port broker 127.0.0.1 1883 15 || true
    elif command -v docker >/dev/null 2>&1; then
        ./sim/broker.sh
        wait_for_port broker 127.0.0.1 1883 20 || true
    else
        echo "WARNING: no broker on :1883 and neither systemctl mosquitto" >&2
        echo "nor docker is available — publishers will fail; console still works." >&2
    fi
fi

# --- sim world ---
launch plc "$LOG_DIR/plc.log" "$PYTHON" sim/plc.py
wait_for_port plc 127.0.0.1 5020 15 || {
    echo "plc never came up — see $LOG_DIR/plc.log" >&2; exit 1; }
launch sensors "$LOG_DIR/sensors.log" "$PYTHON" sim/sensors.py
launch yard "$LOG_DIR/yard.log" "$PYTHON" sim/yard.py --jitter 1 --drop 0.1

# --- operators ---
case "$OPERATOR" in
    scripted)
        launch operator "$LOG_DIR/operator.log" "$PYTHON" sim/agents.py ;;
    glimmer)
        launch glimmer-operator "$LOG_DIR/glimmer-operator.log" \
            "$PYTHON" sim/glimmer_operator.py \
            --backend "$GLIMMER_BACKEND" --cycles "$GLIMMER_CYCLES" ;;
    none)
        echo "-> operator skipped (--operator none)" ;;
esac
if [ "$ROGUE" = 1 ]; then
    launch rogue "$LOG_DIR/rogue.log" "$PYTHON" sim/rogue.py
fi

# --- console ---
if [ "$CONSOLE" = 1 ]; then
    # shellcheck disable=SC2086: STREAMLIT is a command + subcommand pair
    launch console "$LOG_DIR/console.log" $STREAMLIT console/app.py \
        --server.address "$BIND" --server.port "$PORT" --server.headless true
fi

echo ""
echo "All components running. Logs in $LOG_DIR"
if [ "$CONSOLE" = 1 ]; then
    if [ "$BIND" = "127.0.0.1" ] || [ "$BIND" = "localhost" ]; then
        echo "Console: http://localhost:$PORT (via SSH tunnel when on a VM)"
    else
        echo "Console: http://$BIND:$PORT"
    fi
fi
echo "Press Ctrl+C to stop everything."
wait
