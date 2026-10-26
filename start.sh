#!/usr/bin/env bash
# Start every Optimus service with one command.
#   main app  : FastAPI on :8000  -> serves the Defender/Transmitter/Simulator frontend + REST API
#   attacker  : FastAPI on :8001  -> Part 2 AI Attacker UI, talks to the main app's attack gateway
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

MAIN_PORT=8000
ATTACKER_PORT=8001
SOURCE=hohenheim
WITH_ATTACKER=1
LOG_DIR="${TMPDIR:-/tmp}/optimus-logs"

usage() {
  cat <<'EOF'
Usage: ./start.sh [options]

  --source hohenheim|simulator  Data source for the main app (default: hohenheim)
  --main-port N                 Defender app port (default: 8000)
  --attacker-port N             Attacker app port (default: 8001)
  --no-attacker                 Start only the main app
  -h, --help                    Show this help

Ctrl-C stops both services.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)        SOURCE="${2:?--source needs a value}"; shift 2 ;;
    --main-port)     MAIN_PORT="${2:?--main-port needs a value}"; shift 2 ;;
    --attacker-port) ATTACKER_PORT="${2:?--attacker-port needs a value}"; shift 2 ;;
    --no-attacker)   WITH_ATTACKER=0; shift ;;
    -h|--help)       usage; exit 0 ;;
    *)               echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$SOURCE" in
  hohenheim|simulator) ;;
  *) echo "--source must be 'hohenheim' or 'simulator'" >&2; exit 2 ;;
esac

if [[ -x .venv/bin/python ]]; then PY=.venv/bin/python; else PY=python3; fi
mkdir -p "$LOG_DIR"

# Nothing listening on the port? (pure bash, no ss/netstat/curl needed)
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

require_free() {
  if port_busy "$1"; then
    echo "Port $1 is already in use - another Optimus instance may still be running." >&2
    echo "Stop it (Ctrl-C in that terminal, or 'pkill -f run.py') and retry." >&2
    exit 1
  fi
}

PIDS=()
CLEANED=0
cleanup() {
  [[ $CLEANED -eq 1 ]] && return
  CLEANED=1
  trap - EXIT INT TERM
  [[ ${#PIDS[@]} -eq 0 ]] && return
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  echo "Services stopped."
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# wait_up <label> <port> <pid> <logfile>
wait_up() {
  local label=$1 port=$2 pid=$3 log=$4 i
  for ((i = 0; i < 150; i++)); do
    port_busy "$port" && return 0
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "$label failed to start. Last lines of $log:" >&2
      tail -n 20 "$log" >&2
      return 1
    fi
    sleep 0.2
  done
  echo "$label did not answer on port $port within 30s. Last lines of $log:" >&2
  tail -n 20 "$log" >&2
  return 1
}

require_free "$MAIN_PORT"
require_free "$ATTACKER_PORT"

echo "Starting Defender app (:${MAIN_PORT}, source=${SOURCE})..."
"$PY" run.py --source "$SOURCE" --host 127.0.0.1 --port "$MAIN_PORT" >"$LOG_DIR/main.log" 2>&1 &
PIDS+=($!)
wait_up "Defender app" "$MAIN_PORT" "${PIDS[0]}" "$LOG_DIR/main.log"

ATTACKER_UP=""
if [[ $WITH_ATTACKER -eq 1 ]]; then
  echo "Starting Attacker app (:${ATTACKER_PORT})..."
  "$PY" run_attacker.py --host 127.0.0.1 --port "$ATTACKER_PORT" \
    --gateway "http://127.0.0.1:${MAIN_PORT}/api/attacker" >"$LOG_DIR/attacker.log" 2>&1 &
  PIDS+=($!)
  wait_up "Attacker app" "$ATTACKER_PORT" "${PIDS[1]}" "$LOG_DIR/attacker.log"
  ATTACKER_UP="http://127.0.0.1:${ATTACKER_PORT}/"
fi

echo
echo "Optimus is up. Ctrl-C to stop everything."
echo "  Defender portal   http://127.0.0.1:${MAIN_PORT}/"
echo "  Transmitter       http://127.0.0.1:${MAIN_PORT}/transmitter"
echo "  Attack simulator  http://127.0.0.1:${MAIN_PORT}/simulator"
echo "  API docs          http://127.0.0.1:${MAIN_PORT}/api/docs"
[[ -n $ATTACKER_UP ]] && echo "  Attacker UI       ${ATTACKER_UP}"
echo "  Logs              ${LOG_DIR}/{main,attacker}.log"
echo

wait -n 2>/dev/null || wait
