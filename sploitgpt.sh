#!/bin/bash
#!/bin/bash
# Quick start script for SploitGPT (works from any directory)

set -euo pipefail

ROOT_DIR="/home/cheese/SploitGPT"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"

cd "$ROOT_DIR"

# Ensure Docker daemon is accessible
if ! docker info >/dev/null 2>&1; then
  echo "[!] Docker daemon is not accessible for the current user."
  echo "    Fix (recommended): sudo usermod -aG docker $USER && newgrp docker"
  echo "    Or run docker commands with sudo (less ideal for file permissions)."
  exit 1
fi

# Bring up required services if not running
if [ -z "$(docker compose -f "$COMPOSE_FILE" ps --status running -q ollama 2>/dev/null)" ] || \
   [ -z "$(docker compose -f "$COMPOSE_FILE" ps --status running -q sploitgpt 2>/dev/null)" ]; then
  docker compose -f "$COMPOSE_FILE" up -d
fi

# Exec into the app container to start the TUI
docker compose -f "$COMPOSE_FILE" exec sploitgpt sploitgpt "$@"
