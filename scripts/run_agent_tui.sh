#!/usr/bin/env bash
# Launch the built-in SploitGPT Textual TUI (agent + tools) inside Docker.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT_DIR}"

if ! docker info >/dev/null 2>&1; then
  echo "[!] Docker daemon not accessible. Fix (e.g., sudo usermod -aG docker $USER && newgrp docker)."
  exit 1
fi

# Ensure core services are up
docker compose up -d ollama sploitgpt >/dev/null

# Launch the Textual TUI inside the container (uses the full SploitGPT agent)
exec docker compose exec -it sploitgpt sploitgpt
