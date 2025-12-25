#!/usr/bin/env bash
# Run the real SploitGPT agent (CLI) inside the Docker container.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT_DIR}"

if ! docker info >/dev/null 2>&1; then
  echo "[!] Docker daemon not accessible. Fix (e.g., sudo usermod -aG docker $USER && newgrp docker)."
  exit 1
fi

# Ensure core services are up
docker compose up -d ollama sploitgpt >/dev/null

# Attach to the agent CLI (tool-enabled) inside the container
docker compose exec -it sploitgpt sploitgpt --cli
