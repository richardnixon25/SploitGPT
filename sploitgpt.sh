#!/bin/bash
# Quick start script for SploitGPT (works from any directory)

set -euo pipefail

ROOT_DIR="/home/cheese/SploitGPT"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"

cd "$ROOT_DIR"

# Launch the built-in Textual TUI (agent-driven) inside Docker
exec "${ROOT_DIR}/scripts/run_agent_tui.sh" "$@"
