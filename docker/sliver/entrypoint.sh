#!/bin/bash
# SploitGPT Sliver Entrypoint Script
# Handles daemon mode, operator generation, and interactive shell
set -e

SLIVER_DIR="/root/.sliver"
CONFIGS_DIR="/app/configs"

# Generate operator config if it doesn't exist
generate_operator() {
    local operator_name="${1:-sploitgpt}"
    local config_file="${CONFIGS_DIR}/${operator_name}.cfg"
    
    if [ ! -f "$config_file" ]; then
        echo "[*] Generating operator config for '${operator_name}'..."
        
        # Start server temporarily to generate config
        /usr/local/bin/sliver-server daemon &
        DAEMON_PID=$!
        
        # Wait for server to be ready
        echo "[*] Waiting for Sliver server to start..."
        sleep 5
        
        # Generate operator config with full permissions
        /usr/local/bin/sliver-server operator --name "${operator_name}" --lhost 0.0.0.0 --permissions all --save "${config_file}"
        
        # Stop temporary daemon
        kill $DAEMON_PID 2>/dev/null || true
        wait $DAEMON_PID 2>/dev/null || true
        
        echo "[+] Operator config saved to: ${config_file}"
    else
        echo "[*] Operator config already exists: ${config_file}"
    fi
}

# Display banner
echo "==========================================="
echo "  SploitGPT Sliver C2 Server"
echo "  Version: $(sliver-server version 2>/dev/null | head -1 || echo 'v1.6.1')"
echo "==========================================="

case "$1" in
    daemon)
        # Generate default operator config
        generate_operator "sploitgpt"
        
        echo "[*] Starting Sliver server in daemon mode..."
        echo "[*] gRPC API listening on port 31337"
        exec /usr/local/bin/sliver-server daemon
        ;;
    
    operator)
        # Generate operator config with custom name
        shift
        generate_operator "${1:-sploitgpt}"
        ;;
    
    shell|console)
        # Start interactive Sliver console
        exec /usr/local/bin/sliver-server
        ;;
    
    client)
        # Run Sliver client with provided config
        shift
        exec /usr/local/bin/sliver-client "$@"
        ;;
    
    version)
        /usr/local/bin/sliver-server version
        ;;
    
    help|--help|-h)
        echo "Usage: docker run sploitgpt-sliver [command]"
        echo ""
        echo "Commands:"
        echo "  daemon    - Start Sliver server in daemon mode (default)"
        echo "  operator  - Generate operator config (operator [name])"
        echo "  shell     - Start interactive Sliver console"
        echo "  client    - Run Sliver client"
        echo "  version   - Show Sliver version"
        echo "  help      - Show this help"
        echo ""
        echo "Ports:"
        echo "  31337     - gRPC API (mTLS)"
        echo "  8888      - mTLS implant listener"
        echo "  80/443    - HTTP/HTTPS C2"
        echo "  53/udp    - DNS C2"
        echo ""
        echo "Volumes:"
        echo "  /root/.sliver  - Sliver data (configs, implants, loot)"
        echo "  /app/configs   - Operator configs for SploitGPT"
        ;;
    
    *)
        # Pass through to sliver-server
        exec /usr/local/bin/sliver-server "$@"
        ;;
esac
