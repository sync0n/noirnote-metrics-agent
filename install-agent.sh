#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

echo "--- NoirNote Agent Installer (Robust Version) ---"

# --- Configuration ---
AGENT_USER="noirnote-agent"
AGENT_DIR="/opt/noirnote-agent"
CONFIG_DIR="/etc/noirnote"
AGENT_SERVICE_FILE="/etc/systemd/system/noirnote-agent.service"
AGENT_SCRIPT_PATH="${AGENT_DIR}/noirnote_agent.py"
KEY_FILE_PATH="${CONFIG_DIR}/agent-key.json"
CONFIG_FILE_PATH="${CONFIG_DIR}/agent.conf"
FUNCTION_URL="https://us-central1-noirnote.cloudfunctions.net/ingestMetrics"

# --- Helper Functions ---
function check_root() {
    if [ "$EUID" -ne 0 ]; then
      echo "Error: This installer must be run with sudo or as root."
      exit 1
    fi
}

function install_dependencies() {
    echo "--> [1/5] Installing dependencies via apt..."
    if ! command -v apt-get &> /dev/null; then
        echo "Error: apt-get not found. This script is designed for Debian-based systems (Debian, Ubuntu)."
        exit 1
    fi
    
    # --- THIS IS THE FIX ---
    # Refresh package list and install the Debian/Ubuntu packaged versions of our dependencies.
    # This is the correct way to handle PEP 668-protected environments.
    apt-get update
    apt-get install -y python3-pip python3-psutil python3-requests python3-google-auth
    # --- END FIX ---
}

function setup_agent_user_and_dirs() {
    echo "--> [2/5] Setting up user and directories..."
    if ! id -u "$AGENT_USER" >/dev/null 2>&1; then
        useradd --system --shell /usr/sbin/nologin "$AGENT_USER"
        echo "    - Created system user '$AGENT_USER'"
    else
        echo "    - System user '$AGENT_USER' already exists."
    fi
    
    mkdir -p "$AGENT_DIR"
    mkdir -p "$CONFIG_DIR"
    chown -R "$AGENT_USER":"$AGENT_USER" "$AGENT_DIR"
    chown -R "$AGENT_USER":"$AGENT_USER" "$CONFIG_DIR"
    chmod 750 "$AGENT_DIR"
    chmod 750 "$CONFIG_DIR"
}

function create_agent_script() {
    echo "--> [3/5] Creating agent script at ${AGENT_SCRIPT_PATH}..."
    # The agent code will be placed here.
    tee "$AGENT_SCRIPT_PATH" > /dev/null <<'AGENT_EOF'
# PASTE THE ENTIRE, REFINED CONTENT of your noirnote_agent.py SCRIPT HERE
AGENT_EOF
    chown "$AGENT_USER":"$AGENT_USER" "$AGENT_SCRIPT_PATH"
    chmod 750 "$AGENT_SCRIPT_PATH"
}

function configure_agent() {
    echo ""
    echo "--> [4/5] Configuring agent..."
    echo "    Please paste the entire content of your service account JSON key file."
    echo "    Press Enter, then Ctrl+D when you are finished."
    cat > "$KEY_FILE_PATH"
    chown "$AGENT_USER":"$AGENT_USER" "$KEY_FILE_PATH"
    chmod 400 "$KEY_FILE_PATH" # Make key readable only by the owner.
    echo "    - Service account key saved securely."

    echo ""
    read -p "    Enter a unique name for this server (e.g., web-prod-01): " SERVER_ID
    
    echo "SERVER_ID=$SERVER_ID" > "$CONFIG_FILE_PATH"
    echo "INGEST_FUNCTION_URL=$FUNCTION_URL" >> "$CONFIG_FILE_PATH"
    echo "INTERVAL_SECONDS=60" >> "$CONFIG_FILE_PATH"
    chown "$AGENT_USER":"$AGENT_USER" "$CONFIG_FILE_PATH"
    chmod 640 "$CONFIG_FILE_PATH"
    echo "    - Configuration file created."
}

function setup_service() {
    echo "--> [5/5] Setting up and starting systemd service..."
    tee "$AGENT_SERVICE_FILE" > /dev/null <<'SERVICE_EOF'
[Unit]
Description=NoirNote Metrics Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=noirnote-agent
Group=noirnote-agent
ExecStart=/usr/bin/python3 /opt/noirnote-agent/noirnote_agent.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE_EOF
    
    systemctl daemon-reload
    systemctl enable noirnote-agent.service
    systemctl start noirnote-agent.service
    
    echo ""
    echo "--- Installation Complete! ---"
    echo "The NoirNote agent is now running."
    echo "To check its status, run: systemctl status noirnote-agent.service"
    echo "To view live logs, run:    journalctl -u noirnote-agent.service -f"
}

# --- Main Execution ---
check_root
install_dependencies
setup_agent_user_and_dirs
create_agent_script
configure_agent
setup_service