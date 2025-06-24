#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

echo "--- NoirNote Agent Installer (Automated v2) ---"

# --- Configuration ---
AGENT_USER="noirnote-agent"
AGENT_DIR="/opt/noirnote-agent"
CONFIG_DIR="/etc/noirnote"
AGENT_SERVICE_FILE="/etc/systemd/system/noirnote-agent.service"
AGENT_SCRIPT_PATH="${AGENT_DIR}/noirnote_agent.py"
KEY_FILE_PATH="${CONFIG_DIR}/agent-key.json"
CONFIG_FILE_PATH="${CONFIG_DIR}/agent.conf"

# The URLs for the cloud functions
CLAIM_URL="https://us-central1-noirnote.cloudfunctions.net/claimAgentToken"
INGEST_URL="https://us-central1-noirnote.cloudfunctions.net/ingestMetrics"


# --- Helper Functions ---
function check_root() {
    if [ "$EUID" -ne 0 ]; then
      echo "Error: This installer must be run with sudo or as root."
      exit 1
    fi
}

function install_dependencies() {
    echo "--> [1/5] Installing dependencies..."
    if ! command -v apt-get &> /dev/null; then
        echo "Error: apt-get not found. This script is for Debian/Ubuntu systems."
        exit 1
    fi
    apt-get update -y > /dev/null
    apt-get install -y python3 python3-pip curl > /dev/null
    pip3 install psutil==5.9.8 requests==2.32.3 google-auth==2.28.2 > /dev/null
    echo "    - Dependencies installed."
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
    # Make sure to paste the updated noirnote_agent.py content here
    tee "$AGENT_SCRIPT_PATH" > /dev/null <<'AGENT_EOF'
# PASTE THE ENTIRE UPDATED CONTENT of your noirnote_agent.py SCRIPT HERE
AGENT_EOF
    chown "$AGENT_USER":"$AGENT_USER" "$AGENT_SCRIPT_PATH"
    chmod 750 "$AGENT_SCRIPT_PATH"
}

function configure_agent() {
    echo "--> [4/5] Claiming credentials and configuring agent..."
    
    # 1. Parse the --token argument
    TOKEN=""
    for arg in "$@"; do
        case $arg in
            --token=*)
            TOKEN="${arg#*=}"
            shift
            ;;
        esac
    done

    if [ -z "$TOKEN" ]; then
        echo "    [ERROR] --token flag is missing. Installation cannot proceed."
        exit 1
    fi
    echo "    - Using one-time token..."

    # 2. Call the claimAgentToken function to get credentials
    # The response is a JSON object like {"serviceAccountKey": {...}, "userUid": "...", "serverName": "..."}
    RESPONSE_JSON=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"token\": \"$TOKEN\"}" \
        "$CLAIM_URL")

    # 3. Check if the claim was successful and extract data using python3
    if [ -z "$RESPONSE_JSON" ] || [[ "$RESPONSE_JSON" != *"private_key"* ]]; then
        echo "    [ERROR] Failed to claim agent credentials. The token might be invalid, expired, or already used."
        echo "    Server Response: $RESPONSE_JSON"
        exit 1
    fi

    # Extract the values from the JSON response
    SERVICE_ACCOUNT_KEY_JSON=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; data = json.load(sys.stdin); print(json.dumps(data.get('serviceAccountKey'), indent=2)) if data.get('serviceAccountKey') else ''")
    USER_UID=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('userUid', ''))")
    SERVER_ID=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('serverName', ''))")
    
    if [ -z "$SERVICE_ACCOUNT_KEY_JSON" ] || [ -z "$USER_UID" ] || [ -z "$SERVER_ID" ]; then
        echo "    [ERROR] Claim response was incomplete. Could not find all required fields (serviceAccountKey, userUid, serverName)."
        exit 1
    fi
    
    echo "    - Credentials successfully claimed for server: '$SERVER_ID'"

    # 4. Save the service account key and the configuration file automatically
    echo "$SERVICE_ACCOUNT_KEY_JSON" > "$KEY_FILE_PATH"
    chown "$AGENT_USER":"$AGENT_USER" "$KEY_FILE_PATH"
    chmod 400 "$KEY_FILE_PATH"
    echo "    - Service account key saved securely."

    echo "SERVER_ID=$SERVER_ID" > "$CONFIG_FILE_PATH"
    echo "USER_UID=$USER_UID" >> "$CONFIG_FILE_PATH" # Add user UID to config
    echo "INGEST_FUNCTION_URL=$INGEST_URL" >> "$CONFIG_FILE_PATH"
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
configure_agent "$@" # Pass all arguments to the configure function
setup_service