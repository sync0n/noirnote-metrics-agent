#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

echo "--- NoirNote Agent Installer (Automated v3 - Final) ---"

# --- Configuration ---
AGENT_USER="noirnote-agent"
AGENT_DIR="/opt/noirnote-agent"
CONFIG_DIR="/etc/noirnote"
AGENT_SERVICE_FILE="/etc/systemd/system/noirnote-agent.service"
AGENT_SCRIPT_PATH="${AGENT_DIR}/noirnote_agent.py"
KEY_FILE_PATH="${CONFIG_DIR}/agent-key.json"
CONFIG_FILE_PATH="${CONFIG_DIR}/agent.conf"

# The URLs for the cloud functions
CLAIM_URL="https://europe-west3-noirnote.cloudfunctions.net/claimAgentToken"
INGEST_URL="INGEST_URL="https://chronos.noirnote.it/ingest"

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
    pip3 install --break-system-packages psutil==5.9.8 requests==2.32.3 google-auth==2.28.2 > /dev/null
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
    # The agent code is embedded here using a "heredoc".
    tee "$AGENT_SCRIPT_PATH" > /dev/null <<'AGENT_EOF'
# agent/noirnote_agent.py
import psutil
import requests
import json
import time
import os
from google.oauth2 import service_account
import google.auth.transport.requests

# --- Configuration ---
CONFIG_FILE_PATH = "/etc/noirnote/agent.conf"
KEY_FILE_PATH = "/etc/noirnote/agent-key.json"

def load_config():
    """Loads agent configuration from the config file."""
    config = {}
    if not os.path.exists(CONFIG_FILE_PATH):
        print(f"FATAL: Config file not found at '{CONFIG_FILE_PATH}'")
        raise FileNotFoundError
    with open(CONFIG_FILE_PATH, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                config[key.strip()] = value.strip()
    return config

def get_authenticated_session(key_path, target_audience):
    """
    Creates credentials that can be used to invoke a secured Cloud Function.
    """
    try:
        creds = service_account.IDTokenCredentials.from_service_account_file(
            key_path,
            target_audience=target_audience
        )
        return creds
    except FileNotFoundError:
        print(f"FATAL: Service account key file not found at '{key_path}'.")
        raise
    except Exception as e:
        print(f"FATAL: Could not create authenticated session. Error: {e}")
        raise

def collect_metrics():
    """Gathers system metrics using psutil."""
    return {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent
    }

if __name__ == "__main__":
    print("Starting NoirNote Metrics Agent...")
    try:
        config = load_config()
        credentials = get_authenticated_session(KEY_FILE_PATH, config['INGEST_FUNCTION_URL'])
    except Exception as e:
        exit(1)
        
    print(f"Agent configured for server_id: {config.get('SERVER_ID', 'UNKNOWN')} reporting for user: {config.get('USER_UID', 'UNKNOWN')}")
    
    # Create a transport request object to handle token refreshes automatically.
    authed_session = google.auth.transport.requests.Request()

    while True:
        try:
            metrics = collect_metrics()
            
            payload = {
                "server_id": config['SERVER_ID'],
                "user_uid": config['USER_UID'],
                "metrics": metrics
            }
            
            # Refresh the token if it's about to expire
            credentials.refresh(authed_session)
            
            headers = {
                'Authorization': f'Bearer {credentials.token}',
                'Content-Type': 'application/json'
            }
            
            print(f"Pushing metrics: {payload}")
            response = requests.post(config['INGEST_FUNCTION_URL'], json=payload, headers=headers, timeout=15)
            
            response.raise_for_status()
            print(f"Successfully pushed metrics. Status: {response.status_code}")

        except Exception as e:
            print(f"ERROR: Failed to collect or push metrics: {e}")
        
        time.sleep(int(config.get('INTERVAL_SECONDS', 60)))
AGENT_EOF
    chown "$AGENT_USER":"$AGENT_USER" "$AGENT_SCRIPT_PATH"
    chmod 750 "$AGENT_SCRIPT_PATH"
}

function configure_agent() {
    echo "--> [4/5] Configuring agent..."
    
    TOKEN=""
    for arg in "$@"; do
        case $arg in
            --token=*)
            TOKEN="${arg#*=}"
            shift
            ;;
        esac
    done

    # If config files already exist AND no new token was provided, skip this step.
    if [ -f "$CONFIG_FILE_PATH" ] && [ -f "$KEY_FILE_PATH" ] && [ -z "$TOKEN" ]; then
        echo "    - Configuration files already exist. Skipping credential claim."
        return
    fi
    
    # If we are here, we either need to configure for the first time or re-configure.
    if [ -z "$TOKEN" ]; then
        echo "    [ERROR] --token flag is required for initial configuration."
        exit 1
    fi

    echo "    - Using one-time token to claim credentials..."
    RESPONSE_JSON=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"token\": \"$TOKEN\"}" \
        "$CLAIM_URL")

    # Check for a valid response
    if [ -z "$RESPONSE_JSON" ] || [[ "$RESPONSE_JSON" != *"private_key"* ]]; then
        echo "    [ERROR] Failed to claim agent credentials. Token may be invalid, expired, or used."
        echo "    Server Response: $RESPONSE_JSON"
        exit 1
    fi

    # Extract data using python3 to safely parse the JSON
    SERVICE_ACCOUNT_KEY_JSON=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; data = json.load(sys.stdin); print(json.dumps(data.get('serviceAccountKey'), indent=2)) if data.get('serviceAccountKey') else ''")
    USER_UID=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('userUid', ''))")
    SERVER_ID=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('serverName', ''))")
    
    if [ -z "$SERVICE_ACCOUNT_KEY_JSON" ] || [ -z "$USER_UID" ] || [ -z "$SERVER_ID" ]; then
        echo "    [ERROR] Claim response was incomplete. Could not find all required fields."
        exit 1
    fi
    
    echo "    - Credentials successfully claimed for server: '$SERVER_ID'"

    # Save the files
    echo "$SERVICE_ACCOUNT_KEY_JSON" > "$KEY_FILE_PATH"
    chown "$AGENT_USER":"$AGENT_USER" "$KEY_FILE_PATH"
    chmod 400 "$KEY_FILE_PATH"
    echo "    - Service account key saved securely."

    echo "SERVER_ID=$SERVER_ID" > "$CONFIG_FILE_PATH"
    echo "USER_UID=$USER_UID" >> "$CONFIG_FILE_PATH"
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
configure_agent "$@"
setup_service