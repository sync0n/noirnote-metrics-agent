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
# The INGEST_URL is now written directly into the config file below
INGEST_URL="https://europe-west3-noirnote.cloudfunctions.net/ingestMetrics"

# --- Helper Functions ---
function check_root() {
    if [ "$EUID" -ne 0 ]; then
      echo "Error: This installer must be run with sudo or as root."
      exit 1
    fi
}

function install_dependencies() {
    # FIX: Added quotes around the echo statements
    echo "--> [1/5] Installing dependencies..."
    if ! command -v apt-get &> /dev/null; then
        echo "Error: apt-get not found. This script is for Debian/Ubuntu systems."
        exit 1
    fi
    apt-get update -y > /dev/null
    # Ensure python3-venv is installed for pip to work correctly in some environments
    apt-get install -y python3 python3-pip python3-venv curl > /dev/null
    # Using --break-system-packages is the modern, correct way for recent distros
    pip3 install --break-system-packages psutil==5.9.8 requests==2.32.3 google-auth==2.28.2 > /dev/null
    echo "    - Dependencies installed."
}

function setup_agent_user_and_dirs() {
    # FIX: Added quotes around the echo statements
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
    # FIX: Added quotes around the echo statements
    echo "--> [3/5] Creating agent script at ${AGENT_SCRIPT_PATH}..."
    # The agent code is embedded here using a "heredoc".
    # --- ENHANCEMENT: Merged the advanced agent code here ---
    tee "$AGENT_SCRIPT_PATH" > /dev/null <<'AGENT_EOF'
# agent/noirnote_agent.py
import psutil
import requests
import json
import time
import os
import traceback
from google.oauth2 import service_account
import google.auth.transport.requests

# --- Configuration ---
CONFIG_FILE_PATH = "/etc/noirnote/agent.conf"
KEY_FILE_PATH = "/etc/noirnote/agent-key.json"

# --- State for calculating network rate ---
last_net_io = psutil.net_io_counters()
last_time = time.time()

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

def get_service_account_credentials(key_path, target_audience):
    """
    Creates credentials that can be used to invoke a secured Cloud Run/Function service.
    """
    try:
        # This creates a credential object that can mint its own JWTs.
        creds = service_account.IDTokenCredentials.from_service_account_file(
            key_path,
            target_audience=target_audience
        )
        return creds
    except Exception as e:
        print(f"FATAL: Could not create service account credentials. Error: {e}")
        raise

def get_top_processes(limit=10):
    """Gets a list of the top N processes by combined CPU and Memory."""
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            # cpu_percent can be high initially, call it again for a better reading
            p.cpu_percent(interval=0.01) 
            time.sleep(0.01)
            p.cpu_percent(interval=None)
            procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    # Sort by cpu_percent, then memory_percent, descending
    top_procs = sorted(procs, key=lambda p: (p.info['cpu_percent'], p.info['memory_percent']), reverse=True)
    
    # Format the output
    return [
        {
            "pid": p.info['pid'], 
            "name": p.info['name'], 
            "cpu_percent": p.info['cpu_percent'],
            "memory_percent": p.info['memory_percent']
        } 
        for p in top_procs[:limit]
    ]
    
def get_disk_usage():
    """Gets usage for all physical disk partitions."""
    disks = []
    for part in psutil.disk_partitions(all=False):
        if 'loop' in part.device or 'tmpfs' in part.fstype:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "percent": usage.percent
            })
        except Exception:
            continue
    return disks

def get_network_rate():
    """Calculates the network rate in bytes per second."""
    global last_net_io, last_time
    
    current_net_io = psutil.net_io_counters()
    current_time = time.time()
    
    elapsed_time = current_time - last_time
    if elapsed_time <= 0:
        return {"bytes_sent_per_sec": 0, "bytes_recv_per_sec": 0}
        
    bytes_sent_rate = (current_net_io.bytes_sent - last_net_io.bytes_sent) / elapsed_time
    bytes_recv_rate = (current_net_io.bytes_recv - last_net_io.bytes_recv) / elapsed_time
    
    last_net_io = current_net_io
    last_time = current_time
    
    return {
        "bytes_sent_per_sec": int(bytes_sent_rate),
        "bytes_recv_per_sec": int(bytes_recv_rate)
    }

def collect_all_metrics():
    """Gathers all enhanced system metrics."""
    print("--> Collecting metrics...")
    psutil.cpu_percent(interval=0.5) 
    
    metrics = {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disks": get_disk_usage(),
        "processes": get_top_processes(),
        "network": get_network_rate()
    }
    print("--> Metrics collection complete.")
    return metrics

if __name__ == "__main__":
    print("Starting NoirNote Enhanced Metrics Agent...")
    try:
        config = load_config()
        credentials = get_service_account_credentials(KEY_FILE_PATH, config['INGEST_FUNCTION_URL'])
    except Exception as e:
        exit(1)
        
    print(f"Agent configured for server_id: {config.get('SERVER_ID', 'UNKNOWN')} reporting for user: {config.get('USER_UID', 'UNKNOWN')}")
    
    authed_session = google.auth.transport.requests.Request()

    while True:
        try:
            metrics = collect_all_metrics()
            
            payload = {
                "user_uid": config['USER_UID'],
                "server_id": config['SERVER_ID'],
                "metrics": metrics
            }
            
            credentials.refresh(authed_session)
            
            headers = {
                'Authorization': f'Bearer {credentials.token}',
                'Content-Type': 'application/json'
            }
            
            print(f"Pushing metrics to {config['INGEST_FUNCTION_URL']}")
            response = requests.post(config['INGEST_FUNCTION_URL'], json=payload, headers=headers, timeout=15)
            
            response.raise_for_status()
            print(f"Successfully pushed metrics. Status: {response.status_code}")

        except Exception as e:
            print(f"ERROR: Failed to collect or push metrics: {e}")
            traceback.print_exc()
        
        time.sleep(int(config.get('INTERVAL_SECONDS', 60)))
AGENT_EOF
    chown "$AGENT_USER":"$AGENT_USER" "$AGENT_SCRIPT_PATH"
    chmod 750 "$AGENT_SCRIPT_PATH"
}

function configure_agent() {
    # FIX: Added quotes around the echo statements
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

    if [ -f "$CONFIG_FILE_PATH" ] && [ -f "$KEY_FILE_PATH" ] && [ -z "$TOKEN" ]; then
        echo "    - Configuration files already exist. Skipping credential claim."
        return
    fi
    
    if [ -z "$TOKEN" ]; then
        echo "    [ERROR] --token flag is required for initial configuration."
        exit 1
    fi

    echo "    - Using one-time token to claim credentials..."
    RESPONSE_JSON=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"token\": \"$TOKEN\"}" \
        "$CLAIM_URL")

    if [ -z "$RESPONSE_JSON" ] || [[ "$RESPONSE_JSON" != *"private_key"* ]]; then
        echo "    [ERROR] Failed to claim agent credentials. Token may be invalid, expired, or used."
        echo "    Server Response: $RESPONSE_JSON"
        exit 1
    fi

    SERVICE_ACCOUNT_KEY_JSON=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; data = json.load(sys.stdin); print(json.dumps(data.get('serviceAccountKey'), indent=2)) if data.get('serviceAccountKey') else ''")
    USER_UID=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('userUid', ''))")
    SERVER_ID=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('serverName', ''))")
    
    if [ -z "$SERVICE_ACCOUNT_KEY_JSON" ] || [ -z "$USER_UID" ] || [ -z "$SERVER_ID" ]; then
        echo "    [ERROR] Claim response was incomplete. Could not find all required fields."
        exit 1
    fi
    
    echo "    - Credentials successfully claimed for server: '$SERVER_ID'"

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
    # FIX: Added quotes around the echo statements
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
ExecStart=/usr/bin/python3 -u /opt/noirnote-agent/noirnote_agent.py
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