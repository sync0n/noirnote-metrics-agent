code
Bash
download
content_copy
expand_less

#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

echo "--- NoirNote Agent Installer (Event Reporter v4) ---"

# --- Configuration ---
AGENT_USER="noirnote-agent"
AGENT_DIR="/opt/noirnote-agent"
CONFIG_DIR="/etc/noirnote"
# State directory for log-reading positions
STATE_DIR="/var/lib/noirnote-agent" 
AGENT_SERVICE_FILE="/etc/systemd/system/noirnote-agent.service"
AGENT_SCRIPT_PATH="${AGENT_DIR}/noirnote_agent.py"
KEY_FILE_PATH="${CONFIG_DIR}/agent-key.json"
CONFIG_FILE_PATH="${CONFIG_DIR}/agent.conf"

# The URLs for the cloud functions
CLAIM_URL="https://europe-west3-noirnote.cloudfunctions.net/claimAgentToken"
INGEST_URL="https://chronos.noirnote.it/ingest" 

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
    apt-get install -y python3 python3-pip python3-venv curl > /dev/null
    # Using --break-system-packages is the modern, correct way for recent distros
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

    # Grant user permission to read system logs
    usermod -a -G adm,systemd-journal ${AGENT_USER}
    echo "    - Granted '$AGENT_USER' read access to system logs."
    
    mkdir -p "$AGENT_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$STATE_DIR" # <-- NEW: Create state directory

    chown -R "$AGENT_USER":"$AGENT_USER" "$AGENT_DIR"
    chown -R "$AGENT_USER":"$AGENT_USER" "$CONFIG_DIR"
    chown -R "$AGENT_USER":"$AGENT_USER" "$STATE_DIR" # <-- NEW: Set ownership for state

    chmod 750 "$AGENT_DIR"
    chmod 750 "$CONFIG_DIR"
    chmod 750 "$STATE_DIR" # <-- NEW: Set permissions for state
}

function create_agent_script() {
    echo "--> [3/5] Creating agent script at ${AGENT_SCRIPT_PATH}..."
    # The full agent code with event reporting is embedded here.
    tee "$AGENT_SCRIPT_PATH" > /dev/null <<'AGENT_EOF'
# agent/noirnote_agent.py
import psutil
import requests
import json
import time
import os
import traceback
import re
import platform
import subprocess
from datetime import datetime
from google.oauth2 import service_account
import google.auth.transport.requests

# --- Configuration ---
CONFIG_FILE_PATH = "/etc/noirnote/agent.conf"
KEY_FILE_PATH = "/etc/noirnote/agent-key.json"
STATE_FILE_PATH = "/var/lib/noirnote-agent/state.json"

# --- State for calculating network rate ---
last_net_io = psutil.net_io_counters()
last_time = time.time()

# --- State Management Functions ---

def load_state():
    """Loads the agent's state from a file to avoid reprocessing events."""
    if not os.path.exists(STATE_FILE_PATH):
        return {}
    try:
        with open(STATE_FILE_PATH, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError, PermissionError) as e:
        print(f"WARN: Could not load agent state from {STATE_FILE_PATH}, starting fresh. Error: {e}")
        return {} # Return empty dict if file is corrupt, unreadable, or permission denied

def save_state(state):
    """Saves the agent's state to a file."""
    try:
        with open(STATE_FILE_PATH, 'w') as f:
            json.dump(state, f, indent=2)
    except (IOError, PermissionError) as e:
        print(f"ERROR: Could not save agent state to {STATE_FILE_PATH}: {e}")

# --- Event Collection: Linux Log Parsers ---

def _read_new_log_lines(log_path, state):
    """
    A generic helper to read new lines from a log file, handling log rotation.
    It uses the file's inode to detect rotation and byte offset for position.
    """
    new_lines = []
    if not os.path.exists(log_path):
        return new_lines

    try:
        current_inode = os.stat(log_path).st_ino
    except (FileNotFoundError, PermissionError) as e:
        print(f"WARN: Cannot stat log file {log_path}: {e}")
        return new_lines

    log_state = state.get(log_path, {})
    last_inode = log_state.get('inode')
    last_offset = log_state.get('offset', 0)

    # Check for log rotation
    if current_inode != last_inode:
        last_offset = 0

    try:
        with open(log_path, 'rb') as f: # Open as binary to get accurate byte offsets
            f.seek(last_offset)
            raw_lines = f.readlines()
            new_offset = f.tell()
    except (IOError, PermissionError) as e:
        print(f"WARN: Could not read from log file {log_path}: {e}")
        return new_lines
    
    # Decode lines, ignoring errors
    new_lines = [line.decode('utf-8', errors='ignore').strip() for line in raw_lines]

    # Update state for this file
    state[log_path] = {'inode': current_inode, 'offset': new_offset}
    
    return new_lines

def _create_event(event_type, summary):
    """Standardizes event creation."""
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "summary": summary
    }

def parse_auth_log(state):
    """Parses auth.log or secure for login events."""
    events = []
    log_file = '/var/log/auth.log' if os.path.exists('/var/log/auth.log') else '/var/log/secure'
    
    new_lines = _read_new_log_lines(log_file, state)
    for line in new_lines:
        # Successful SSH login
        match = re.search(r'sshd.*?session opened for user (\w+)', line)
        if match:
            user = match.group(1)
            events.append(_create_event('USER_LOGIN', f"User '{user}' logged in via SSH"))
            continue
            
        # Failed login
        match = re.search(r'Failed password for (\w+) from ([\d.]+)', line)
        if match:
            user, ip = match.groups()
            events.append(_create_event('FAILED_LOGIN', f"Failed password for '{user}' from {ip}"))
            continue

    return events

def parse_package_log(state):
    """Parses apt/history.log or dnf.log for package changes."""
    events = []
    log_files = ['/var/log/apt/history.log', '/var/log/dnf.log']
    
    log_file_to_use = None
    for f in log_files:
        if os.path.exists(f):
            log_file_to_use = f
            break
            
    if not log_file_to_use:
        return events

    new_lines = _read_new_log_lines(log_file_to_use, state)
    for line in new_lines:
        # APT Install/Upgrade
        install_match = re.search(r'Install: ([\w.+-]+):.*? \((.*?)\)', line)
        if install_match:
            package, version = install_match.groups()
            package_name = package.split(':')[0]
            events.append(_create_event('PACKAGE_CHANGE', f"Package '{package_name}' installed (version {version})"))
            continue
            
        upgrade_match = re.search(r'Upgrade: ([\w.+-]+):.*? \((.*?)\), ([\w.+-]+):.*? \((.*?)\)', line)
        if upgrade_match:
            package, old_ver, _, new_ver = upgrade_match.groups()
            package_name = package.split(':')[0]
            events.append(_create_event('PACKAGE_CHANGE', f"Package '{package_name}' upgraded to '{new_ver}'"))
            continue

        # DNF Install/Upgrade (often on the same "Upgraded" or "Installed" line)
        dnf_match = re.search(r'^(?:Install|Upgrade|Installed|Upgraded): ([\w-]+)-([0-9].*)', line)
        if dnf_match:
            package, version = dnf_match.groups()
            summary = f"Package '{package}' was installed or upgraded to version '{version}'"
            if any(e['summary'].startswith(f"Package '{package}'") for e in events):
                continue # Avoid duplicate events if DNF logs verbosely
            events.append(_create_event('PACKAGE_CHANGE', summary))

    return events

def parse_syslog_and_kern(state):
    """Parses common system logs for critical error messages."""
    events = []
    log_files = {
        '/var/log/syslog': 'SYSTEM_ERROR',
        '/var/log/messages': 'SYSTEM_ERROR',
        '/var/log/kern.log': 'KERNEL_ERROR',
    }
    keywords = ['error', 'failed', 'fatal', 'segfault', 'panic', 'out of memory', 'critical']

    for log_file, event_type in log_files.items():
        new_lines = _read_new_log_lines(log_file, state)
        for line in new_lines:
            if any(keyword in line.lower() for keyword in keywords):
                # Truncate long lines
                summary = (line[:250] + '...') if len(line) > 253 else line
                events.append(_create_event(event_type, summary))
    return events


# --- Event Collection: Windows ---

def get_windows_events(state):
    """Uses PowerShell to get new Windows Events."""
    events = []
    
    # --- Security Log: Successful Logins (EventID 4624) ---
    log_name = "Security"
    event_id = 4624
    state_key = f"win_event_{log_name}_{event_id}_last_id"
    last_record_id = state.get(state_key, 0)
    
    # Note: PowerShell 5.1 (default on Win10/Server2016/2019) syntax.
    # PowerShell 7+ might have slightly different parameter handling.
    ps_command = f"""
    Get-WinEvent -LogName {log_name} -FilterXPath "*[System[EventID={event_id} and EventRecordID > {last_record_id}]]" |
    Select-Object TimeCreated, Message, RecordId |
    Sort-Object RecordId |
    ConvertTo-Json
    """
    
    try:
        # The `capture_output=True`, `text=True` are crucial.
        result = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True, check=True, timeout=20)
        
        # PowerShell might return a single object or an array of objects.
        # `json.loads` will handle both.
        win_events = json.loads(result.stdout.strip())
        
        if not isinstance(win_events, list):
            win_events = [win_events]

        max_id = last_record_id
        for win_event in win_events:
            # Simple parsing of the message for the user. More complex parsing is possible.
            summary_match = re.search(r'Account Name:\s+([\w\-$]+)', win_event['Message'])
            summary = f"User '{summary_match.group(1)}' logged on." if summary_match else "A user successfully logged on."
            events.append(_create_event('USER_LOGIN', summary))
            if win_event['RecordId'] > max_id:
                max_id = win_event['RecordId']
        
        state[state_key] = max_id

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        # FileNotFoundError if powershell isn't on PATH.
        print(f"WARN: Could not execute PowerShell command for {log_name} log. Error: {e}")
    except Exception as e:
        print(f"ERROR: An unexpected error occurred while fetching Windows events. {e}")

    return events


# --- Main Orchestrator Functions ---

def collect_events(state):
    """Gathers all system events from various sources based on the OS."""
    all_events = []
    print("--> Collecting events...")
    
    system = platform.system()
    if system == "Linux":
        all_events.extend(parse_auth_log(state))
        all_events.extend(parse_package_log(state))
        all_events.extend(parse_syslog_and_kern(state))
    elif system == "Windows":
        all_events.extend(get_windows_events(state))
    else:
        print(f"WARN: Event collection not supported on this OS: {system}")

    if all_events:
        print(f"--> Collected {len(all_events)} new events.")
    return all_events

def collect_all_metrics():
    """Gathers all enhanced system metrics."""
    global last_net_io, last_time
    print("--> Collecting metrics...")

    # CPU
    psutil.cpu_percent(interval=0.1) # Prime the pump
    cpu_percent = psutil.cpu_percent(interval=1)
    
    # Memory
    mem = psutil.virtual_memory()
    memory_percent = mem.percent

    # Disk
    disks = []
    for part in psutil.disk_partitions(all=False):
        # Filter out docker overlayfs, tmpfs, and snap loops
        if 'loop' in part.device or any(fs in part.fstype for fs in ['tmpfs', 'squashfs']):
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
    
    # Processes
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            # This logic avoids re-calculating CPU for every process, but might be slightly stale.
            # For this agent's purpose, it's a good trade-off.
            procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    top_procs = sorted(procs, key=lambda p: (p.get('cpu_percent', 0) or 0, p.get('memory_percent', 0) or 0), reverse=True)


    # Network
    current_net_io = psutil.net_io_counters()
    current_time = time.time()
    elapsed_time = current_time - last_time
    if elapsed_time <= 0:
        net_rate = {"bytes_sent_per_sec": 0, "bytes_recv_per_sec": 0}
    else:
        bytes_sent_rate = (current_net_io.bytes_sent - last_net_io.bytes_sent) / elapsed_time
        bytes_recv_rate = (current_net_io.bytes_recv - last_net_io.bytes_recv) / elapsed_time
        net_rate = {
            "bytes_sent_per_sec": int(bytes_sent_rate),
            "bytes_recv_per_sec": int(bytes_recv_rate)
        }
    last_net_io = current_net_io
    last_time = current_time

    metrics = {
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "disks": disks,
        "processes": top_procs[:10],
        "network": net_rate,
    }
    print("--> Metrics collection complete.")
    return metrics


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
    """Creates credentials that can be used to invoke a secured Cloud Run/Function service."""
    try:
        creds = service_account.IDTokenCredentials.from_service_account_file(
            key_path,
            target_audience=target_audience
        )
        return creds
    except Exception as e:
        print(f"FATAL: Could not create service account credentials. Error: {e}")
        raise

# --- Main Execution Loop ---
if __name__ == "__main__":
    print("Starting NoirNote Event & Metrics Agent...")
    try:
        config = load_config()
        credentials = get_service_account_credentials(KEY_FILE_PATH, config['INGEST_FUNCTION_URL'])
    except Exception as e:
        exit(1)
        
    print(f"Agent configured for server_id: {config.get('SERVER_ID', 'UNKNOWN')} "
          f"workspace_id: {config.get('WORKSPACE_ID', 'UNKNOWN')}")
    
    # Load state at startup
    state = load_state()
    
    authed_session = google.auth.transport.requests.Request()

    while True:
        try:
            # Collect both metrics and events
            metrics = collect_all_metrics()
            events = collect_events(state)
            
            # Construct the full payload
            payload = {
                "user_id": config['USER_ID'],
                "workspace_id": config['WORKSPACE_ID'],
                "server_id": config['SERVER_ID'],
                "metrics": metrics,
                "events": events
            }
            
            # Send data only if there's something to send (metrics are always sent)
            if not metrics and not events:
                print("No new metrics or events to send. Skipping cycle.")
            else:
                credentials.refresh(authed_session)
                
                headers = {
                    'Authorization': f'Bearer {credentials.token}',
                    'Content-Type': 'application/json'
                }
                
                print(f"Pushing payload to {config['INGEST_FUNCTION_URL']}...")
                # print(json.dumps(payload, indent=2)) # Uncomment for deep debugging
                response = requests.post(config['INGEST_FUNCTION_URL'], json=payload, headers=headers, timeout=30)
                
                response.raise_for_status()
                print(f"Successfully pushed payload. Status: {response.status_code}")

                # Save state only after a successful send
                save_state(state)

        except requests.exceptions.RequestException as e:
            print(f"ERROR: Network error while pushing payload: {e}")
            # Do NOT save state on network failure, so we can retry sending the events.
        except Exception as e:
            print(f"ERROR: An unhandled exception occurred in the main loop: {e}")
            traceback.print_exc()
            # Optionally save state here depending on whether the error was pre- or post-send.
            # For safety, we don't save state on generic errors to avoid data loss.
        
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
    
    USER_ID=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('userId', ''))")
    SERVER_ID=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('serverId', ''))")
    
    if [ -z "$SERVICE_ACCOUNT_KEY_JSON" ] || [ -z "$USER_ID" ] || [ -z "$SERVER_ID" ]; then
        echo "    [ERROR] Claim response was incomplete. Could not find all required fields."
        exit 1
    fi
    
    echo "    - Credentials successfully claimed for server: '$SERVER_ID'"

    echo "$SERVICE_ACCOUNT_KEY_JSON" > "$KEY_FILE_PATH"
    chown "$AGENT_USER":"$AGENT_USER" "$KEY_FILE_PATH"
    chmod 400 "$KEY_FILE_PATH"
    echo "    - Service account key saved securely."

    # Write all configuration values
    echo "SERVER_ID=$SERVER_ID" > "$CONFIG_FILE_PATH"
    echo "USER_ID=$USER_ID" >> "$CONFIG_FILE_PATH"
    echo "WORKSPACE_ID=$USER_ID" >> "$CONFIG_FILE_PATH" # <-- NEW: Set Workspace to User ID
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
Description=NoirNote Event & Metrics Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=noirnote-agent
Group=noirnote-agent
# Add adm and systemd-journal groups for log reading access
SupplementaryGroups=adm systemd-journal
ExecStart=/usr/bin/python3 -u /opt/noirnote-agent/noirnote_agent.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE_EOF
    
    systemctl daemon-reload
    systemctl enable noirnote-agent.service
    systemctl restart noirnote-agent.service # Use restart to ensure changes take effect
    
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