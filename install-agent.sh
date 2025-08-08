#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

echo "--- NoirNote Agent Installer (Full State v5) ---"

# --- Configuration ---
AGENT_USER="noirnote-agent"
AGENT_DIR="/opt/noirnote-agent"
CONFIG_DIR="/etc/noirnote"
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
    # Add net-tools for the 'netstat' command required by the new agent
    apt-get install -y python3 python3-pip python3-venv curl net-tools > /dev/null
    # Using --break-system-packages is the modern, correct way for recent distros
    pip3 install --break-system-packages psutil==5.9.8 requests==2.32.3 google-auth==2.28.2 > /dev/null
    echo "    - Dependencies installed (including net-tools)."
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
    mkdir -p "$STATE_DIR"

    chown -R "$AGENT_USER":"$AGENT_USER" "$AGENT_DIR"
    chown -R "$AGENT_USER":"$AGENT_USER" "$CONFIG_DIR"
    chown -R "$AGENT_USER":"$AGENT_USER" "$STATE_DIR"

    chmod 750 "$AGENT_DIR"
    chmod 750 "$CONFIG_DIR"
    chmod 750 "$STATE_DIR"
}

function create_agent_script() {
    echo "--> [3/5] Creating agent script at ${AGENT_SCRIPT_PATH}..."
    # The full agent code with state snapshot reporting is embedded here.
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

# --- State Management Functions (for event processing) ---

def load_state():
    """Loads the agent's state from a file to avoid reprocessing events."""
    if not os.path.exists(STATE_FILE_PATH):
        return {}
    try:
        with open(STATE_FILE_PATH, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError, PermissionError) as e:
        print(f"WARN: Could not load agent state from {STATE_FILE_PATH}, starting fresh. Error: {e}")
        return {}

def save_state(state):
    """Saves the agent's state to a file."""
    try:
        with open(STATE_FILE_PATH, 'w') as f:
            json.dump(state, f, indent=2)
    except (IOError, PermissionError) as e:
        print(f"ERROR: Could not save agent state to {STATE_FILE_PATH}: {e}")

# --- State Snapshot Collection (for AI Root Cause Analysis) ---

def _run_command(command):
    """A robust helper to run a shell command and return its output or an error."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=20,
            check=False  # Don't raise exception on non-zero exit codes
        )
        if result.returncode != 0:
            # Combine stdout and stderr for better error context
            error_output = (result.stdout.strip() + " " + result.stderr.strip()).strip()
            return f"Error executing command '{command}': [Exit Code {result.returncode}] {error_output}"
        return result.stdout.strip()
    except FileNotFoundError:
        return f"Error: Command not found for '{command}'."
    except subprocess.TimeoutExpired:
        return f"Error: Command '{command}' timed out after 20 seconds."
    except Exception as e:
        return f"An unexpected error occurred while running '{command}': {e}"

def get_dmesg_output():
    """Gets kernel ring buffer messages."""
    return _run_command("dmesg -T")

def get_netstat_output():
    """Gets network connection and listening port information."""
    return _run_command("netstat -tulnp")

def get_syslog_snippet():
    """Gets the last 200 lines from journalctl or syslog."""
    if os.path.exists('/bin/journalctl'):
        return _run_command("journalctl -n 200 --no-pager")
    elif os.path.exists('/var/log/syslog'):
        return _run_command("tail -n 200 /var/log/syslog")
    else:
        return "Neither journalctl nor /var/log/syslog found."

def get_messages_log_snippet():
    """Gets the last 200 lines from /var/log/messages (for RHEL/CentOS)."""
    if os.path.exists('/var/log/messages'):
        return _run_command("tail -n 200 /var/log/messages")
    return ""  # Return empty if file doesn't exist, not an error

def get_kern_log_snippet():
    """Gets the last 200 lines from /var/log/kern.log."""
    if os.path.exists('/var/log/kern.log'):
        return _run_command("tail -n 200 /var/log/kern.log")
    return ""

def get_auth_log_snippet():
    """Gets the last 200 lines from the auth log."""
    if os.path.exists('/var/log/auth.log'):
        return _run_command("tail -n 200 /var/log/auth.log")
    elif os.path.exists('/var/log/secure'):
        return _run_command("tail -n 200 /var/log/secure")
    return ""

def get_windows_event_logs():
    """Queries and formats the last 50 System and Security events on Windows."""
    ps_command = """
    $logs = @{
        "System" = Get-WinEvent -LogName System -MaxEvents 50 | Select-Object TimeCreated, LevelDisplayName, Message -ErrorAction SilentlyContinue;
        "Security" = Get-WinEvent -LogName Security -MaxEvents 50 | Select-Object TimeCreated, Message -ErrorAction SilentlyContinue
    }
    $logs | ConvertTo-Json -Compress -Depth 3
    """
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=30,
            check=True
        )
        return json.loads(result.stdout.strip())
    except FileNotFoundError:
        return {"error": "PowerShell is not installed or not in PATH."}
    except subprocess.CalledProcessError as e:
        return {"error": f"PowerShell command failed: {e.stderr}"}
    except subprocess.TimeoutExpired:
        return {"error": "PowerShell command timed out after 30 seconds."}
    except json.JSONDecodeError:
        return {"error": "Failed to parse JSON output from PowerShell."}
    except Exception as e:
        return {"error": f"An unexpected error occurred while fetching Windows events: {e}"}

def collect_state_snapshot():
    """
    Orchestrates the collection of a comprehensive state snapshot for analysis.
    """
    print("--> Collecting state snapshot...")
    snapshot = {}
    system = platform.system()

    if system == "Linux":
        snapshot['dmesg'] = get_dmesg_output()
        snapshot['netstat'] = get_netstat_output()
        snapshot['syslog_snippet'] = get_syslog_snippet()
        snapshot['messages_log_snippet'] = get_messages_log_snippet()
        snapshot['kern_log_snippet'] = get_kern_log_snippet()
        snapshot['auth_log_snippet'] = get_auth_log_snippet()
    elif system == "Windows":
        snapshot['windows_event_logs'] = get_windows_event_logs()

    print("--> State snapshot collection complete.")
    return snapshot

# --- Event Collection ---

def _read_new_log_lines(log_path, state):
    """Generic helper to read new lines from a log file, handling log rotation."""
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
    if current_inode != last_inode:
        last_offset = 0
    try:
        with open(log_path, 'rb') as f:
            f.seek(last_offset)
            raw_lines = f.readlines()
            new_offset = f.tell()
    except (IOError, PermissionError) as e:
        print(f"WARN: Could not read from log file {log_path}: {e}")
        return new_lines
    new_lines = [line.decode('utf-8', errors='ignore').strip() for line in raw_lines]
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
    for line in _read_new_log_lines(log_file, state):
        match = re.search(r'sshd.*?session opened for user (\w+)', line)
        if match:
            events.append(_create_event('USER_LOGIN', f"User '{match.group(1)}' logged in via SSH"))
            continue
        match = re.search(r'Failed password for (\w+) from ([\d.]+)', line)
        if match:
            events.append(_create_event('FAILED_LOGIN', f"Failed password for '{match.group(1)}' from {match.group(2)}"))
            continue
    return events

def parse_package_log(state):
    """Parses apt/history.log or dnf.log for package changes."""
    events = []
    log_file = None
    for f in ['/var/log/apt/history.log', '/var/log/dnf.log']:
        if os.path.exists(f):
            log_file = f
            break
    if not log_file:
        return events
    for line in _read_new_log_lines(log_file, state):
        install_match = re.search(r'Install: ([\w.+-]+):.*? \((.*?)\)', line)
        if install_match:
            pkg_name = install_match.group(1).split(':')[0]
            events.append(_create_event('PACKAGE_CHANGE', f"Package '{pkg_name}' installed (version {install_match.group(2)})"))
            continue
        upgrade_match = re.search(r'Upgrade: ([\w.+-]+):.*? \((.*?)\), ([\w.+-]+):.*? \((.*?)\)', line)
        if upgrade_match:
            pkg_name = upgrade_match.group(1).split(':')[0]
            events.append(_create_event('PACKAGE_CHANGE', f"Package '{pkg_name}' upgraded to '{upgrade_match.group(4)}'"))
            continue
        dnf_match = re.search(r'^(?:Install|Upgrade|Installed|Upgraded): ([\w-]+)-([0-9].*)', line)
        if dnf_match:
            summary = f"Package '{dnf_match.group(1)}' was installed or upgraded to version '{dnf_match.group(2)}'"
            if not any(e['summary'].startswith(f"Package '{dnf_match.group(1)}'") for e in events):
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
        for line in _read_new_log_lines(log_file, state):
            if any(keyword in line.lower() for keyword in keywords):
                summary = (line[:250] + '...') if len(line) > 253 else line
                events.append(_create_event(event_type, summary))
    return events

def get_windows_events(state):
    """Uses PowerShell to get new Windows Events (for structured event stream)."""
    events = []
    log_name = "Security"
    event_id = 4624
    state_key = f"win_event_{log_name}_{event_id}_last_id"
    last_record_id = state.get(state_key, 0)
    ps_command = f'Get-WinEvent -LogName {log_name} -FilterXPath "*[System[EventID={event_id} and EventRecordID > {last_record_id}]]" | Select-Object TimeCreated, Message, RecordId | Sort-Object RecordId | ConvertTo-Json'
    try:
        result = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True, check=True, timeout=20)
        win_events = json.loads(result.stdout.strip())
        if not isinstance(win_events, list):
            win_events = [win_events]
        max_id = last_record_id
        for win_event in win_events:
            summary_match = re.search(r'Account Name:\s+([\w\-$]+)', win_event['Message'])
            summary = f"User '{summary_match.group(1)}' logged on." if summary_match else "A user successfully logged on."
            events.append(_create_event('USER_LOGIN', summary))
            if win_event['RecordId'] > max_id:
                max_id = win_event['RecordId']
        state[state_key] = max_id
    except Exception as e:
        print(f"WARN: Could not execute PowerShell command for {log_name} log. Error: {e}")
    return events

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
    if all_events:
        print(f"--> Collected {len(all_events)} new events.")
    return all_events

# --- Metrics Collection ---

def collect_all_metrics():
    """Gathers all enhanced system metrics."""
    global last_net_io, last_time
    print("--> Collecting metrics...")
    psutil.cpu_percent(interval=0.1)
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_percent = psutil.virtual_memory().percent
    disks = []
    for part in psutil.disk_partitions(all=False):
        if 'loop' in part.device or any(fs in part.fstype for fs in ['tmpfs', 'squashfs']):
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({"device": part.device, "mountpoint": part.mountpoint, "percent": usage.percent})
        except Exception:
            continue
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    top_procs = sorted(procs, key=lambda p: (p.get('cpu_percent', 0) or 0, p.get('memory_percent', 0) or 0), reverse=True)
    current_net_io = psutil.net_io_counters()
    current_time = time.time()
    elapsed_time = current_time - last_time
    if elapsed_time <= 0:
        net_rate = {"bytes_sent_per_sec": 0, "bytes_recv_per_sec": 0}
    else:
        bytes_sent_rate = (current_net_io.bytes_sent - last_net_io.bytes_sent) / elapsed_time
        bytes_recv_rate = (current_net_io.bytes_recv - last_net_io.bytes_recv) / elapsed_time
        net_rate = {"bytes_sent_per_sec": int(bytes_sent_rate), "bytes_recv_per_sec": int(bytes_recv_rate)}
    last_net_io = current_net_io
    last_time = current_time
    metrics = {"cpu_percent": cpu_percent, "memory_percent": memory_percent, "disks": disks, "processes": top_procs[:10], "network": net_rate}
    print("--> Metrics collection complete.")
    return metrics

# --- Core Agent Logic ---

def load_config():
    """Loads agent configuration from the config file."""
    config = {}
    if not os.path.exists(CONFIG_FILE_PATH):
        raise FileNotFoundError(f"FATAL: Config file not found at '{CONFIG_FILE_PATH}'")
    with open(CONFIG_FILE_PATH, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                config[key.strip()] = value.strip()
    return config

def get_service_account_credentials(key_path, target_audience):
    """Creates credentials that can be used to invoke a secured service."""
    try:
        return service_account.IDTokenCredentials.from_service_account_file(key_path, target_audience=target_audience)
    except Exception as e:
        raise Exception(f"FATAL: Could not create service account credentials. Error: {e}")

# --- Main Execution Loop ---
if __name__ == "__main__":
    print("Starting NoirNote Full State Agent...")
    try:
        config = load_config()
        credentials = get_service_account_credentials(KEY_FILE_PATH, config['INGEST_FUNCTION_URL'])
    except Exception as e:
        print(e)
        exit(1)
        
    print(f"Agent configured for server_id: {config.get('SERVER_ID', 'UNKNOWN')} "
          f"workspace_id: {config.get('WORKSPACE_ID', 'UNKNOWN')}")
    
    state = load_state()
    authed_session = google.auth.transport.requests.Request()

    while True:
        try:
            metrics = collect_all_metrics()
            events = collect_events(state)
            state_snapshot = collect_state_snapshot()  # <<< NEW FUNCTION CALL

            payload = {
                "user_id": config['USER_ID'],
                "workspace_id": config.get('WORKSPACE_ID', config['USER_ID']),
                "server_id": config['SERVER_ID'],
                "metrics": metrics,
                "events": events,
                "state": state_snapshot  # <<< NEW DATA STRUCTURE
            }
            
            credentials.refresh(authed_session)
            headers = {'Authorization': f'Bearer {credentials.token}', 'Content-Type': 'application/json'}
            
            print(f"Pushing full payload to {config['INGEST_FUNCTION_URL']}...")
            # Uncomment for deep debugging of the entire payload:
            # print(json.dumps(payload, indent=2))
            
            response = requests.post(config['INGEST_FUNCTION_URL'], json=payload, headers=headers, timeout=30)
            
            response.raise_for_status()
            print(f"Successfully pushed payload. Status: {response.status_code}")

            save_state(state)

        except requests.exceptions.RequestException as e:
            print(f"ERROR: Network error while pushing payload: {e}")
        except Exception as e:
            print(f"ERROR: An unhandled exception occurred in the main loop: {e}")
            traceback.print_exc()
        
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
    echo "WORKSPACE_ID=$USER_ID" >> "$CONFIG_FILE_PATH"
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
Description=NoirNote Full State Agent
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