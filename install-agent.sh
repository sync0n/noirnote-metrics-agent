Of course. Here is the complete install-agent.sh script with all the requested modifications. The changes are confined to the embedded noirnote_agent.py script as specified, ensuring the agent can now monitor user-defined logs and configuration files.

code
Bash
download
content_copy
expand_less

#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

echo "--- NoirNote Agent Installer (Context-Aware v6) ---"

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
    apt-get install -y python3 python3-pip python3-venv curl net-tools > /dev/null
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
import glob
from datetime import datetime
from google.oauth2 import service_account
import google.auth.transport.requests

# --- Configuration ---
CONFIG_FILE_PATH = "/etc/noirnote/agent.conf"
KEY_FILE_PATH = "/etc/noirnote/agent-key.json"
STATE_FILE_PATH = "/var/lib/noirnote-agent/state.json"
# Task 1: Define the Optional Configuration Path
USER_INTEGRATIONS_CONFIG_PATH = "/etc/noirnote/integrations.conf"

# --- State for calculating rates ---
last_net_io = psutil.net_io_counters()
last_disk_io = psutil.disk_io_counters()
last_time = time.time()

INTEGRATION_KNOWLEDGE_MAP = {
    "nginx": {
        "log_paths": ["/var/log/nginx/error.log*", "/var/log/nginx/error.log"],
        "config_paths": ["/etc/nginx/nginx.conf"],
        "version_command": "nginx -v",
        "pid_path": "/var/run/nginx.pid"
    },
    "postgres": {
        "log_paths": ["/var/log/postgresql/postgresql-*.log"],
        "config_paths": ["/etc/postgresql/*/main/postgresql.conf"],
        "version_command": "psql --version",
        "pid_path": "/var/run/postgresql/*.pid" # Varies by version
    },
    "httpd": {
        "log_paths": ["/var/log/httpd/error_log"],
        "config_paths": ["/etc/httpd/conf/httpd.conf"],
        "version_command": "httpd -v",
        "pid_path": "/var/run/httpd/httpd.pid"
    },
    "apache2": {
        "log_paths": ["/var/log/apache2/error.log"],
        "config_paths": ["/etc/apache2/apache2.conf"],
        "version_command": "apache2 -v",
        "pid_path": "/var/run/apache2/apache2.pid"
    },
    "mysqld": {
        "log_paths": ["/var/log/mysql/error.log", "/var/log/mysqld.log"],
        "config_paths": ["/etc/mysql/my.cnf", "/etc/my.cnf"],
        "version_command": "mysql --version",
        "pid_path": "/var/run/mysqld/mysqld.pid"
    },
    "redis-server": {
        "log_paths": ["/var/log/redis/redis-server.log"],
        "config_paths": ["/etc/redis/redis.conf"],
        "version_command": "redis-server --version",
        "pid_path": "/var/run/redis/redis-server.pid"
    }
}


# --- State Management Functions ---
def load_state():
    if not os.path.exists(STATE_FILE_PATH): return {}
    try:
        with open(STATE_FILE_PATH, 'r') as f: return json.load(f)
    except (json.JSONDecodeError, IOError, PermissionError) as e:
        print(f"WARN: Could not load state from {STATE_FILE_PATH}, starting fresh. Error: {e}")
        return {}

def save_state(state):
    try:
        with open(STATE_FILE_PATH, 'w') as f: json.dump(state, f, indent=2)
    except (IOError, PermissionError) as e:
        print(f"ERROR: Could not save state to {STATE_FILE_PATH}: {e}")

# Task 2: Implement the Configuration Loader
def load_user_integrations():
    """
    Loads custom log and config paths from an optional user-defined file.
    The file format is a simple .ini style with [logs] and [configs] sections.
    """
    empty_integrations = {"logs": [], "configs": []}
    
    if not os.path.exists(USER_INTEGRATIONS_CONFIG_PATH):
        return empty_integrations

    integrations = {"logs": [], "configs": []}
    try:
        with open(USER_INTEGRATIONS_CONFIG_PATH, 'r') as f:
            current_section = None
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1].lower()
                    continue

                if current_section and '=' in line:
                    key, value = line.split('=', 1)
                    name = key.strip()
                    path = value.strip()
                    
                    if not name or not path:
                        print(f"WARN: Skipping malformed entry in {USER_INTEGRATIONS_CONFIG_PATH}: {line}")
                        continue
                    
                    if current_section in integrations:
                        integrations[current_section].append({"name": name, "path": path})

    except (IOError, PermissionError) as e:
        print(f"WARN: Could not read user integrations file at {USER_INTEGRATIONS_CONFIG_PATH}. Error: {e}")
        return empty_integrations

    return integrations

# --- Helper Functions ---
def _run_command(command):
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=20, check=False
        )
        if result.returncode != 0:
            error_output = (result.stdout.strip() + " " + result.stderr.strip()).strip()
            return f"Error executing command '{command}': [Exit Code {result.returncode}] {error_output}"
        return result.stdout.strip()
    except Exception as e:
        return f"An unexpected error occurred while running '{command}': {e}"

def get_dmesg_output():
    return _run_command("dmesg -T")

def get_netstat_output():
    return _run_command("netstat -tulnp")

def get_syslog_snippet():
    if os.path.exists('/bin/journalctl'):
        return _run_command("journalctl -n 200 --no-pager")
    elif os.path.exists('/var/log/syslog'):
        return _run_command("tail -n 200 /var/log/syslog")
    return "Neither journalctl nor /var/log/syslog found."

def get_log_snippet(path):
    if os.path.exists(path):
        return _run_command(f"tail -n 200 {path}")
    return ""

def _read_pid_from_file(pid_path_pattern):
    """Safely reads a PID from a file, handling globs and errors."""
    try:
        # Use glob to find the actual PID file path
        pid_files = glob.glob(pid_path_pattern)
        if not pid_files:
            return None
        with open(pid_files[0], 'r') as f:
            return int(f.read().strip())
    except (IOError, PermissionError, ValueError, IndexError):
        return None

# --- State Snapshot Collection ---
def collect_state_snapshot(discovered_services: list):
    """Orchestrates the collection of a comprehensive, correlated state snapshot."""
    print("--> Collecting state snapshot...")
    snapshot = {}
    system = platform.system()

    if system == "Linux":
        snapshot['dmesg'] = get_dmesg_output()
        snapshot['netstat'] = get_netstat_output()
        snapshot['syslog_snippet'] = get_syslog_snippet()
        snapshot['messages_log_snippet'] = get_log_snippet('/var/log/messages')
        snapshot['kern_log_snippet'] = get_log_snippet('/var/log/kern.log')
        snapshot['auth_log_snippet'] = get_log_snippet('/var/log/auth.log') or get_log_snippet('/var/log/secure')
        
        snapshot['versions'] = {}
        snapshot['configs'] = {}

        # Snapshot auto-discovered services
        print(f"--> Snapshotting discovered services: {discovered_services}")
        for service in discovered_services:
            knowledge = INTEGRATION_KNOWLEDGE_MAP.get(service, {})
            
            if knowledge.get("version_command"):
                snapshot['versions'][service] = _run_command(knowledge["version_command"])
            
            pid = None
            if knowledge.get("pid_path"):
                pid = _read_pid_from_file(knowledge["pid_path"])

            config_content = "Config path not found or not readable."
            for config_pattern in knowledge.get("config_paths", []):
                for config_path in glob.glob(config_pattern):
                    try:
                        with open(config_path, 'r', errors='ignore') as f:
                            config_content = f.read()
                        break
                    except (IOError, PermissionError) as e:
                        config_content = f"Error reading {config_path}: {e}"
                        break
                if "Error" not in config_content and "not found" not in config_content:
                    break
            
            snapshot['configs'][service] = {"pid": pid, "content": config_content}

        # Task 4: Integrate User Config into State Snapshot Collection
        user_integrations = load_user_integrations()
        user_configs = user_integrations.get("configs", [])
        if user_configs:
            print(f"--> Snapshotting user-defined configurations...")
            for custom_config in user_configs:
                content = f"File not found or not readable at {custom_config['path']}"
                try:
                    with open(custom_config['path'], 'r', errors='ignore') as f:
                        content = f.read()
                except (IOError, PermissionError) as e:
                    content = f"Error reading {custom_config['path']}: {e}"
                
                # Add to snapshot using user-defined name as key
                snapshot['configs'][custom_config['name']] = {"pid": None, "content": content}

    print("--> State snapshot collection complete.")
    return snapshot

# --- Event Collection ---
def _read_new_log_lines(log_path, state):
    new_lines = []
    if not os.path.exists(log_path) or not os.path.isfile(log_path): return new_lines
    try:
        current_inode = os.stat(log_path).st_ino
    except (FileNotFoundError, PermissionError): return new_lines
    
    log_state_key = f"log_{log_path}"
    log_state = state.get(log_state_key, {})
    last_inode, last_offset = log_state.get('inode'), log_state.get('offset', 0)
    if current_inode != last_inode: last_offset = 0

    try:
        with open(log_path, 'rb') as f:
            f.seek(last_offset)
            new_lines = [line.decode('utf-8', 'ignore').strip() for line in f.readlines()]
            state[log_state_key] = {'inode': current_inode, 'offset': f.tell()}
    except (IOError, PermissionError): pass
    return new_lines

def _create_event(event_type, summary, pid=None):
    """Standardizes event creation, now with optional PID."""
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "summary": summary
    }
    if pid:
        try:
            event["pid"] = int(pid)
        except (ValueError, TypeError):
            pass # Ignore if PID is not a valid integer
    return event

def parse_auth_log(state):
    events = []
    log_file = '/var/log/auth.log' if os.path.exists('/var/log/auth.log') else '/var/log/secure'
    patterns = {
        'USER_LOGIN': re.compile(r'sshd(?:\[(\d+)\])?:\s*session opened for user (\w+)'),
        'FAILED_LOGIN': re.compile(r'sshd(?:\[(\d+)\])?:\s*Failed password for.*?(\w+) from ([\d.]+)')
    }
    for line in _read_new_log_lines(log_file, state):
        for event_type, pattern in patterns.items():
            match = pattern.search(line)
            if match:
                pid = match.group(1)
                if event_type == 'USER_LOGIN':
                    summary = f"User '{match.group(2)}' logged in via SSH"
                    events.append(_create_event(event_type, summary, pid))
                elif event_type == 'FAILED_LOGIN':
                    summary = f"Failed password for '{match.group(2)}' from {match.group(3)}"
                    events.append(_create_event(event_type, summary, pid))
    return events

def parse_syslog_and_kern(state):
    events = []
    log_files = ['/var/log/syslog', '/var/log/messages', '/var/log/kern.log']
    line_pattern = re.compile(r'\S+\s+\d+\s+\S+\s+([\w\d\._-]+)(?:\[(\d+)\])?:\s*(.*)')
    
    for log_file in log_files:
        for line in _read_new_log_lines(log_file, state):
            match = line_pattern.search(line)
            pid, message = (match.group(2), match.group(3)) if match else (None, line)
            
            if "oom-killer" in message.lower() or "out of memory" in message.lower():
                summary = (message[:250] + '...') if len(message) > 253 else message
                events.append(_create_event('OOM_KILLER_INVOKED', summary, pid))
                continue

            keywords = ['error', 'failed', 'fatal', 'segfault', 'panic', 'critical']
            if any(keyword in message.lower() for keyword in keywords):
                event_type = 'KERNEL_ERROR' if 'kern.log' in log_file else 'SYSTEM_ERROR'
                summary = (message[:250] + '...') if len(message) > 253 else message
                events.append(_create_event(event_type, summary, pid))
    return events

def check_systemd_failures(state):
    """Checks for services in a failed state using systemctl."""
    events = []
    command_output = _run_command("systemctl --failed --no-legend --plain")
    if not command_output or command_output.startswith("Error"):
        return events

    state_key = "reported_systemd_failures"
    if state_key not in state:
        state[state_key] = []
        
    current_failed_services = {line.split()[0] for line in command_output.strip().splitlines()}
    newly_failed_services = current_failed_services - set(state[state_key])

    for service_name in newly_failed_services:
        summary = f"[systemd] Service '{service_name}' entered failed state."
        events.append(_create_event('SERVICE_FAILURE', summary))
        state[state_key].append(service_name)

    state[state_key] = [s for s in state[state_key] if s in current_failed_services]
    
    return events

def collect_events(state, discovered_services: list):
    """Gathers all system and application events from various sources."""
    all_events = []
    print("--> Collecting events...")
    system = platform.system()
    if system == "Linux":
        all_events.extend(parse_auth_log(state))
        all_events.extend(parse_syslog_and_kern(state))
        all_events.extend(check_systemd_failures(state))
        
        # Collect from auto-discovered services
        print(f"--> Checking logs for discovered services: {discovered_services}")
        for service in discovered_services:
            knowledge = INTEGRATION_KNOWLEDGE_MAP.get(service, {})
            for log_pattern in knowledge.get("log_paths", []):
                for log_path in glob.glob(log_pattern):
                    for line in _read_new_log_lines(log_path, state):
                        summary = f"[{service}] {line}"
                        summary = (summary[:250] + '...') if len(summary) > 253 else summary
                        all_events.append(_create_event('APPLICATION_LOG', summary))

        # Task 3: Integrate User Config into Event Collection
        user_integrations = load_user_integrations()
        user_logs = user_integrations.get("logs", [])
        if user_logs:
            print(f"--> Checking logs for user-defined integrations...")
            for custom_log in user_logs:
                for line in _read_new_log_lines(custom_log['path'], state):
                    summary = f"[{custom_log['name']}] {line}"
                    summary = (summary[:250] + '...') if len(summary) > 253 else summary
                    all_events.append(_create_event('APPLICATION_LOG', summary))

    if all_events:
        print(f"--> Collected {len(all_events)} new events.")
    return all_events

# --- Metrics Collection ---
def collect_all_metrics() -> (dict, list):
    """Gathers granular system metrics and discovers running services."""
    global last_net_io, last_disk_io, last_time
    print("--> Collecting granular metrics and discovering services...")
    
    cpu_times = psutil.cpu_times_percent(interval=1, percpu=False)
    cpu_states = {
        "user": cpu_times.user,
        "system": cpu_times.system,
        "idle": cpu_times.idle,
        "iowait": cpu_times.iowait
    }

    vmem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    memory_details = {
        "total": vmem.total,
        "available": vmem.available,
        "used": vmem.used,
        "cached": getattr(vmem, 'cached', 0),
        "buffers": getattr(vmem, 'buffers', 0),
        "swap_used_percent": swap.percent
    }
    
    current_time = time.time()
    elapsed_time = current_time - last_time
    if elapsed_time <= 0: elapsed_time = 1
    
    current_disk_io = psutil.disk_io_counters()
    disk_io = {
        "read_ops_per_sec": (current_disk_io.read_count - last_disk_io.read_count) / elapsed_time,
        "write_ops_per_sec": (current_disk_io.write_count - last_disk_io.write_count) / elapsed_time
    }
    
    current_net_io = psutil.net_io_counters()
    net_rate = {
        "bytes_sent_per_sec": (current_net_io.bytes_sent - last_net_io.bytes_sent) / elapsed_time,
        "bytes_recv_per_sec": (current_net_io.bytes_recv - last_net_io.bytes_recv) / elapsed_time
    }
    
    tcp_states = {"ESTABLISHED": 0, "TIME_WAIT": 0, "CLOSE_WAIT": 0}
    try:
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status in tcp_states:
                tcp_states[conn.status] += 1
    except psutil.AccessDenied:
        print("WARN: Access denied for net_connections, TCP states will be empty.")

    net_rate["tcp_connections"] = tcp_states
    
    last_disk_io = current_disk_io
    last_net_io = current_net_io
    last_time = current_time

    procs, discovered_services = [], set()
    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            p_info = p.info
            procs.append(p_info)
            if p_info['name'] in INTEGRATION_KNOWLEDGE_MAP:
                discovered_services.add(p_info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied): continue
    top_procs = sorted(procs, key=lambda p: (p.get('cpu_percent', 0) or 0), reverse=True)
    
    metrics = {
        "cpu_states": cpu_states,
        "memory_details": memory_details,
        "disk_io": disk_io,
        "disks": [{"device": p.device, "mountpoint": p.mountpoint, "percent": psutil.disk_usage(p.mountpoint).percent} for p in psutil.disk_partitions(all=False) if 'loop' not in p.device],
        "processes": top_procs[:15],
        "network": net_rate
    }
    
    print(f"--> Metrics collection complete. Discovered services: {list(discovered_services)}")
    return metrics, list(discovered_services)

# --- Core Agent Logic ---
def load_config():
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
    try:
        return service_account.IDTokenCredentials.from_service_account_file(key_path, target_audience=target_audience)
    except Exception as e:
        raise Exception(f"FATAL: Could not create service account credentials. Error: {e}")

# --- Main Execution Loop ---
if __name__ == "__main__":
    print("Starting NoirNote Context-Aware Agent...")
    try:
        config = load_config()
        credentials = get_service_account_credentials(KEY_FILE_PATH, config['INGEST_FUNCTION_URL'])
    except Exception as e:
        print(e); exit(1)
        
    print(f"Agent configured for server_id: {config.get('SERVER_ID', 'UNKNOWN')}")
    state = load_state()
    authed_session = google.auth.transport.requests.Request()

    while True:
        try:
            metrics, discovered_services = collect_all_metrics()
            events = collect_events(state, discovered_services)
            state_snapshot = collect_state_snapshot(discovered_services)

            payload = {
                "user_id": config['USER_ID'],
                "workspace_id": config.get('WORKSPACE_ID', config['USER_ID']),
                "server_id": config['SERVER_ID'],
                "metrics": metrics,
                "events": events,
                "state": state_snapshot
            }
            
            credentials.refresh(authed_session)
            headers = {'Authorization': f'Bearer {credentials.token}', 'Content-Type': 'application/json'}
            
            print(f"Pushing full payload to {config['INGEST_FUNCTION_URL']}...")
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
        if [[ $arg == --token=* ]]; then TOKEN="${arg#*=}"; shift; fi
    done

    if [ -f "$CONFIG_FILE_PATH" ] && [ -f "$KEY_FILE_PATH" ] && [ -z "$TOKEN" ]; then
        echo "    - Configuration files already exist. Skipping."
        return
    fi
    if [ -z "$TOKEN" ]; then
        echo "    [ERROR] --token flag is required for initial configuration."; exit 1
    fi

    echo "    - Claiming credentials..."
    RESPONSE_JSON=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"token\": \"$TOKEN\"}" "$CLAIM_URL")

    if ! echo "$RESPONSE_JSON" | grep -q "private_key"; then
        echo "    [ERROR] Failed to claim agent credentials. Response: $RESPONSE_JSON"; exit 1
    fi

    SERVICE_ACCOUNT_KEY_JSON=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin).get('serviceAccountKey'), indent=2))")
    USER_ID=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('userId', ''))")
    SERVER_ID=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('serverId', ''))")
    
    if [ -z "$SERVICE_ACCOUNT_KEY_JSON" ] || [ -z "$USER_ID" ] || [ -z "$SERVER_ID" ]; then
        echo "    [ERROR] Claim response was incomplete."; exit 1
    fi
    
    echo "    - Credentials claimed for server: '$SERVER_ID'"

    echo "$SERVICE_ACCOUNT_KEY_JSON" > "$KEY_FILE_PATH"
    chown "$AGENT_USER":"$AGENT_USER" "$KEY_FILE_PATH"
    chmod 400 "$KEY_FILE_PATH"

    echo "SERVER_ID=$SERVER_ID" > "$CONFIG_FILE_PATH"
    echo "USER_ID=$USER_ID" >> "$CONFIG_FILE_PATH"
    echo "WORKSPACE_ID=$USER_ID" >> "$CONFIG_FILE_PATH"
    echo "INGEST_FUNCTION_URL=$INGEST_URL" >> "$CONFIG_FILE_PATH"
    echo "INTERVAL_SECONDS=60" >> "$CONFIG_FILE_PATH"
    chown "$AGENT_USER":"$AGENT_USER" "$CONFIG_FILE_PATH"
    chmod 640 "$CONFIG_FILE_PATH"
    echo "    - Configuration saved."
}

function setup_service() {
    echo "--> [5/5] Setting up and starting systemd service..."
    tee "$AGENT_SERVICE_FILE" > /dev/null <<'SERVICE_EOF'
[Unit]
Description=NoirNote Context-Aware Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=noirnote-agent
Group=noirnote-agent
SupplementaryGroups=adm systemd-journal
ExecStart=/usr/bin/python3 -u /opt/noirnote-agent/noirnote_agent.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE_EOF
    
    systemctl daemon-reload
    systemctl enable noirnote-agent.service
    systemctl restart noirnote-agent.service
    
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