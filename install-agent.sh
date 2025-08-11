#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

echo "--- NoirNote Agent Installer (Multi-OS v10 with Fluent Bit & Repo Fallback) ---"

# --- Global Variables ---
AGENT_USER="noirnote-agent"
AGENT_DIR="/opt/noirnote-agent"
CONFIG_DIR="/etc/noirnote"
STATE_DIR="/var/lib/noirnote-agent"
AGENT_SERVICE_FILE="/etc/systemd/system/noirnote-agent.service"
AGENT_SCRIPT_PATH="${AGENT_DIR}/noirnote_agent.py"
KEY_FILE_PATH="${CONFIG_DIR}/agent-key.json"
CONFIG_FILE_PATH="${CONFIG_DIR}/agent.conf"
USER_INTEGRATIONS_CONFIG_PATH="/etc/noirnote/integrations.conf"

# Fluent Bit configuration paths
FLUENTBIT_CONF_DIR="/etc/fluent-bit/conf.d"
NOIRNOTE_FLUENTBIT_CONF="${FLUENTBIT_CONF_DIR}/noirnote.conf"
NOIRNOTE_CUSTOM_FLUENTBIT_CONF="${FLUENTBIT_CONF_DIR}/noirnote-custom.conf"
NOIRNOTE_PARSERS_CONF="/etc/fluent-bit/noirnote-parsers.conf"

# The URLs for the cloud functions
CLAIM_URL="https://europe-west3-noirnote.cloudfunctions.net/claimAgentToken"
INGEST_URL="https://chronos.noirnote.it/ingest"

# Variable to hold the detected OS family
OS_FAMILY=""

# --- Helper and OS-Specific Functions ---

function check_root() {
    if [ "$EUID" -ne 0 ]; then
      echo "Error: This installer must be run with sudo or as root."
      exit 1
    fi
}

function detect_os() {
    echo "--> [1/8] Detecting operating system..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" || "$ID" == "debian" || "$ID_LIKE" == "debian" ]]; then
            OS_FAMILY="debian"
        elif [[ "$ID" == "centos" || "$ID" == "rhel" || "$ID" == "fedora" || "$ID_LIKE" == "rhel fedora" ]]; then
            OS_FAMILY="rhel"
        else
            echo "Error: Unsupported Linux distribution: $ID"
            exit 1
        fi
        echo "    - Detected OS Family: $OS_FAMILY"
    else
        echo "Error: Cannot detect operating system. /etc/os-release not found."
        exit 1
    fi
}

function install_dependencies() {
    echo "--> [2/8] Installing dependencies for $OS_FAMILY..."
    case "$OS_FAMILY" in
        "debian")
            apt-get update -y > /dev/null
            apt-get install -y curl gpg lsb-release > /dev/null
            
            # --- START: ROBUST REPOSITORY SETUP ---
            CODENAME=$(lsb_release -cs)
            # Fallback for non-LTS or very new versions like 'oracular'
            case "$CODENAME" in
              noble|jammy) # Supported LTS versions
                REPO_CODENAME="$CODENAME"
                ;;
              *)
                echo "    - Warning: Unsupported codename '$CODENAME'. Falling back to 'noble' (Ubuntu 24.04 LTS) for Fluent Bit repository."
                REPO_CODENAME="noble"
                ;;
            esac
            
            curl -s https://packages.fluentbit.io/fluentbit.key | gpg --dearmor > /usr/share/keyrings/fluentbit-key.gpg
            echo "deb [signed-by=/usr/share/keyrings/fluentbit-key.gpg] https://packages.fluentbit.io/ubuntu/${REPO_CODENAME} ${REPO_CODENAME} main" > /etc/apt/sources.list.d/fluent-bit.list
            # --- END: ROBUST REPOSITORY SETUP ---

            apt-get update -y > /dev/null
            apt-get install -y python3 python3-pip python3-venv net-tools fluent-bit > /dev/null
            ;;
        "rhel")
            PKG_MANAGER=$(command -v dnf || command -v yum)
            $PKG_MANAGER makecache > /dev/null
            tee /etc/yum.repos.d/fluent-bit.repo > /dev/null <<'YUM_REPO_EOF'
[fluent-bit]
name = Fluent Bit
baseurl = https://packages.fluentbit.io/centos/8/$basearch/
gpgcheck=1
gpgkey=https://packages.fluentbit.io/fluentbit.key
enabled=1
YUM_REPO_EOF
            $PKG_MANAGER install -y python3 python3-pip curl net-tools fluent-bit > /dev/null
            ;;
    esac
    pip3 install --break-system-packages psutil==5.9.8 requests==2.32.3 google-auth==2.28.2 > /dev/null
    echo "    - Dependencies installed."
}

function setup_agent_user_and_dirs() {
    echo "--> [3/8] Setting up user and directories..."
    if ! id -u "$AGENT_USER" >/dev/null 2>&1; then
        useradd --system --shell /usr/sbin/nologin "$AGENT_USER"
        echo "    - Created system user '$AGENT_USER'"
    else
        echo "    - System user '$AGENT_USER' already exists."
    fi

    usermod -a -G adm,systemd-journal ${AGENT_USER}
    echo "    - Granted '$AGENT_USER' read access to system logs."
    
    mkdir -p "$AGENT_DIR" "$CONFIG_DIR" "$STATE_DIR"
    chown -R "$AGENT_USER":"$AGENT_USER" "$AGENT_DIR" "$CONFIG_DIR" "$STATE_DIR"
    chmod 750 "$AGENT_DIR" "$CONFIG_DIR" "$STATE_DIR"
}

function configure_fluent_bit() {
    echo "--> [4/8] Configuring Fluent Bit for structured log collection..."

    tee "/etc/fluent-bit/fluent-bit.conf" > /dev/null <<'FLUENTBIT_MAIN_EOF'
[SERVICE]
    Flush           5
    Daemon          Off
    Log_Level       info
    Parsers_File    noirnote-parsers.conf
    @INCLUDE        conf.d/*.conf
FLUENTBIT_MAIN_EOF

    mkdir -p "$FLUENTBIT_CONF_DIR"

    tee "$NOIRNOTE_FLUENTBIT_CONF" > /dev/null <<'FLUENTBIT_NOIRNOTE_EOF'
[INPUT]
    Name            systemd
    Tag             noirnote.host.*
    Systemd_Filter  _SYSTEMD_UNIT
[INPUT]
    Name            tail
    Tag             noirnote.nginx.error
    Path            /var/log/nginx/error.log*
    Parser          nginx_error
    Multiline.parser  docker, cri
[INPUT]
    Name            tail
    Tag             noirnote.apache.error
    Path            /var/log/apache2/error.log*
    Multiline.parser  docker, cri
[INPUT]
    Name            tail
    Tag             noirnote.httpd.error
    Path            /var/log/httpd/error_log*
    Multiline.parser  docker, cri
[INPUT]
    Name            tail
    Tag             noirnote.postgres.log
    Path            /var/log/postgresql/*.log
    Parser          postgres_log
[OUTPUT]
    Name            file
    Match           noirnote.*
    Path            /var/lib/noirnote-agent/structured_logs.json
    Format          json_lines
FLUENTBIT_NOIRNOTE_EOF

    tee "$NOIRNOTE_PARSERS_CONF" > /dev/null <<'FLUENTBIT_PARSERS_EOF'
[PARSER]
    Name   nginx_error
    Format regex
    Regex  ^(?<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?<level>\w+)\] (?<pid>\d+#\d+): (?<tid>\*\d+)?(?<message>.*)$
[PARSER]
    Name   postgres_log
    Format regex
    Regex  ^(?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d+ \w+)\s\[(?<pid>\d+)\]\s(?<message>.*)$
FLUENTBIT_PARSERS_EOF

    echo "    - Fluent Bit configured for multi-OS log paths."
}

function configure_custom_integrations() {
    echo "--> [5/8] Configuring Custom Integrations..."
    if [ ! -f "$USER_INTEGRATIONS_CONFIG_PATH" ]; then
        echo "    - No custom integrations file found at '$USER_INTEGRATIONS_CONFIG_PATH'. Skipping."
        touch "$NOIRNOTE_CUSTOM_FLUENTBIT_CONF"
        return
    fi
    
    echo "    - Found custom integrations file. Generating Fluent Bit config..."
    
    awk '
        BEGIN { printing = 0 }
        /^\[logs\]$/ { printing = 1; next }
        /^\[.*\]$/ { printing = 0 }
        printing && /=/ { print }
    ' "$USER_INTEGRATIONS_CONFIG_PATH" | while IFS='=' read -r name path; do
        name=$(echo "$name" | xargs)
        path=$(echo "$path" | xargs)
        
        if [ -n "$name" ] && [ -n "$path" ]; then
            echo "    - Adding custom log: '$name' at '$path'"
            tee -a "$NOIRNOTE_CUSTOM_FLUENTBIT_CONF" > /dev/null <<EOF
[INPUT]
    Name            tail
    Tag             noirnote.custom.${name}
    Path            ${path}
    Multiline.parser  docker, cri

EOF
        fi
    done

    if [ ! -s "$NOIRNOTE_CUSTOM_FLUENTBIT_CONF" ]; then
        echo "    - No valid log entries found in '$USER_INTEGRATIONS_CONFIG_PATH'."
    else
        echo "    - Custom Fluent Bit configuration created at '$NOIRNOTE_CUSTOM_FLUENTBIT_CONF'."
    fi
}

function create_agent_script() {
    echo "--> [6/8] Creating agent script at ${AGENT_SCRIPT_PATH}..."
    tee "$AGENT_SCRIPT_PATH" > /dev/null <<'AGENT_EOF'
# agent/noirnote_agent.py (Multi-OS v9 with restored features)
import psutil, requests, json, time, os, traceback, re, platform, subprocess, glob
from datetime import datetime, timezone
from google.oauth2 import service_account
import google.auth.transport.requests
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CONFIG_FILE_PATH = "/etc/noirnote/agent.conf"
KEY_FILE_PATH = "/etc/noirnote/agent-key.json"
STATE_FILE_PATH = "/var/lib/noirnote-agent/state.json"
STRUCTURED_LOG_PATH = "/var/lib/noirnote-agent/structured_logs.json"
USER_INTEGRATIONS_CONFIG_PATH = "/etc/noirnote/integrations.conf"

last_net_io, last_disk_io, last_time = psutil.net_io_counters(), psutil.disk_io_counters(), time.time()

INTEGRATION_KNOWLEDGE_MAP = {
    "nginx": {"config_paths": ["/etc/nginx/nginx.conf"], "version_command": "nginx -v", "pid_path": "/var/run/nginx.pid"},
    "postgres": {"config_paths": ["/etc/postgresql/*/main/postgresql.conf"], "version_command": "psql --version", "pid_path": "/var/run/postgresql/*.pid"},
    "httpd": {"config_paths": ["/etc/httpd/conf/httpd.conf"], "version_command": "httpd -v", "pid_path": "/var/run/httpd/httpd.pid"},
    "apache2": {"config_paths": ["/etc/apache2/apache2.conf"], "version_command": "apache2 -v", "pid_path": "/var/run/apache2/apache2.pid"},
    "mysqld": {"config_paths": ["/etc/mysql/my.cnf", "/etc/my.cnf"], "version_command": "mysql --version", "pid_path": "/var/run/mysqld/mysqld.pid"},
    "redis-server": {"config_paths": ["/etc/redis/redis.conf"], "version_command": "redis-server --version", "pid_path": "/var/run/redis/redis-server.pid"}
}

def encrypt_payload(plaintext_bytes: bytes, key: bytes) -> (str, str):
    """
    Encrypts a plaintext byte string using AES-GCM, returning base64-encoded
    ciphertext+tag and nonce, matching the Go backend's expected format.
    """
    try:
        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce # This is 12 bytes by default for PyCryptodome's GCM
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        
        # The Go service expects the tag appended to the ciphertext.
        combined_ciphertext = ciphertext + tag
        
        # Return base64 encoded strings
        return (
            base64.b64encode(combined_ciphertext).decode('utf-8'),
            base64.b64encode(nonce).decode('utf-8')
        )
    except Exception as e:
        print(f"FATAL: Encryption failed: {e}")
        traceback.print_exc()
        raise

def load_state():
    if not os.path.exists(STATE_FILE_PATH): return {}
    try:
        with open(STATE_FILE_PATH, 'r') as f: return json.load(f)
    except (json.JSONDecodeError, IOError, PermissionError): return {}

def save_state(state):
    try:
        with open(STATE_FILE_PATH, 'w') as f: json.dump(state, f, indent=2)
    except (IOError, PermissionError): pass

def load_user_integrations():
    empty_integrations = {"logs": [], "configs": []}
    if not os.path.exists(USER_INTEGRATIONS_CONFIG_PATH): return empty_integrations
    integrations = {"logs": [], "configs": []}
    try:
        with open(USER_INTEGRATIONS_CONFIG_PATH, 'r') as f:
            current_section = None
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1].lower()
                    continue
                if current_section and '=' in line:
                    key, value = line.split('=', 1)
                    if current_section in integrations:
                        integrations[current_section].append({"name": key.strip(), "path": value.strip()})
    except (IOError, PermissionError): return empty_integrations
    return integrations

def _run_command(command):
    try:
        return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=20, check=False).stdout.strip()
    except Exception: return ""

def _read_pid_from_file(pid_path_pattern):
    try:
        pid_files = glob.glob(pid_path_pattern)
        if not pid_files: return None
        with open(pid_files[0], 'r') as f: return int(f.read().strip())
    except (IOError, PermissionError, ValueError, IndexError): return None

def get_structured_dmesg():
    output = _run_command("dmesg -T")
    pattern = re.compile(r'\[\s*([^\]]+)\]\s*(.*)')
    return [{"timestamp": m.group(1).strip(), "message": m.group(2).strip()} for line in output.splitlines() if (m := pattern.match(line))]

def get_ss_listeners():
    output = _run_command("ss -tulpn")
    listeners = []
    for line in output.splitlines()[1:]:
        try:
            parts = line.split()
            match = re.search(r'users:\(\("([^"]+)",pid=(\d+),', parts[-1])
            proc_name, pid = (match.group(1), int(match.group(2))) if match else (None, None)
            listeners.append({"protocol": parts[0], "state": parts[1], "local_address": parts[4], "process_name": proc_name, "pid": pid})
        except (IndexError, ValueError): continue
    return listeners

def get_version_info(command):
    raw = _run_command(command)
    match = re.search(r'(\d+\.\d+\.\d+)', raw)
    return {"version": match.group(1) if match else None, "raw": raw}

def collect_state_snapshot(discovered_services: list):
    snapshot = { 'dmesg_events': get_structured_dmesg(), 'network_listeners': get_ss_listeners(), 'versions': {}, 'configs': {} }
    for service in discovered_services:
        k = INTEGRATION_KNOWLEDGE_MAP.get(service, {})
        if k.get("version_command"): snapshot['versions'][service] = get_version_info(k["version_command"])
        pid = _read_pid_from_file(k["pid_path"]) if k.get("pid_path") else None
        
        config_content = "Config path not found or not readable."
        if "config_paths" in k:
            for path_pattern in k["config_paths"]:
                for path in glob.glob(path_pattern):
                    try:
                        with open(path, 'r', errors='ignore') as f: config_content = f.read()
                        break
                    except (IOError, PermissionError, FileNotFoundError): continue
                if "not found" not in config_content: break
        snapshot['configs'][service] = {"pid": pid, "content": config_content}

    user_integrations = load_user_integrations()
    for custom_config in user_integrations.get("configs", []):
        content = f"File not found or not readable at {custom_config['path']}"
        try:
            with open(custom_config['path'], 'r', errors='ignore') as f: content = f.read()
        except (IOError, PermissionError) as e: content = f"Error reading {custom_config['path']}: {e}"
        snapshot['configs'][custom_config['name']] = {"pid": None, "content": content}

    return snapshot

def _read_new_lines_from_file(path, state):
    lines, key = [], f"log_{path}"
    if not os.path.exists(path): return lines
    try:
        inode = os.stat(path).st_ino
        log_state = state.get(key, {})
        offset = log_state.get('offset', 0) if log_state.get('inode') == inode else 0
        with open(path, 'rb') as f:
            f.seek(offset)
            lines = [line.decode('utf-8', 'ignore').strip() for line in f.readlines()]
            state[key] = {'inode': inode, 'offset': f.tell()}
    except (IOError, PermissionError, FileNotFoundError): pass
    return lines

def collect_events(state):
    return [json.loads(line) for line in _read_new_lines_from_file(STRUCTURED_LOG_PATH, state) if line]

def collect_all_metrics():
    global last_net_io, last_disk_io, last_time
    now, elapsed = time.time(), 1.0
    if now > last_time: elapsed = now - last_time
    net, disk = psutil.net_io_counters(), psutil.disk_io_counters()
    
    procs, services = [], set()
    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            info = p.info
            procs.append(info)
            if info['name'] in INTEGRATION_KNOWLEDGE_MAP: services.add(info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied): continue

    tcp_states = {"ESTABLISHED": 0, "TIME_WAIT": 0, "CLOSE_WAIT": 0}
    try:
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status in tcp_states: tcp_states[conn.status] += 1
    except psutil.AccessDenied: pass

    metrics = {
        "cpu_states": psutil.cpu_times_percent()._asdict(),
        "memory_details": psutil.virtual_memory()._asdict(),
        "disk_io": {"reads_per_sec": (disk.read_count - last_disk_io.read_count) / elapsed, "writes_per_sec": (disk.write_count - last_disk_io.write_count) / elapsed},
        "disks": [{"device": p.device, "mountpoint": p.mountpoint, "percent": psutil.disk_usage(p.mountpoint).percent} for p in psutil.disk_partitions(all=False) if 'loop' not in p.device],
        "network": {"sent_per_sec": (net.bytes_sent - last_net_io.bytes_sent) / elapsed, "recv_per_sec": (net.bytes_recv - last_net_io.bytes_recv) / elapsed, "tcp_connections": tcp_states},
        "processes": sorted(procs, key=lambda p: (p.get('cpu_percent', 0) or 0), reverse=True)[:15],
    }
    last_net_io, last_disk_io, last_time = net, disk, now
    return metrics, list(services)

def main():
    print("Starting NoirNote Agent v10 (E2EE Edition)...")
    config = {k.strip(): v.strip() for line in open(CONFIG_FILE_PATH) if '=' in line for k, v in [line.strip().split('=', 1)]}
    
    chronos_key_b64 = config.get('CHRONOS_ENCRYPTION_KEY')
    if not chronos_key_b64:
        print("FATAL: CHRONOS_ENCRYPTION_KEY not found in config. Agent cannot run.")
        return
    try:
        chronos_key = base64.b64decode(chronos_key_b64)
        if len(chronos_key) != 32: raise ValueError("Decoded key is not 32 bytes.")
    except Exception as e:
        print(f"FATAL: Could not decode CHRONOS_ENCRYPTION_KEY: {e}"); return

    creds = service_account.IDTokenCredentials.from_service_account_file(KEY_FILE_PATH, target_audience=config['INGEST_FUNCTION_URL'])
    state = load_state()
    session = google.auth.transport.requests.Request()
    while True:
        try:
            metrics, services = collect_all_metrics()
            
            data_to_encrypt = { "metrics": metrics, "events": collect_events(state), "state": collect_state_snapshot(services) }
            plaintext_json_bytes = json.dumps(data_to_encrypt).encode('utf-8')
            
            encrypted_payload_b64, nonce_b64 = encrypt_payload(plaintext_json_bytes, chronos_key)
            
            payload = {
                "user_id": config['USER_ID'],
                "workspace_id": config.get('WORKSPACE_ID', config['USER_ID']),
                "server_id": config['SERVER_ID'],
                "encrypted_payload_b64": encrypted_payload_b64,
                "nonce_b64": nonce_b64,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

            creds.refresh(session)
            headers = {'Authorization': f'Bearer {creds.token}', 'Content-Type': 'application/json'}
            resp = requests.post(config['INGEST_FUNCTION_URL'], json=payload, headers=headers, timeout=30)
            resp.raise_for_status()
            print(f"Successfully pushed ENCRYPTED payload. Status: {resp.status_code}")
            save_state(state)
        except Exception as e:
            print(f"ERROR: An unhandled exception occurred in the main loop: {e}")
            traceback.print_exc()
        time.sleep(int(config.get('INTERVAL_SECONDS', 60)))

if __name__ == "__main__":
    main()
AGENT_EOF
    chown "$AGENT_USER":"$AGENT_USER" "$AGENT_SCRIPT_PATH"
    chmod 750 "$AGENT_SCRIPT_PATH"
}

function configure_agent() {
    echo "--> [7/8] Configuring agent..."
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
    CHRONOS_KEY=$(echo "$RESPONSE_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('chronosKey', ''))")
    
    if [ -z "$SERVICE_ACCOUNT_KEY_JSON" ] || [ -z "$USER_ID" ] || [ -z "$SERVER_ID" ] || [ -z "$CHRONOS_KEY" ]; then
        echo "    [ERROR] Claim response was incomplete."; exit 1
    fi
    
    echo "$SERVICE_ACCOUNT_KEY_JSON" > "$KEY_FILE_PATH"
    chown "$AGENT_USER":"$AGENT_USER" "$KEY_FILE_PATH"
    chmod 400 "$KEY_FILE_PATH"

    tee "$CONFIG_FILE_PATH" > /dev/null <<EOF
SERVER_ID=$SERVER_ID
USER_ID=$USER_ID
WORKSPACE_ID=$USER_ID
INGEST_FUNCTION_URL=$INGEST_URL
INTERVAL_SECONDS=60
CHRONOS_ENCRYPTION_KEY=$CHRONOS_KEY
EOF
    chown "$AGENT_USER":"$AGENT_USER" "$CONFIG_FILE_PATH"
    chmod 640 "$CONFIG_FILE_PATH"
    echo "    - Configuration saved for server: '$SERVER_ID'."
}

function setup_service() {
    echo "--> [8/8] Setting up and starting systemd services..."
    tee "$AGENT_SERVICE_FILE" > /dev/null <<'SERVICE_EOF'
[Unit]
Description=NoirNote Structured Data Agent
After=network-online.target fluent-bit.service
Wants=network-online.target fluent-bit.service

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
    systemctl enable fluent-bit.service || echo "Warning: Could not enable fluent-bit service."
    systemctl restart fluent-bit.service || echo "Warning: Could not restart fluent-bit service."
    systemctl enable noirnote-agent.service
    systemctl restart noirnote-agent.service
    
    echo ""
    echo "--- Installation Complete! ---"
    echo "The NoirNote agent and Fluent Bit are now running."
    echo "To check agent status:      systemctl status noirnote-agent.service"
    echo "To check fluent-bit status: systemctl status fluent-bit.service"
    echo "To view live agent logs:    journalctl -u noirnote-agent.service -f"
}

# --- Main Execution ---
main() {
    check_root
    detect_os
    install_dependencies
    setup_agent_user_and_dirs
    configure_fluent_bit
    configure_custom_integrations
    create_agent_script
    configure_agent "$@"
    setup_service
}

main "$@"
Next Steps