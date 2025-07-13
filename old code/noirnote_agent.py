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
         # Skip temporary or virtual filesystems
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
            continue # Ignore errors for unreadable partitions
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
    
    # Update state for next calculation
    last_net_io = current_net_io
    last_time = current_time
    
    return {
        "bytes_sent_per_sec": int(bytes_sent_rate),
        "bytes_recv_per_sec": int(bytes_recv_rate)
    }

def collect_all_metrics():
    """Gathers all enhanced system metrics."""
    print("--> Collecting metrics...")
    # A small initial sleep to allow cpu_percent to get a baseline
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
        # The target_audience is the URL of our Chronos service
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
        
        # Wait for the next interval
        time.sleep(int(config.get('INTERVAL_SECONDS', 60)))