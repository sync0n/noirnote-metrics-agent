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

    # --- START OF FIX: This entire block is now correctly indented ---
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
    # --- END OF FIX ---