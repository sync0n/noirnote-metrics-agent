# agent/noirnote_agent.py (DEBUGGING VERSION)
import psutil
import requests
import json
import time
import os
import traceback
from datetime import datetime
from google.oauth2 import service_account
import google.auth.transport.requests

# --- Constants ---
CONFIG_FILE_PATH = "/etc/noirnote/agent.conf"
KEY_FILE_PATH = "/etc/noirnote/agent-key.json"
LOG_FILE_PATH = "/tmp/noirnote_agent.log" # <--- NEW DEBUG LOG

# --- Debug Logging Helper ---
def log_debug(message):
    """Writes a timestamped message to the debug log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    with open(LOG_FILE_PATH, 'a') as f:
        f.write(f"[{timestamp}] {message}\n")

# --- Functions ---
def load_config():
    """Loads agent configuration from the config file."""
    log_debug("Attempting to load config...")
    config = {}
    try:
        with open(CONFIG_FILE_PATH, 'r') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    config[key.strip()] = value.strip()
        log_debug(f"Config loaded successfully: {config}")
        return config
    except FileNotFoundError:
        log_debug(f"FATAL: Configuration file not found at {CONFIG_FILE_PATH}")
        raise
    except Exception as e:
        log_debug(f"FATAL: Error reading configuration file: {e}")
        raise

def get_credentials(key_path, target_audience):
    """Creates and returns ID token credentials from a service account key."""
    log_debug("Attempting to get credentials...")
    try:
        creds = service_account.IDTokenCredentials.from_service_account_file(
            key_path,
            target_audience=target_audience
        )
        log_debug("Credentials object created successfully.")
        return creds
    except FileNotFoundError:
        log_debug(f"FATAL: Service account key file not found at '{key_path}'.")
        raise
    except Exception as e:
        log_debug(f"FATAL: Could not create credentials from key file. Error: {e}")
        raise

def collect_metrics():
    """Gathers system metrics using psutil."""
    log_debug("Collecting metrics...")
    metrics = {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent
    }
    log_debug(f"Metrics collected: {metrics}")
    return metrics

def main():
    """Main function to initialize and run the agent's loop."""
    log_debug("--- Agent main() function entered ---")
    try:
        config = load_config()
        credentials = get_credentials(KEY_FILE_PATH, config['INGEST_FUNCTION_URL'])
        http_session = requests.Session()
        log_debug("Initialization successful.")
    except Exception as e:
        log_debug(f"Initialization failed with exception: {e}. Exiting.")
        exit(1)
        
    log_debug(f"Agent configured for server_id: {config['SERVER_ID']}")
    
    log_debug("Entering main while True loop...")
    while True:
        try:
            log_debug("Top of main loop.")
            metrics = collect_metrics()
            payload = {
                "server_id": config['SERVER_ID'],
                "metrics": metrics
            }
            
            log_debug("Refreshing auth token...")
            auth_req = google.auth.transport.requests.Request(session=http_session)
            credentials.refresh(auth_req)
            log_debug("Auth token refreshed.")

            headers = {
                'Authorization': f'Bearer {credentials.token}',
                'Content-Type': 'application/json'
            }
            
            log_debug(f"Making POST request to {config['INGEST_FUNCTION_URL']} with payload: {json.dumps(payload)}")
            
            response = http_session.post(
                config['INGEST_FUNCTION_URL'], 
                json=payload, 
                headers=headers, 
                timeout=15
            )
            
            response.raise_for_status()
            log_debug(f"Request successful. Status: {response.status_code}")

        except Exception as e:
            log_debug(f"ERROR: An error occurred in the main loop: {e}")
            log_debug(traceback.format_exc())
        
        sleep_interval = int(config.get('INTERVAL_SECONDS', 60))
        log_debug(f"Sleeping for {sleep_interval} seconds...")
        time.sleep(sleep_interval)

# --- Script Entry Point ---
if __name__ == "__main__":
    # Clear the log file on each start for a clean slate
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)
    log_debug("--- NoirNote Metrics Agent Script Started ---")
    main()
    log_debug("--- SCRIPT IS EXITING UNEXPECTEDLY ---") # This line should never be reached