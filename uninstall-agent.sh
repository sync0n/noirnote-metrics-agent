Of course. Here is the complete and updated uninstall-agent.sh script.

The primary change is the addition of a command to remove the new state directory (/var/lib/noirnote-agent), ensuring no files are left behind after uninstallation.

code
Bash
download
content_copy
expand_less

#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

echo "--- NoirNote Agent Uninstaller ---"

# --- Configuration (Must match the installer) ---
AGENT_USER="noirnote-agent"
AGENT_DIR="/opt/noirnote-agent"
CONFIG_DIR="/etc/noirnote"
STATE_DIR="/var/lib/noirnote-agent" # <-- NEW: State directory to remove
AGENT_SERVICE_FILE="/etc/systemd/system/noirnote-agent.service"
PYTHON_PACKAGES="psutil requests google-auth"

# --- Helper Functions ---
function check_root() {
    if [ "$EUID" -ne 0 ]; then
      echo "Error: This uninstaller must be run with sudo or as root."
      exit 1
    fi
}

function stop_and_disable_service() {
    echo "--> [1/5] Stopping and disabling the systemd service..."
    if systemctl is-active --quiet noirnote-agent.service; then
        systemctl stop noirnote-agent.service
        echo "    - Service stopped."
    else
        echo "    - Service was not running."
    fi

    if systemctl is-enabled --quiet noirnote-agent.service; then
        systemctl disable noirnote-agent.service
        echo "    - Service disabled."
    else
        echo "    - Service was not enabled."
    fi
}

function remove_agent_files() {
    echo "--> [2/5] Removing agent files and directories..."
    
    # Remove the service file
    if [ -f "$AGENT_SERVICE_FILE" ]; then
        rm -f "$AGENT_SERVICE_FILE"
        echo "    - Removed systemd service file: $AGENT_SERVICE_FILE"
        # Tell systemd to re-read its configuration
        systemctl daemon-reload
        echo "    - Reloaded systemd daemon."
    else
        echo "    - Service file not found (already removed)."
    fi

    # Remove the agent's main directory
    if [ -d "$AGENT_DIR" ]; then
        rm -rf "$AGENT_DIR"
        echo "    - Removed agent directory: $AGENT_DIR"
    else
        echo "    - Agent directory not found (already removed)."
    fi

    # Remove the agent's configuration directory
    if [ -d "$CONFIG_DIR" ]; then
        rm -rf "$CONFIG_DIR"
        echo "    - Removed configuration directory: $CONFIG_DIR"
    else
        echo "    - Configuration directory not found (already removed)."
    fi

    # Remove the agent's state directory
    if [ -d "$STATE_DIR" ]; then
        rm -rf "$STATE_DIR"
        echo "    - Removed agent state directory: $STATE_DIR"
    else
        echo "    - Agent state directory not found (already removed)."
    fi
}

function remove_agent_user() {
    echo "--> [3/5] Removing agent user..."
    if id -u "$AGENT_USER" >/dev/null 2>&1; then
        # The `userdel` command automatically removes the user from any groups.
        userdel "$AGENT_USER"
        echo "    - Removed system user '$AGENT_USER'."
    else
        echo "    - System user '$AGENT_USER' not found (already removed)."
    fi
}

function uninstall_python_deps() {
    echo "--> [4/5] Uninstalling Python dependencies..."
    if command -v pip3 &> /dev/null; then
        # The -y flag confirms the uninstallation without a prompt
        pip3 uninstall -y $PYTHON_PACKAGES > /dev/null 2>&1
        echo "    - Uninstalled Python packages: $PYTHON_PACKAGES"
    else
        echo "    - pip3 not found, skipping Python package uninstallation."
    fi
    echo "    - Note: System-level packages like python3, curl, etc., are not removed."
}

function final_summary() {
    echo ""
    echo "--- Uninstallation Complete! ---"
    echo "The NoirNote agent and all its components have been removed."
    echo "You may want to run 'sudo apt-get autoremove' to clean up any other unused dependencies."
}

# --- Main Execution ---
check_root
stop_and_disable_service
remove_agent_files
remove_agent_user
uninstall_python_deps
final_summary