#!/bin/bash

# Function to safely get the primary remote URL
get_primary_remote_url() {
    # First try origin as it's the most common default
    if git remote get-url origin >/dev/null 2>&1; then
        echo $(git remote get-url origin)
        return 0
    fi
    
    # If origin doesn't exist, get the first remote
    local first_remote=$(git remote | head -1)
    if [ -n "$first_remote" ]; then
        echo $(git remote get-url "$first_remote")
        return 0
    fi
    
    # No remotes found
    echo "No remote configured"
    return 1
}

# Get the primary remote URL
url=$(get_primary_remote_url)
if [ $? -ne 0 ]; then
    echo "ERROR: No git remote found. Cannot verify repository."
    exit 1
fi

# Get primary remote name
primary_remote=$(git remote | head -1)

# Log file and remote logging URL
LOG_FILE="$HOME/.git/hooks/push_attempts.log"
REMOTE_LOGGING_URL="https://viy7077zbe.execute-api.ap-south-1.amazonaws.com/prod/log"

# Define colors using simpler ANSI color codes that are more widely compatible
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
PURPLE='\033[35m'
CYAN='\033[36m'
WHITE='\033[37m'
NC='\033[0m' # No Color

log_and_notify() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local hostname=$(hostname 2>/dev/null || echo "unknown")
    local username=$(whoami 2>/dev/null || echo "unknown")
    
    # Function to properly escape JSON strings
    json_escape() {
        # Escape backslashes first, then quotes, then handle special characters
        echo "$1" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed 's/\t/\\t/g' | sed 's/\n/\\n/g' | sed 's/\r/\\r/g'
    }
    
    # Create JSON payload using native tools with proper escaping
    local escaped_timestamp=$(json_escape "$timestamp")
    local escaped_hostname=$(json_escape "$hostname")
    local escaped_username=$(json_escape "$username")
    local escaped_url=$(json_escape "$url")
    local escaped_remote=$(json_escape "$primary_remote")
    
    local payload="{"
    payload+="\"timestamp\":\"$escaped_timestamp\","
    payload+="\"hostname\":\"$escaped_hostname\","
    payload+="\"username\":\"$escaped_username\","
    payload+="\"repository\":\"$escaped_url\","
    payload+="\"git_remote\":\"$escaped_remote\""
    payload+="}"
    
    # Make sure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"
    
    echo "$timestamp - BLOCKED: User $username on $hostname attempted to push to non-zeptonow repository: $url" >> "$LOG_FILE"
    echo "$payload" > "$HOME/.git/hooks/last_payload.json"
    
    # Use logger only if it exists
    if command -v logger >/dev/null 2>&1; then
        logger -p auth.warning "Git Push Security Alert: User $username on $hostname tried to push to non-zeptonow repository: $url"
    fi
    
    # Send the notification silently
    curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$REMOTE_LOGGING_URL" > /dev/null 2>&1 &
}

# Check all remotes for compliance
check_all_remotes() {
    local has_valid_remote=false
    
    for remote in $(git remote); do
        local remote_url=""
        if remote_url=$(git remote get-url "$remote" 2>/dev/null); then
            if [[ "$remote_url" == *"zeptonow"* ]]; then
                has_valid_remote=true
            fi
        fi
    done
    
    if [ "$has_valid_remote" = false ]; then
        return 1
    fi
    
    return 0
}

# Check if any remote is a zeptonow repository
# This specifically checks for "zeptonow" in the URL (not just "zepto")
if [[ "$url" != *"zeptonow"* ]] && ! check_all_remotes; then
    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                  SECURITY ALERT                            ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}ERROR: Pushing to non-zeptonow repositories is not allowed${NC}"
    echo -e "${YELLOW}This action has been logged and reported to the security team.${NC}"
    echo -e "For assistance, please contact ${CYAN}security@zeptonow.com${NC} or Slack channel ${CYAN}#security${NC}"
    echo ""
    
    # Log the attempt and notify
    log_and_notify
    
    exit 1
fi

# Debug info that can be enabled if needed
# echo "Verified repository: $url is a valid zeptonow repository"

exit 0
