#!/bin/bash

# Get the current remote and URL
remote=$(git remote)
url=$(git remote get-url "$remote")

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
    local hostname=$(hostname)
    local username=$(whoami)
    local remote=$(git remote)
    local url=$(git remote get-url "$remote")
    local payload=$(jq -n \
        --arg timestamp "$timestamp" \
        --arg hostname "$hostname" \
        --arg username "$username" \
        --arg repository "$url" \
        --arg git_remote "$remote" \
        '{timestamp: $timestamp, hostname: $hostname, username: $username, repository: $repository, git_remote: $git_remote}'
    )
    echo "$timestamp - BLOCKED: User $username on $hostname attempted to push to non-zeptonow repository: $url" >> "$LOG_FILE"
    echo "$payload" > "$HOME/.git/hooks/last_payload.json"
    logger -p auth.warning "Git Push Security Alert: User $username on $hostname tried to push to non-zeptonow repository: $url"
    
    # Send the notification silently
    curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$REMOTE_LOGGING_URL" > /dev/null 2>&1 &
}

# Check if pushing to any non-zeptonow repository
# This specifically checks for "zeptonow" in the URL (not just "zepto")
if [[ $url != *"zeptonow"* ]]; then
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

exit 0
