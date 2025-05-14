#!/bin/bash

# Get the current remote and URL
remote="$1"
url="$2"

# Log file and remote logging URL
LOG_FILE="$HOME/.git/hooks/push_attempts.log"
REMOTE_LOGGING_URL="https://viy7077zbe.execute-api.ap-south-1.amazonaws.com/prod/log"

# Function to log and notify
log_and_notify() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local hostname=$(hostname)
    local username=$(whoami)
    
    # Create simplified JSON payload with only required details
    local payload="{\"timestamp\":\"$timestamp\",\"hostname\":\"$hostname\",\"username\":\"$username\",\"repository\":\"$url\",\"git_remote\":\"$remote\"}"
    
    # Log locally - avoid sudo, use $HOME which is always writable by the user
    echo "$timestamp - BLOCKED: User $username on $hostname attempted to push to non-zeptonow repository: $url" >> "$LOG_FILE"
    
    # System log (syslog) - native to macOS
    logger -p auth.warning "Git Push Security Alert: User $username on $hostname tried to push to non-zeptonow repository: $url"
    
    # Send to remote logging service - runs in background to not delay the user
    (curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$REMOTE_LOGGING_URL" &) 2>/dev/null
}

# Check if pushing to any non-zeptonow repository
# This specifically checks for "zeptonow" in the URL (not just "zepto")
if [[ $url != *"zeptonow"* ]]; then
    # Standard terminal colors that work on all macOS versions
    echo ""
    echo "ERROR: Pushing to non-zeptonow repositories is not allowed"
    echo "This action has been logged and reported to the security team."
    echo "For assistance, please contact security@zeptonow.com or Slack channel #security"
    echo ""
    
    # Log the attempt and notify
    log_and_notify
    
    exit 1
fi

exit 0
