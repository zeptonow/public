#!/bin/bash

# Get the current remote and URL
remote=$(git remote)
url=$(git remote get-url "$remote")


# Log file and remote logging URL
LOG_FILE="$HOME/.git/hooks/push_attempts.log"
REMOTE_LOGGING_URL="https://viy7077zbe.execute-api.ap-south-1.amazonaws.com/prod/log"

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
