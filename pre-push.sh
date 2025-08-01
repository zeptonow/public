#!/bin/bash
#
# Git Pre-Push Hook
#
# This script performs two primary security checks before allowing a push:
# 1. Repository Validation: Ensures pushes are only made to approved 'zeptonow' repositories
#    on GitHub or GitLab. It blocks pushes to any other remote and displays an alert.
# 2. Secret Detection: Scans the commits being pushed for secrets using 'gitleaks'.
#    If secrets are found, the push is blocked, a report is displayed, and the event is logged.
#
# --- Failsafe Design ---
# This script is designed to "fail open". If the script itself encounters an
# unexpected error (e.g., a command fails, a dependency is missing), it will
# immediately and silently exit with a success code (0), allowing the push
# to proceed. This ensures that a broken hook does not block developer workflow.
# Deliberate security blocks (invalid repo, secrets found) will still exit
# with a failure code (1) to block the push as intended.

# The main logic is wrapped in a function.
main() {
    # Exit immediately if a command exits with a non-zero status.
    set -e

    # --- Configuration ---
    readonly REMOTE_NAME="$1"
    readonly REMOTE_URL="$2"
    readonly LOG_FILE="$HOME/.git/hooks/push_attempts.log"
    readonly REMOTE_LOGGING_URL="https://viy7077zbe.execute-api.ap-south-1.amazonaws.com/prod/log"
    # New endpoint for logging blocked secrets
    readonly SECRET_LOGGING_URL="https://security.zepto.co.in/Secret/logblocked"
    readonly RED='\033[31m'
    readonly GREEN='\033[32m'
    readonly YELLOW='\033[33m'
    readonly BLUE='\033[34m'
    readonly PURPLE='\033[35m'
    readonly CYAN='\033[36m'
    readonly WHITE='\033[37m'
    readonly NC='\033[0m' # No Color

    # --- Initial Checks ---
    if [ -z "$REMOTE_URL" ]; then exit 0; fi
    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then exit 0; fi

    # --- Helper Functions ---
    is_valid_zeptonow_repo() {
        local url="$1"
        url="${url%.git}"
        if [[ "$url" == git@* ]]; then
            local domain_and_path="${url#git@}"
            local domain="${domain_and_path%%:*}"
            local path="${domain_and_path#*:}"
            url="https://$domain/$path"
        fi
        [[ "$url" == *"github.com/zeptonow/"* ]] || [[ "$url" == *"gitlab.com/zeptonow/"* ]]
    }

    json_escape() {
        echo "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\n/\\n/g' -e 's/\r/\\r/g'
    }

    log_and_notify() {
        local remote_name="$1"
        local remote_url="$2"
        local timestamp; timestamp=$(date +"%Y-%m-%d %H:%M:%S")
        local hostname; hostname=$(hostname 2>/dev/null || echo "unknown_host")
        local username; username=$(whoami 2>/dev/null || echo "unknown_user")
        local payload; payload=$(cat <<EOF
{
  "timestamp": "$(json_escape "$timestamp")",
  "hostname": "$(json_escape "$hostname")",
  "username": "$(json_escape "$username")",
  "repository": "$(json_escape "$remote_url")",
  "git_remote": "$(json_escape "$remote_name")"
}
EOF
)
        mkdir -p "$(dirname "$LOG_FILE")"
        echo "$timestamp - BLOCKED: User '$username' on '$hostname' attempted to push to a non-zeptonow repository: $remote_url" >> "$LOG_FILE"
        if command -v logger >/dev/null 2>&1; then
            logger -p auth.warning "Git Push Blocked: User '$username' attempted to push to non-zeptonow repo: $remote_url"
        fi
        curl -s -X POST \
          -H "Content-Type: application/json" \
          -d "$payload" "$REMOTE_LOGGING_URL" \
          --connect-timeout 5 --max-time 10 > /dev/null 2>&1 &
    }

    # New function to log blocked secret events
    log_blocked_secrets() {
        local report_file="$1"
        local remote_url="$2"

        # Gather required information
        local user; user=$(whoami 2>/dev/null || echo "unknown_user")
        
        # Use jq to create a JSON array of the detected secrets
        local secrets_array; secrets_array=$(jq 'group_by(.Commit + .File + .RuleID) | map({type: (.[0].RuleID // "N/A"),  commit: (.[0].Commit // "N/A")})' "$report_file")

        # If jq fails or produces no output, exit gracefully
        if [ -z "$secrets_array" ] || [ "$secrets_array" == "[]" ]; then
            return
        fi
        
        # Construct the final JSON payload
        local final_payload; final_payload=$(cat <<EOF
{
  "user": "$(json_escape "$user")",
  "repository": "$(json_escape "$remote_url")",
  "blocked_secrets": $secrets_array
}
EOF
)

        # Send the log to the security endpoint in the background
        curl -s -X POST \
          -H "Content-Type: application/json" \
          -d "$final_payload" "$SECRET_LOGGING_URL" \
          --connect-timeout 5 --max-time 10 > /dev/null 2>&1 &
    }


    # --- Check 1: Repository Validation ---
    if ! is_valid_zeptonow_repo "$REMOTE_URL"; then
        echo "" >&2
        echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}" >&2
        echo -e "${RED}║                     SECURITY ALERT                         ║${NC}" >&2
        echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}" >&2
        echo -e "\n${RED}ERROR: Pushing to non-zeptonow repositories is not allowed${NC}" >&2
        echo -e "${YELLOW}This action has been logged and reported to the security team.${NC}" >&2
        echo -e "For assistance, please contact ${CYAN}security@zeptonow.com${NC} or Slack channel ${CYAN}#security${NC}\n" >&2
        log_and_notify "$REMOTE_NAME" "$REMOTE_URL"
        exit 1
    fi

    # --- Check 2: Secret Scanning with gitleaks ---
    check_for_secrets() {
        if ! command -v gitleaks >/dev/null 2>&1; then return 0; fi
        
        # Check for jq, the only dependency for parsing the report.
        if ! command -v jq >/dev/null 2>&1; then
            echo -e "${YELLOW}Warning: 'jq' is not installed. It is required to parse the gitleaks report. Please connect with Security team if it fails.${NC}" >&2
            # Check if Homebrew is installed before trying to use it.
            if command -v brew >/dev/null 2>&1; then
                echo -e "${CYAN}Attempting to install jq using Homebrew...${NC}" >&2
                if brew install jq; then
                    echo -e "${GREEN}jq installed successfully.${NC}" >&2
                else
                    echo -e "${RED}ERROR: Failed to install jq automatically.${NC}" >&2
                    echo -e "${YELLOW}Please install jq manually ('brew install jq') and try again.${NC}" >&2
                    return 1 # Return failure to block the push
                fi
            else
                echo -e "${RED}ERROR: Homebrew is not installed.${NC}" >&2
                echo -e "${YELLOW}Please install jq manually and try again.${NC}" >&2
                return 1 # Return failure to block the push
            fi
        fi

        local temp_report; temp_report=$(mktemp)
        trap 'rm -f "$temp_report"' EXIT
        local secrets_found_in_push=false
        
        while read -r local_ref local_sha remote_ref remote_sha; do
            if [[ "$local_sha" =~ ^0+$ ]]; then continue; fi
            
            # Clear report for each ref
            > "$temp_report"
            
            local log_opts
            if [[ "$remote_sha" =~ ^0+$ ]]; then
                # For new branches, only scan commits not already on any remote branch
                log_opts="$local_sha --not --remotes"
            else
                # For existing branches, scan only the new commits
                log_opts="$remote_sha..$local_sha"
            fi
            
            # Debug output (enable with DEBUG_HOOK=1)
            if [ "${DEBUG_HOOK:-}" = "1" ]; then
                local commit_count; commit_count=$(git log --oneline $log_opts 2>/dev/null | wc -l)
                echo "DEBUG: Scanning ref $local_ref: $commit_count commits" >&2
                echo "DEBUG: Range: $log_opts" >&2
            fi
            
            if ! gitleaks detect --source="." --log-opts="$log_opts" --report-format="json" --report-path="$temp_report" --redact=60 >/dev/null 2>&1; then
                if [ -s "$temp_report" ]; then
                    secrets_found_in_push=true
                    break
                fi
            fi
        done
        
        if [ "$secrets_found_in_push" = true ]; then
            # ADDED: Log the event to the new security endpoint
            log_blocked_secrets "$temp_report" "$REMOTE_URL"
            # Display the report to the user
            display_secrets_report "$temp_report"
            return 1 # Return failure
        fi
        
        return 0
    }

    display_secrets_report() {
        local report_file="$1"
        echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}" >&2
        echo -e "${RED}║${YELLOW}               HARDCODED SECRETS DETECTED                      ${RED}║${NC}" >&2
        echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}" >&2
        echo -e "\n${YELLOW}⚠️  Your push has been blocked because secrets were found in your commits.${NC}" >&2
        echo -e "   Please remove them from your commits/history and try again. ${WHITE}For help, contact the ${CYAN}#security${WHITE} team.${NC}\n" >&2

        local current_commit=""
        jq -r 'group_by(.Commit + .File + .RuleID + .Secret) | map({Commit: .[0].Commit, File: .[0].File, RuleID: .[0].RuleID, Secret: .[0].Secret, Lines: ([.[].StartLine] | sort | unique | map(tostring) | join(", "))}) | sort_by(.Commit) | .[] | "\(.Commit // "N/A")\t\(.File // "N/A")\t\(.RuleID // "N/A")\t\(.Secret // "N/A")\t\(.Lines // "N/A")"' "$report_file" | while IFS=$'\t' read -r commit file rule secret lines; do
            if [ "$commit" != "$current_commit" ]; then
                local subject; subject=$(git log -1 --pretty=%s "$commit" 2>/dev/null || echo "Unknown Subject")
                echo -e "\n${BLUE}📝 Commit: $commit (${subject})${NC}" >&2
                current_commit="$commit"
            fi
            echo -e "  ${CYAN}File:  $file${NC}" >&2
            echo -e "  ${GREEN}Lines: $lines${NC}" >&2
            echo -e "  ${PURPLE}Type:  $rule${NC}" >&2
            echo -e "  ${YELLOW}Secret:$secret${NC}" >&2
            echo "" >&2
        done
        echo "" >&2
    }

    # --- Execute Checks ---
    if ! check_for_secrets; then
        exit 1
    fi
    exit 0
}

# --- Failsafe Execution ---
main "$@" || exit 0
