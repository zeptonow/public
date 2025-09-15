#!/bin/bash
#
# Git Pre-Push Hook (v11 - Log Routing)
#
# This script performs security checks before allowing a git push:
# 1. Repository Validation: BLOCKS pushes to non-'zeptonow' repositories.
# 2. Secret Detection: BLOCKS pushes if 'gitleaks' finds secrets.
# 3. Dependency Scanning: If dependency files were changed, WARNS with a
#    colorized, concise summary if 'trivy' finds vulnerabilities.

# --- Main Orchestration Logic ---
main() {
    # --- Configuration ---
    export TERM=xterm-256color

    readonly REMOTE_NAME="$1"
    readonly REMOTE_URL="$2"
    readonly HOOKS_DIR="$HOME/.git/hooks"
    readonly ERROR_LOG_FILE="$HOOKS_DIR/pre-push-errors.log"
    
    # --- Logging URLs ---
    # The ORIGINAL endpoint for "non-zeptonow" alerts ONLY.
    readonly NON_ZEPTONOW_LOGGING_URL="https://viy7077zbe.execute-api.ap-south-1.amazonaws.com/prod/log"
    # The NEW endpoint for all other script/tool errors.
    readonly SCRIPT_ERROR_LOGGING_URL="https://5cvr3xxsh1.execute-api.ap-south-1.amazonaws.com/prod" # <-- REPLACE WITH YOUR NEW REST API URL
    
    readonly SECRET_LOGGING_URL="https://security.zepto.co.in/Secret/logblocked"
    readonly SOP_URL="https://zeptonow.atlassian.net/wiki/spaces/Engineerin/pages/617021497/SOP+Removing+Hardcoded+Secrets+from+Your+Git+Commits"
    
    
    # Terminal Colors
    readonly RED='\033[31m'
    readonly GREEN='\033[32m'
    readonly YELLOW='\033[33m'
    readonly BLUE='\033[34m'
    readonly PURPLE='\033[35m'
    readonly CYAN='\033[36m'
    readonly WHITE='\033[37m'
    readonly NC='\033[0m'

    # --- Initial Sanity Checks ---
    if [[ -z "$REMOTE_URL" ]] || ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        exit 0
    fi
    mkdir -p "$HOOKS_DIR"

    # Capture stdin ONCE to be shared by all functions
    local readonly STDIN_REFS=$(cat)
    if [ -z "$STDIN_REFS" ]; then exit 0; fi

    # Dependency Auto-Installation
    install_if_missing "jq" "gitleaks" "trivy"


    # Check 1: Repository Validation
    if ! check_repo_validity; then
        exit 1
    fi

    local gitleaks_report_file; gitleaks_report_file=$(mktemp)
    local trivy_report_file; trivy_report_file=$(mktemp)
    trap 'rm -f "$gitleaks_report_file" "$trivy_report_file"' EXIT

    # Check 2: Secret Scanning (Hard Block)
    if ! check_for_secrets_gitleaks "$STDIN_REFS" "$gitleaks_report_file"; then
        display_gitleaks_report "$gitleaks_report_file"
        log_findings "$gitleaks_report_file" "gitleaks"
        exit 1
    fi
    
    # Check 3: Dependency Scanning (Conditional & Interactive)
    if has_dependency_file_changes "$STDIN_REFS"; then
        echo -e "${CYAN}Dependency file changes detected. Scanning for vulnerabilities...${NC}"
        if ! check_for_vulnerabilities_trivy "$trivy_report_file"; then
            display_trivy_vulnerability_report "$trivy_report_file"
            log_findings "$trivy_report_file" "trivy"

            local response
            read -p "Are you sure you want to push these? (y/n): " response </dev/tty
            
            if [[ "$response" =~ ^[Yy]$ ]]; then
                echo -e "\n${GREEN}User override accepted. Proceeding with push.${NC}"
                exit 0
            else
                echo -e "\n${RED}Push aborted by user.${NC}"
                exit 1
            fi
        fi
    fi
    
    echo -e "\n${GREEN}✅ All security checks passed. Proceeding with push.${NC}"
    exit 0
}

# ==============================================================================
# CHECK & HELPER FUNCTIONS
# ==============================================================================

install_if_missing() {
    for tool_name in "$@"; do
        if command -v "$tool_name" >/dev/null 2>&1; then continue; fi
        log_script_error "Dependency missing: $tool_name. Attempting background install."
        if [[ "$(uname)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
            local install_cmd
            case "$tool_name" in
                "jq") install_cmd="brew install jq" ;;
                "gitleaks") install_cmd="brew install gitleaks" ;;
                "trivy") install_cmd="brew install aquasecurity/trivy/trivy" ;;
                *) continue ;;
            esac
            ( (brew update && $install_cmd) >/dev/null 2>&1 ) &
        fi
    done
}

resolve_host() {
    local host="$1"
    local ssh_config="$HOME/.ssh/config"

    if [[ -f "$ssh_config" ]]; then
        local mapped
        mapped=$(awk -v alias="$host" '
            $1 == "Host" && $2 == alias {inblock=1; next}
            inblock && $1 == "HostName" {print $2; exit}
            inblock && $1 == "Host" {inblock=0}
        ' "$ssh_config")

        if [[ -n "$mapped" ]]; then
            echo "$mapped"
            return
        fi
    fi

    echo "$host"
}

check_repo_validity() {
    local url="${REMOTE_URL%.git}"

    if [[ "$url" == git@* ]]; then
        local domain_and_path="${url#git@}"
        local domain="${domain_and_path%%:*}"
        local path="${domain_and_path#*:}"

        # resolve alias if present in ~/.ssh/config
        domain=$(resolve_host "$domain")

        url="https://$domain/$path"
    fi

    if [[ "$url" == *"github.com/zeptonow/"* ]]; then
        return 0
    fi

    echo -e "\n${RED}╔════════════════════════════════════════════════════════════╗${NC}" >&2
    echo -e "${RED}║                     SECURITY ALERT                         ║${NC}" >&2
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}" >&2
    echo -e "\n${RED}ERROR: Pushing to non-zeptonow repositories is not allowed${NC}" >&2
    echo -e "${YELLOW}This action has been logged and reported to the security team.${NC}" >&2
    echo -e "For assistance, please contact ${CYAN}security@zeptonow.com${NC} or Slack channel ${CYAN}#security${NC}\n" >&2

    log_non_zeptonow_alert
    return 1
}


check_for_secrets_gitleaks() {
    local refs_to_check="$1"
    local report_file="$2"
    if ! command -v gitleaks >/dev/null 2>&1; then return 0; fi

    while read -r local_ref local_sha remote_ref remote_sha; do
        if [[ "$local_sha" =~ ^0+$ ]]; then continue; fi
        local log_opts
        if [[ "$remote_sha" =~ ^0+$ ]]; then log_opts="$local_sha --not --remotes"; else log_opts="$remote_sha..$local_sha"; fi
        
        local stderr_file; stderr_file=$(mktemp)
        gitleaks detect --source="." --log-opts "$log_opts" --report-format="json" --report-path="$report_file" --redact >/dev/null 2>"$stderr_file"
        local exit_code=$?
        
        if [[ $exit_code -eq 1 ]]; then rm -f "$stderr_file"; return 1; fi
        if [[ $exit_code -ne 0 ]]; then log_script_error "Gitleaks failed" "$(<"$stderr_file")"; fi
        rm -f "$stderr_file"
    done <<< "$refs_to_check"
    return 0
}

has_dependency_file_changes() {
    local refs_to_check="$1"
    local dependency_files_pattern
    dependency_files_pattern='(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|Pipfile\.lock|poetry\.lock|go\.mod|go\.sum|Gemfile\.lock|pom\.xml|build\.gradle|Cargo\.lock|composer\.lock|package\.json|packages\.lock\.json|packages\.config|\.gemspec|deps\.json|gradle\.lockfile|conan\.lock|mix\.lock|pubspec\.lock|Podfile\.lock|Package\.resolved)'

    while read -r local_ref local_sha remote_ref remote_sha; do
        if [[ "$local_sha" =~ ^0+$ ]]; then continue; fi
        
        local changed_files
        if [[ "$remote_sha" =~ ^0+$ ]]; then
            changed_files=$(git diff-tree --no-commit-id --name-only -r "$local_sha")
        else
            changed_files=$(git diff --name-only "$remote_sha..$local_sha")
        fi
        
        if echo "$changed_files" | grep -qE "$dependency_files_pattern"; then
            return 0
        fi
    done <<< "$refs_to_check"
    return 1
}

check_for_vulnerabilities_trivy() {
    local report_file="$1"
    if ! command -v trivy >/dev/null 2>&1; then return 0; fi

    local stderr_file; stderr_file=$(mktemp)
    trivy fs --scanners vuln --exit-code 1 --format json --output "$report_file" . >/dev/null 2>"$stderr_file"
    local exit_code=$?

    if [[ $exit_code -eq 1 ]]; then rm -f "$stderr_file"; return 1; fi
    if [[ $exit_code -ne 0 ]]; then log_script_error "Trivy failed" "$(<"$stderr_file")"; fi
    rm -f "$stderr_file"
    return 0
}

# ==============================================================================
# LOGGING & DISPLAY FUNCTIONS
# ==============================================================================

# NEW function to handle ONLY non-zeptonow alerts to the original endpoint
log_non_zeptonow_alert() {
    local timestamp; timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local hostname; hostname=$(hostname 2>/dev/null || echo "unknown_host")
    local username; username=$(whoami 2>/dev/null || echo "unknown_user")
    
    if ! command -v jq >/dev/null 2>&1; then return; fi
    local payload
    payload=$(jq -n --arg ts "$timestamp" --arg hn "$hostname" --arg un "$username" --arg repo "$REMOTE_URL" --arg remote "$REMOTE_NAME" \
                    '{timestamp: $ts, hostname: $hn, username: $un, repository: $repo, git_remote: $remote}')
    
    curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$NON_ZEPTONOW_LOGGING_URL" --max-time 10 >/dev/null 2>&1 &
}

# This function now handles all OTHER script errors and sends them to the NEW endpoint
log_script_error() {
    local context="$1"
    local details="${2:-"No details provided."}"
    local timestamp; timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local hostname; hostname=$(hostname 2>/dev/null || echo "unknown_host")
    local username; username=$(whoami 2>/dev/null || echo "unknown_user")
    local log_entry="$timestamp - SCRIPT_ERROR - User: $username, Repo: $REMOTE_URL, Context: $context"
    echo "$log_entry" >> "$ERROR_LOG_FILE"; echo "Details: $details" >> "$ERROR_LOG_FILE"
    if ! command -v jq >/dev/null 2>&1; then return; fi
    local payload
    payload=$(jq -n --arg ts "$timestamp" --arg hn "$hostname" --arg un "$username" --arg repo "$REMOTE_URL" --arg ctx "$context" --arg dtls "$details" \
                    '{log_type: "script_error", timestamp: $ts, hostname: $hn, username: $un, repository: $repo, context: $ctx, details: $dtls}')
    
    # Note: Using SCRIPT_ERROR_LOGGING_URL
    curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$SCRIPT_ERROR_LOGGING_URL" --max-time 10 >/dev/null 2>&1 &
}

log_findings() {
    local report_file="$1"
    local scanner_type="$2"
    if ! command -v jq >/dev/null 2>&1; then return; fi
    
    local user; user=$(whoami 2>/dev/null || echo "unknown_user")
    local findings_json

    if [[ "$scanner_type" == "gitleaks" ]]; then
        findings_json=$(jq '[.[] | {type: .RuleID, file: .File, commit: .Commit}]' "$report_file")
    elif [[ "$scanner_type" == "trivy" ]]; then
        findings_json=$(jq '[.Results[]? | select(.Vulnerabilities) | . as $r | .Vulnerabilities[]? | {id: .VulnerabilityID, sev: .Severity, pkg: .PkgName, ver: .InstalledVersion, file: $r.Target}]' "$report_file")
    else
        return
    fi

    if [[ -z "$findings_json" ]] || [[ "$findings_json" == "[]" ]]; then return; fi
    local final_payload
    final_payload=$(jq -n --arg user "$user" --arg repo "$REMOTE_URL" --arg scanner "$scanner_type" --rawfile findings <(echo "$findings_json") \
                        '{user: $user, repository: $repo, scanner: $scanner, blocked_findings: ($findings | fromjson)}')
    curl -s -X POST -H "Content-Type: application/json" -d "$final_payload" "$SECRET_LOGGING_URL" --max-time 10 >/dev/null 2>&1 &
}

display_gitleaks_report() {
    local report_file="$1"
    if ! command -v jq >/dev/null 2>&1; then return; fi

    echo -e "\n${RED}╔═══════════════════════════════════════════════════════════════╗${NC}" >&2
    echo -e "${RED}║${YELLOW}                  HARDCODED SECRETS DETECTED                   ${RED}║${NC}" >&2
    echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}" >&2
    echo -e "\n${YELLOW}⚠️  Your push has been blocked because secrets were found in your commits.${NC}" >&2
    echo -e "   Self-Serve SoP -> ${CYAN}$SOP_URL${NC}\n" >&2
    echo -e "   Please remove them from your history and try again. For help, contact the ${CYAN}#security${NC} team.\n" >&2

    local current_commit=""
    jq -r 'group_by(.Commit, .File, .RuleID, .Secret) | map({
        Commit: .[0].Commit,
        File: .[0].File,
        RuleID: .[0].RuleID,
        Secret: .[0].Secret,
        Lines: ([.[].StartLine] | sort | unique | map(tostring) | join(", "))
    }) | sort_by(.Commit) | .[] | "\(.Commit // "N/A")\t\(.File // "N/A")\t\(.RuleID // "N/A")\t\(.Secret // "N/A")\t\(.Lines // "N/A")"' "$report_file" | \
    while IFS=$'\t' read -r commit file rule secret lines; do
        if [ "$commit" != "$current_commit" ]; then
            local subject
            subject=$(git log -1 --pretty=%s "$commit" 2>/dev/null || echo "Unknown Subject")
            echo -e "${BLUE}📝 Commit: $commit (${subject})${NC}" >&2
            current_commit="$commit"
        fi
        echo -e "   ${CYAN}File:   $file${NC}" >&2
        echo -e "   ${GREEN}Lines:  $lines${NC}" >&2
        echo -e "   ${PURPLE}Type:   $rule${NC}" >&2
        echo -e "   ${YELLOW}Secret: $secret${NC}\n" >&2
    done
}

display_trivy_vulnerability_report() {
    local report_file="$1"
    if ! command -v jq >/dev/null 2>&1; then return; fi

    local summary
    summary=$(jq -r '
      [ .Results[]? | select(.Vulnerabilities) | . as $result | .Vulnerabilities[]? | select(type == "object" and .PkgName) | 
        {target: $result.Target, pkg: .PkgName, sev: .Severity} ] |
      group_by(.pkg + " in " + .target) |
      map({
        package: .[0].pkg,
        target: .[0].target,
        total: length,
        critical: map(select(.sev == "CRITICAL")) | length,
        high: map(select(.sev == "HIGH")) | length,
        medium: map(select(.sev == "MEDIUM")) | length,
        low: map(select(.sev == "LOW")) | length
      }) |
      .[] |
      "\u001b[1m\u001b[33m\(.package)\u001b[0m in \(.target): \(.total) vulnerabilities (\u001b[31mC:\(.critical)\u001b[0m, \u001b[31mH:\(.high)\u001b[0m, \u001b[33mM:\(.medium)\u001b[0m, L:\(.low))"
    ' "$report_file")

    if [ -n "$summary" ]; then
        echo -e "\n${RED}╔═══════════════════════════════════════════════════════════════╗${NC}" >&2
        echo -e "${RED}║${YELLOW}           VULNERABLE DEPENDENCIES DETECTED                    ${RED}║${NC}" >&2
        echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}" >&2
        echo -e "\n${YELLOW}⚠️  WARNING: Security scanner has detected the following vulnerable packages:${NC}\n" >&2
        echo -e "$summary" >&2
        echo "────────────────────────────────────────────────────────" >&2
    fi
}

# --- SCRIPT ENTRY POINT ---
{
    main "$@"
} || {
    log_script_error "Catastrophic hook failure" "The main() function exited unexpectedly."
    exit 0
}
