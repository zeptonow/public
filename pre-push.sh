#!/bin/bash
#
# Git Pre-Push Hook
#
# This script performs three primary security checks before allowing a push:
# 1. Repository Validation: Ensures pushes are only made to approved 'zeptonow' repositories.
# 2. Secret Detection: Scans commits for secrets using 'gitleaks'.
# 3. Vulnerable Dependency Scan: Scans for vulnerable dependencies using 'Trivy' if dependency files have changed.
#
# --- Failsafe Design ---
# This script is designed to "fail open". If the script itself encounters an
# unexpected error, it will immediately and silently exit with a success code (0),
# allowing the push to proceed. Deliberate security blocks will still exit
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
        url="${url%.git}" # Remove .git suffix
    
        # Strip embedded user info and token (e.g., https://user:token@... )
        url=$(echo "$url" | sed -E 's|//.*@|//|')
    
        # Normalize if it's NOT an HTTP/S URL but contains a colon (is an SSH alias)
        if [[ "$url" != "https://"* ]] && [[ "$url" != "http://"* ]] && [[ "$url" == *:* ]]; then
            local path="${url#*:}"
            url="https://github.com/$path"
        fi
    
        # Final validation check on the cleaned URL
        [[ "$url" == "https://github.com/zeptonow/"* ]] || \
        [[ "$url" == "https://gitlab.com/zeptonow/"* ]]
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

    log_blocked_secrets() {
        local report_file="$1"
        local remote_url="$2"
        local user; user=$(whoami 2>/dev/null || echo "unknown_user")
        local secrets_array; secrets_array=$(jq 'group_by(.Commit + .File + .RuleID) | map({type: (.[0].RuleID // "N/A"),  commit: (.[0].Commit // "N/A")})' "$report_file")

        if [ -z "$secrets_array" ] || [ "$secrets_array" == "[]" ]; then
            return
        fi
        
        local final_payload; final_payload=$(cat <<EOF
{
  "user": "$(json_escape "$user")",
  "repository": "$(json_escape "$remote_url")",
  "blocked_secrets": $secrets_array
}
EOF
)
        curl -s -X POST \
          -H "Content-Type: application/json" \
          -d "$final_payload" "$SECRET_LOGGING_URL" \
          --connect-timeout 5 --max-time 10 > /dev/null 2>&1 &
    }

    check_for_secrets() {
        if ! command -v gitleaks >/dev/null 2>&1; then return 0; fi
        if ! command -v jq >/dev/null 2>&1; then
            echo -e "${YELLOW}Warning: 'jq' is not installed. Secret scanning report parsing may fail.${NC}" >&2
        fi

        local temp_report; temp_report=$(mktemp)
        trap 'rm -f "$temp_report"' EXIT
        local secrets_found_in_push=false
        
        local all_refs; all_refs=$(cat)

        while read -r local_ref local_sha remote_ref remote_sha; do
            if [[ "$local_sha" =~ ^0+$ ]]; then continue; fi
            > "$temp_report"
            
            local log_opts
            if [[ "$remote_sha" =~ ^0+$ ]]; then
                log_opts="$local_sha --not --remotes"
            else
                log_opts="$remote_sha..$local_sha"
            fi
            
            if ! gitleaks detect --source="." --log-opts="$log_opts" --report-format="json" --report-path="$temp_report" --redact=60 >/dev/null 2>&1; then
                if [ -s "$temp_report" ]; then
                    secrets_found_in_push=true
                    break
                fi
            fi
        done <<< "$all_refs"
        
        if [ "$secrets_found_in_push" = true ]; then
            log_blocked_secrets "$temp_report" "$REMOTE_URL"
            display_secrets_report "$temp_report"
            return 1
        fi
        
        return 0
    }

    display_secrets_report() {
        local report_file="$1"
        echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}" >&2
        echo -e "${RED}║${YELLOW}               HARDCODED SECRETS DETECTED                      ${RED}║${NC}" >&2
        echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}" >&2
        echo -e "\n${YELLOW}⚠️  Your push has been blocked because secrets were found in your commits.${NC}" >&2
        echo -e "   Please remove them from your history and try again. ${WHITE}For help, contact the ${CYAN}#security${WHITE} team.${NC}\n" >&2

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

    check_for_vulnerable_dependencies() {
        local readonly DEPENDENCY_FILES=(
            "Gemfile.lock" "*.gemspec" "Pipfile.lock" "poetry.lock" "requirements.txt"
            "composer.lock" "package-lock.json" "yarn.lock" "pnpm-lock.yaml" "package.json"
            "packages.lock.json" "packages.config" "*.deps.json" "pom.xml" "*gradle.lockfile"
            "go.mod" "Cargo.lock" "conan.lock" "mix.lock" "pubspec.lock"
            "Podfile.lock" "Package.resolved"
        )

        local all_refs; all_refs=$(cat)
        local scan_needed=false

        while read -r local_ref local_sha remote_ref remote_sha; do
            local changed_files=""
            if [[ "$remote_sha" =~ ^0+$ ]]; then
                changed_files=$(git diff-tree --no-commit-id --name-only -r "$local_sha")
            else
                changed_files=$(git diff --name-only "$remote_sha..$local_sha")
            fi

            for file in $changed_files; do
              for pattern in "${DEPENDENCY_FILES[@]}"; do
                local regex_pattern; regex_pattern=$(echo "$pattern" | sed 's/\./\\./g; s/\*/.*/g')
                if [[ "$file" =~ ^$regex_pattern$ ]]; then
                    echo -e "${GREEN}✅ Detected changes in dependency file: $file${NC}" >&2
                    scan_needed=true
                fi
              done
            done
        done <<< "$all_refs"

        if [ "$scan_needed" = false ]; then return 2; fi # Return 2 for SKIPPED

        for cmd in trivy jq; do
          if ! command -v $cmd &> /dev/null; then echo -e "${YELLOW}⚠️ $cmd is not installed. SCA scan will be skipped.${NC}" >&2; return 0; fi
        done

        local trivy_output_raw; trivy_output_raw=$(trivy fs --scanners vuln --pkg-types library --exit-code 1 --format json . 2>&1)
        local trivy_exit_code=$?
        local trivy_output_json; trivy_output_json=$(echo "$trivy_output_raw" | sed -n '/^[[:space:]]*{/,$p')

        if [ "$trivy_exit_code" -eq 1 ]; then
            # CORRECTED JQ QUERY: A more robust query to handle JSON variations and prevent parsing errors.
            local summary; summary=$(echo "$trivy_output_json" | jq -r '
              [
                .Results[]?
                | select(.Vulnerabilities)
                | . as $result
                | .Vulnerabilities[]?
                | select(type == "object" and .PkgName)
                | {target: $result.Target, pkg: .PkgName, sev: .Severity}
              ]
              | group_by({pkg: .pkg, target: .target})
              | map(
                  {
                    package: .[0].pkg,
                    target: .[0].target,
                    total: length,
                    critical: map(select(.sev == "CRITICAL")) | length,
                    high: map(select(.sev == "HIGH")) | length,
                    medium: map(select(.sev == "MEDIUM")) | length,
                    low: map(select(.sev == "LOW")) | length
                  }
                )
              | .[]
              | "\u001b[1m\u001b[33m\(.package)\u001b[0m in \(.target): \(.total) vulnerabilities (\u001b[31mC:\(.critical)\u001b[0m, \u001b[31mH:\(.high)\u001b[0m, \u001b[33mM:\(.medium)\u001b[0m, L:\(.low))"
            ')

            if [ -n "$summary" ]; then
                echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}" >&2
                echo -e "${RED}║${YELLOW}           VULNERABLE DEPENDENCIES DETECTED                  ${RED}║${NC}" >&2
                echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}" >&2
                echo -e "\n\033[31m⚠️  WARNING: Trivy detected the following vulnerable packages:\033[0m\n" >&2
                echo -e "$summary" >&2
                echo "────────────────────────────────────────────────────────" >&2
                read -p "Are you sure you want to push these? (y/n) " -n 1 -r < /dev/tty; echo >&2
                if [[ $REPLY =~ ^[Yy]$ ]]; then return 0; else return 1; fi
            else
                echo -e "\n${RED}❌ ERROR: Trivy indicated vulnerabilities, but the report could not be parsed.${NC}\n" >&2; echo "$trivy_output_raw" >&2
                return 1
            fi
        elif [ "$trivy_exit_code" -ne 0 ]; then
            echo -e "\n${RED}❌ ERROR: Trivy failed to run. Please check the output below.${NC}\n" >&2; echo "$trivy_output_raw" >&2
            return 1
        else
            return 0
        fi
    }

    # --- Execute Checks ---
    echo "────────────────────────────────────────────────────────" >&2
    echo "🛡️  Running Security Pre-Push Checks..." >&2
    echo "────────────────────────────────────────────────────────" >&2

    # 1. Repository Validation
    echo -n "[1/3] Validating repository destination... " >&2
    if ! is_valid_zeptonow_repo "$REMOTE_URL"; then
        echo -e "${RED}BLOCKED ❌${NC}" >&2
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
    echo -e "${GREEN}OK ✅${NC}" >&2

    # The script reads from stdin. We pass it to each function that needs it.
    stdin_content=$(cat)

    # 2. Secret Detection
    echo -n "[2/3] Scanning for hardcoded secrets... " >&2
    if ! echo "$stdin_content" | check_for_secrets; then
        echo # Newline for clarity after the function's detailed output
        echo -e "[2/3] Scanning for hardcoded secrets... ${RED}BLOCKED ❌${NC}" >&2
        exit 1
    fi
    echo -e "${GREEN}OK ✅${NC}" >&2

    # 3. Vulnerable Dependency Scan
    echo -n "[3/3] Scanning for vulnerable dependencies... " >&2
    # We must redirect stderr to stdout to capture all output from the function
    sca_output=$(echo "$stdin_content" | check_for_vulnerable_dependencies 2>&1)
    sca_exit_code=$?
    
    if [ $sca_exit_code -eq 1 ]; then
        echo -e "${RED}BLOCKED ❌${NC}" >&2
        echo "$sca_output" >&2 # Display the detailed report from the function
        exit 1
    elif [ $sca_exit_code -eq 2 ]; then
        echo -e "${YELLOW}SKIPPED ✅${NC}" >&2
        echo "$sca_output" >&2 # Display the "skipping" message
    else
        echo -e "${GREEN}OK ✅${NC}" >&2
        echo "$sca_output" >&2 # Display the "no vulns found" or other info
    fi
    
    echo "────────────────────────────────────────────────────────" >&2
    echo -e "${GREEN}All security checks passed. Proceeding with push.${NC}" >&2
    echo "────────────────────────────────────────────────────────" >&2

    exit 0
}

# --- Failsafe Execution ---
main "$@" || exit 0
