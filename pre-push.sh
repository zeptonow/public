#!/bin/bash

# Function to check if gitleaks is installed
check_gitleaks() {
    if ! command -v gitleaks &> /dev/null; then
        echo "Gitleaks not found. Installing..."
        if ! command -v brew &> /dev/null; then
            echo "Error: Homebrew is required to install gitleaks."
            echo "Please install Homebrew first: https://brew.sh"
            exit 1
        fi
        brew install gitleaks
        echo "✅ Gitleaks installed successfully"
    fi
}

# Get the current remote and URL
remote="$1"
url="$2"

# Check and install gitleaks if needed
check_gitleaks

# Check if pushing to personal GitHub
if [[ $url == *"github.com"* && $url != *"github.com/zeptonow"* && $url != *"github.com:zeptonow"* ]]; then
    echo -e "Error: Pushing to personal GitHub repositories is not allowed\n"
    echo -e "Please push only to zeptonow repositories. This action will be logged.\n"
    logger -p auth.warning "Git Push Attempt: User $(whoami) tried to push to personal repository: $url"
    exit 1
fi

# Run gitleaks check
echo "Running secret detection..."
gitleaks git --pre-commit --staged --no-banner -v .

if [ $? -ne 0 ]; then
    echo -e "\n❌ Error: Secrets detected in your changes. Please remove them before pushing."
    exit 1
fi

exit 0
