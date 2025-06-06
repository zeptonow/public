#!/bin/bash

# Set error handling
set -e

# Create global git hooks directory
mkdir -p ~/.git/hooks

# Create log file in user's home directory (always accessible)
touch ~/.git/hooks/push_attempts.log
chmod 600 ~/.git/hooks/push_attempts.log

# Download the pre-push hook
curl -s -f -o ~/.git/hooks/pre-push https://raw.githubusercontent.com/zeptonow/public/main/pre-push.sh || {
    echo "Failed to download pre-push hook"
    exit 1
}

# Make the hook executable
chmod +x ~/.git/hooks/pre-push || {
    echo "Failed to set execute permissions"
    exit 1
}

# Set global hooks path
git config --global core.hooksPath ~/.git/hooks || {
    echo "Failed to set global hooks path"
    exit 1
}

# Verify installation
if [ -x ~/.git/hooks/pre-push ]; then
    echo "✓"
else
    echo "× Installation failed"
    exit 1
fi

echo "For assistance, contact security@zeptonow.com or Slack channel #security"

exit 0
