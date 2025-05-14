#!/bin/bash

# Set error handling
set -e

echo "Setting up git security hooks for zeptonow..."

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
    echo "✓ zeptonow security hook setup successful"
    echo "✓ Global hooks path set to: $(git config --global --get core.hooksPath)"
else
    echo "× Installation failed"
    exit 1
fi

echo "REMINDER: Code push security measures are now in place."
echo "Pushing to non-zeptonow repositories is blocked."
echo "For assistance, contact security@zeptonow.com or Slack channel #security"

exit 0
