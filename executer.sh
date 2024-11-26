#!/bin/bash

# Create global git hooks directory
mkdir -p ~/.git/hooks

# Download the pre-push hook
curl -o ~/.git/hooks/pre-push https://raw.githubusercontent.com/zeptonow/public/main/pre-push.sh

# Make the hook executable
chmod +x ~/.git/hooks/pre-push

# Set global hooks path
git config --global core.hooksPath ~/.git/hooks

# Verify installation
if [ -x ~/.git/hooks/pre-push ]; then
    echo "✅ Setup successful"
    echo "✅ Global path set to: $(git config --global --get core.hooksPath)"
else
    echo "❌ Installation failed"
    exit 1
fi
