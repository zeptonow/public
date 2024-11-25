#!/bin/bash

# Get the current remote and URL
remote="$1"
url="$2"

# Check if pushing to personal GitHub
if [[ $url == *"github.com"* && $url != *"github.com/zeptonow"* ]]; then
    echo -e "Error: Pushing to personal GitHub repositories is not allowed\n"
    echo -e "Please push only to zeptonow repositories. This action will be logged.\n"
    
    # Log the attempt
    logger -p auth.warning "Git Push Attempt: User $(whoami) tried to push to personal repository: $url"
    
    exit 1
fi

exit 0
