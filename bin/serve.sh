#!/bin/bash

# Function to handle termination signal
cleanup() {
  echo "Stopping Jekyll server..."
  pkill -f 'bundle exec jekyll serve'
  exit 0
}

# Trap the termination signal
trap cleanup SIGINT SIGTERM

# Start the Jekyll server in the background
bundle exec jekyll serve --host 0.0.0.0 --port 4000 &

# Wait for the server to start
sleep 3

# Open the specific URL in Firefox
open -a "Firefox" http://localhost:4000

# Wait for the Jekyll server process to finish
wait
