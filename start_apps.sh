#!/bin/bash

# Navigate to the workspace root directory (optional, depends on where you run it from)
# cd "$(dirname "$0")"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for prerequisites
if ! command_exists mvn; then
    echo "Error: mvn command not found. Please install Maven."
    exit 1
fi

if ! command_exists npm; then
    echo "Error: npm command not found. Please install Node.js and npm."
    exit 1
fi

# Start Backend
echo "Attempting to start backend in 183_12_1_tresorbackend_rupe-master..."
cd 183_12_1_tresorbackend_rupe-master
if [ $? -ne 0 ]; then
    echo "Error: Failed to change directory to backend."
    exit 1
fi

mvn spring-boot:run &
BACKEND_PID=$!
echo "Backend started with PID $BACKEND_PID. Check logs for details."
cd ..
if [ $? -ne 0 ]; then
    echo "Error: Failed to change back to root directory from backend."
    exit 1
fi

# Start Frontend
echo "Attempting to start frontend in 183_12_2_tresorfrontend_rupe-master..."
cd 183_12_2_tresorfrontend_rupe-master
if [ $? -ne 0 ]; then
    echo "Error: Failed to change directory to frontend."
    exit 1
fi

# Check if node_modules exists, run npm install if not
if [ ! -d "node_modules" ]; then
  echo "node_modules not found. Running npm install..."
  npm install
  if [ $? -ne 0 ]; then
    echo "Error: npm install failed."
    # Attempt to kill the backend process if frontend setup fails
    kill $BACKEND_PID > /dev/null 2>&1
    exit 1
  fi
fi

npm start &
FRONTEND_PID=$!
echo "Frontend started with PID $FRONTEND_PID. Check logs for details."
cd ..
if [ $? -ne 0 ]; then
    echo "Error: Failed to change back to root directory from frontend."
    exit 1
fi

echo "Both applications are starting in the background."
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"
echo "Use 'kill $BACKEND_PID $FRONTEND_PID' to stop them."

# Optional: wait for background processes if needed
# wait $BACKEND_PID
# wait $FRONTEND_PID 
