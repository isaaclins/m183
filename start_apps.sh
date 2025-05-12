#!/bin/bash

# --- Configuration ---
BACKEND_DIR="183_12_1_tresorbackend_rupe-master"
FRONTEND_DIR="183_12_2_tresorfrontend_rupe-master"
PROPERTIES_FILE="$BACKEND_DIR/src/main/resources/application.properties"
DB_SETUP_SCRIPT="$BACKEND_DIR/tresordb.sql"

# --- Script Arguments ---
# Usage: ./start_apps.sh [db_password]
DB_PASS_ARG=$1        # Password from $1 (can be empty)

# --- Helper Functions ---

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to read property from application.properties using awk
get_property() {
    awk -F= -v key="^$1" '$1 ~ key {sub(/^[^=]+=/, ""); gsub(/\r$/, ""); print; exit}' "$PROPERTIES_FILE"
}

# Function to parse JDBC URL
parse_jdbc_url() {
    local url=$1
    # Expected format: jdbc:mysql://host:port/dbname
    DB_HOST=$(echo "$url" | sed -n 's|.*//\([^:]*\):.*|\1|p')
    DB_PORT=$(echo "$url" | sed -n 's|.*//[^:]*:\([0-9]*\)/.*|\1|p')
    DB_NAME=$(echo "$url" | sed -n 's|.*/\([^?]*\).*|\1|p')

    # Apply defaults if parsing failed or parts are missing
    [[ -z "$DB_HOST" ]] && DB_HOST="localhost"
    [[ -z "$DB_PORT" ]] && DB_PORT="3306"
}

# Function to kill processes on a given port
kill_on_port() {
    local port=$1
    echo "Checking for processes on port $port..."
    # Use lsof to find PIDs listening on the port. -t gives only PIDs.
    # Use || true to prevent script exit if lsof finds nothing (exit code 1)
    local pids=$(lsof -t -i:$port || true)
    if [[ -n "$pids" ]]; then
        echo "Killing processes on port $port with PIDs: $pids"
        # Use xargs to handle multiple PIDs properly
        echo "$pids" | xargs kill -9
        sleep 2 # Give a moment for ports to be released
    else
        echo "No processes found on port $port."
    fi
}

# --- Prerequisites Check ---

echo "Checking prerequisites..."

# Check for Homebrew (for MySQL service management on macOS)
if ! command_exists brew; then
    echo "Error: Homebrew (brew) command not found. Please install Homebrew first (https://brew.sh/)."
    exit 1
fi

# Check for MySQL command
if ! command_exists mysql; then
    echo "Error: mysql command not found."
    echo "Please install MySQL using Homebrew: brew install mysql"
    echo "Then run: brew services start mysql"
    echo "And secure the installation: mysql_secure_installation (if needed)"
    exit 1
fi

# Check for Maven
if ! command_exists mvn; then
    echo "Error: mvn command not found. Please install Maven (e.g., using 'brew install maven')."
    exit 1
fi

# Check for Node/npm
if ! command_exists npm; then
    echo "Error: npm command not found. Please install Node.js and npm (e.g., using 'brew install node')."
    exit 1
fi

echo "Prerequisites met."

# --- Database Configuration and Setup ---

echo "Checking Database Configuration..."

# Read DB URL and Username from properties
DB_URL=$(get_property "spring.datasource.url")
DB_USER=$(get_property "spring.datasource.username")

if [[ -z "$DB_URL" || -z "$DB_USER" ]]; then
    echo "Error: Could not read spring.datasource.url or spring.datasource.username from $PROPERTIES_FILE."
    exit 1
fi

parse_jdbc_url "$DB_URL"

if [[ -z "$DB_NAME" ]]; then
    echo "Error: Could not parse database name from URL: $DB_URL"
    exit 1
fi

# Determine DB Password
DB_PASS="$DB_PASS_ARG" # Assign password from argument $1

if [[ -z "$DB_PASS" ]]; then
    if [[ -n "$MYSQL_PWD" ]]; then
        echo "Using MySQL password from MYSQL_PWD environment variable."
        DB_PASS="$MYSQL_PWD"
    else
        echo -n "Enter MySQL password for user '$DB_USER': "
        read -s DB_PASS # Read password securely
        echo
        if [[ -z "$DB_PASS" ]]; then
            echo "Error: Password not provided for database setup/access."
            exit 1
        fi
    fi
fi

echo "Database config: User='$DB_USER', Host='$DB_HOST', Port='$DB_PORT', Name='$DB_NAME'"
# IMPORTANT: Avoid printing the password in logs if possible, though it's in MYSQL_PWD here.

# Check MySQL Service Status
echo "Checking MySQL service status..."
if ! brew services list | grep -q "mysql.*started"; then
    echo "MySQL service is not running. Attempting to start with 'brew services start mysql'..."
    brew services start mysql
    sleep 5 # Give service time to start
    if ! brew services list | grep -q "mysql.*started"; then
        echo "Error: Failed to start MySQL service. Please check 'brew services list' and MySQL logs."
        exit 1
    fi
    echo "MySQL service started successfully."
else
    echo "MySQL service is running."
fi

# Check if database exists and set it up if not
export MYSQL_PWD="$DB_PASS" # Use MYSQL_PWD for mysql commands

if mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -e "USE \`$DB_NAME\`;" >/dev/null 2>&1; then
    echo "Database '$DB_NAME' exists and is accessible."
else
    echo "Database '$DB_NAME' does not exist or cannot be accessed by user '$DB_USER'."
    echo "Attempting to create database and import schema from $DB_SETUP_SCRIPT..."

    if [[ ! -f "$DB_SETUP_SCRIPT" ]]; then
        echo "Error: Database setup script $DB_SETUP_SCRIPT not found! Cannot create/configure database."
        unset MYSQL_PWD
        exit 1
    fi

    # Attempt to run the whole SQL script (which should include CREATE DATABASE and USE)
    # This relies on DB_USER having sufficient privileges (CREATE DATABASE, CREATE TABLE, INSERT, etc.)
    if mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" < "$DB_SETUP_SCRIPT"; then
        echo "Database setup script executed. Assuming database '$DB_NAME' is now created and configured."
        # Verify connection to the specific DB again
        if ! mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -e "USE \`$DB_NAME\`;" >/dev/null 2>&1; then
            echo "Error: Still cannot connect to database '$DB_NAME' after running setup script."
            echo "Please check user ('$DB_USER') privileges and the content of $DB_SETUP_SCRIPT."
            unset MYSQL_PWD
            exit 1
        fi
        echo "Successfully connected to database '$DB_NAME' after setup."
    else
        echo "Error: Failed to execute database setup script $DB_SETUP_SCRIPT."
        echo "Please check MySQL user ('$DB_USER') privileges or run the script manually."
        unset MYSQL_PWD
        exit 1
    fi
fi
# MYSQL_PWD will be unset before starting the main apps if password was prompted.
# If it came from env or arg, it remains for the backend process.
if [[ -z "$DB_PASS_ARG" && -z "${MYSQL_PWD_INIT}" ]]; then # If password was prompted
  echo "Unsetting prompted MYSQL_PWD for subsequent processes (backend will use its own config or a new MYSQL_PWD from this script)."
  # The backend spring-boot:run below will get a fresh MYSQL_PWD set before it runs
  # However, we should unset the one we used for setup if it was prompted for security.
  # Better to handle MYSQL_PWD specifically for each command that needs it if possible,
  # but for simplicity here, we manage it across the setup phase.
  # The `export MYSQL_PWD="$DB_PASS"` before starting backend will re-establish it.
  TEMP_MYSQL_PWD_FOR_BACKEND="$DB_PASS" # Store it
  unset MYSQL_PWD
  export MYSQL_PWD="$TEMP_MYSQL_PWD_FOR_BACKEND" # Re-export for backend
fi

echo "Database setup checked."

# --- Start Applications ---

echo ""
echo "IMPORTANT: Backend application will use connection details from its application.properties."
echo "The password provided to this script is primarily for initial DB setup if needed."
echo "If the backend also needs MYSQL_PWD set, it will be set from the argument/prompt."
echo ""

# Kill existing processes before starting new ones
kill_on_port 8080 # Backend port
kill_on_port 3000 # Frontend port

# Re-ensure MYSQL_PWD is set for the backend process
export MYSQL_PWD="$DB_PASS"

# Start Backend
echo "Attempting to start backend in $BACKEND_DIR..."
cd "$BACKEND_DIR" || { echo "Error: Failed to cd to $BACKEND_DIR"; unset MYSQL_PWD; exit 1; }

mvn spring-boot:run &
BACKEND_PROC_PID=$!
echo "Backend starting with PID $BACKEND_PROC_PID. Check logs for details."
cd .. || { echo "Error: Failed to cd back to root from backend"; kill $BACKEND_PROC_PID 2>/dev/null; unset MYSQL_PWD; exit 1; }

# Start Frontend
# Frontend doesn't need MYSQL_PWD
echo "Attempting to start frontend in $FRONTEND_DIR..."
cd "$FRONTEND_DIR" || { echo "Error: Failed to cd to $FRONTEND_DIR"; kill $BACKEND_PROC_PID 2>/dev/null; unset MYSQL_PWD; exit 1; }

# Check if node_modules exists, run npm install if not
if [ ! -d "node_modules" ]; then
  echo "node_modules not found in $FRONTEND_DIR. Running npm install..."
  npm install
  if [ $? -ne 0 ]; then
    echo "Error: Frontend 'npm install' failed."
    kill $BACKEND_PROC_PID 2>/dev/null
    unset MYSQL_PWD
    exit 1
  fi
fi

npm start &
FRONTEND_PROC_PID=$!
echo "Frontend starting with PID $FRONTEND_PROC_PID. Check logs for details."
cd .. || { echo "Error: Failed to cd back to root from frontend"; kill $BACKEND_PROC_PID $FRONTEND_PROC_PID 2>/dev/null; unset MYSQL_PWD; exit 1; }

# Unset MYSQL_PWD if it was set by this script
if [[ -n "$DB_PASS" && -z "${MYSQL_PWD_INIT_ENV}" ]]; then # Simplified: if DB_PASS was set by arg/prompt.
    # Storing initial MYSQL_PWD state is more robust, but this is simpler for now.
    echo "Clearing MYSQL_PWD environment variable set by script."
    unset MYSQL_PWD
fi

echo ""
echo "--- Applications Starting ---"
echo "Backend PID: $BACKEND_PROC_PID"
echo "Frontend PID: $FRONTEND_PROC_PID"
echo "Wait for applications to boot completely. Check their logs for status."
echo "To stop them later, run: kill $BACKEND_PROC_PID $FRONTEND_PROC_PID"
echo ""
