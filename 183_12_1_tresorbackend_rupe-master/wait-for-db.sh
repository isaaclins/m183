#!/bin/sh
set -e

host="$1"
shift
cmd="$@"

# Extract hostname and port
hostname=$(echo $host | cut -d':' -f1)
port=$(echo $host | cut -d':' -f2)

echo "Waiting for database at $hostname:$port to be ready..."

# Loop until we can connect to the database
until nc -z $hostname $port; do
  echo "Database is unavailable - sleeping..."
  sleep 5
done

# Add extra delay to ensure database is fully initialized
echo "Database is reachable, waiting for it to be fully initialized..."
sleep 10

echo "Database should be ready now - executing command"
exec $cmd