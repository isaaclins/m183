#!/bin/bash
set -e

host="$1"
shift
cmd="$@"

echo "Waiting for $host to be ready..."

until mysqladmin ping -h "$host" --silent; do
  echo "MariaDB is unavailable - waiting..."
  sleep 2
done

echo "MariaDB is up - executing command"
exec $cmd