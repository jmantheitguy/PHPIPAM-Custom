#!/bin/bash
set -e

echo "Starting IPAM Subnet Scanner..."

# Wait for MySQL
echo "Waiting for MySQL..."
max_tries=30
counter=0
until python3 -c "import mysql.connector; mysql.connector.connect(host='${MYSQL_HOST}', user='${MYSQL_USER}', password='${MYSQL_PASSWORD}', database='${MYSQL_DATABASE}')" > /dev/null 2>&1; do
    counter=$((counter + 1))
    if [ $counter -gt $max_tries ]; then
        echo "Error: MySQL not available after $max_tries attempts"
        exit 1
    fi
    echo "MySQL not ready, waiting... ($counter/$max_tries)"
    sleep 2
done
echo "MySQL is ready!"

# Wait for Redis
echo "Waiting for Redis..."
counter=0
until redis-cli -h "${REDIS_HOST:-redis}" -p "${REDIS_PORT:-6379}" ping > /dev/null 2>&1; do
    counter=$((counter + 1))
    if [ $counter -gt $max_tries ]; then
        echo "Error: Redis not available after $max_tries attempts"
        exit 1
    fi
    echo "Redis not ready, waiting... ($counter/$max_tries)"
    sleep 2
done
echo "Redis is ready!"

echo "Starting scanner service..."
exec "$@"
