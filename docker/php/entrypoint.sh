#!/bin/sh
set -e

# Create log directory
mkdir -p /var/log/php
chown -R www-data:www-data /var/log/php

# Wait for MySQL to be ready using PHP
echo "Waiting for MySQL..."
max_tries=30
counter=0
until php -r "new PDO('mysql:host=${PHPIPAM_DB_HOST};dbname=${PHPIPAM_DB_NAME}', '${PHPIPAM_DB_USER}', '${PHPIPAM_DB_PASS}');" 2>/dev/null; do
    counter=$((counter + 1))
    if [ $counter -gt $max_tries ]; then
        echo "Error: MySQL not available after $max_tries attempts"
        exit 1
    fi
    echo "MySQL not ready, waiting... ($counter/$max_tries)"
    sleep 2
done
echo "MySQL is ready!"

# Wait for Redis to be ready using netcat
echo "Waiting for Redis..."
counter=0
while ! nc -z "${REDIS_HOST:-redis}" "${REDIS_PORT:-6379}" 2>/dev/null; do
    counter=$((counter + 1))
    if [ $counter -gt $max_tries ]; then
        echo "Warning: Redis not available, continuing anyway..."
        break
    fi
    echo "Redis not ready, waiting... ($counter/$max_tries)"
    sleep 2
done
echo "Redis is ready!"

# Check if PHPIPAM is installed
if [ ! -f /var/www/html/phpipam/config.php ]; then
    echo "PHPIPAM config not found. Please ensure PHPIPAM is properly installed."
fi

# Set proper permissions
chown -R www-data:www-data /var/www/html/phpipam 2>/dev/null || true

echo "Starting PHP-FPM..."
exec "$@"
