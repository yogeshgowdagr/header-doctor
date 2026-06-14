#!/bin/sh

# Start Redis server in background
redis-server --daemonize yes --bind 127.0.0.1 --port 6379

# Wait for Redis to start
sleep 3

# Verify Redis is running
redis-cli ping

# Start Flask application
exec python app.py