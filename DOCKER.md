# 🐳 HeaderDoctor Docker Deployment

## Quick Start Commands

### Development Mode
```bash
# Start with Docker Compose (recommended)
docker-compose up --build

# Or run in background
docker-compose up --build -d

# Using Makefile
make dev
```

### Production Mode
```bash
# With Nginx reverse proxy
docker-compose -f docker-compose.prod.yml up --build -d

# Using Makefile
make prod
```

### Simple Docker
```bash
# Build and run single container
docker build -t headerdoctor .
docker run -p 5000:5000 headerdoctor

# Alpine version (smaller size)
docker build -f Dockerfile.alpine -t headerdoctor:alpine .
docker run -p 5000:5000 headerdoctor:alpine
```

## Available Files

- **Dockerfile** - Main Docker image (Ubuntu-based)
- **Dockerfile.alpine** - Lightweight Alpine-based image
- **docker-compose.yml** - Development setup
- **docker-compose.prod.yml** - Production setup with Nginx
- **docker-entrypoint.sh** - Startup script for main image
- **docker-entrypoint-alpine.sh** - Startup script for Alpine
- **nginx.conf** - Nginx reverse proxy configuration
- **Makefile** - Simplified build commands
- **.dockerignore** - Files to exclude from Docker context

## Access Points

- **Development**: http://localhost:5000
- **Production**: http://localhost (port 80)

## Features

✅ Multi-container setup with Redis
✅ Production-ready with Nginx reverse proxy
✅ Security headers configured
✅ Health checks and monitoring
✅ Volume persistence for data
✅ Alpine variant for smaller images
✅ Make commands for easy deployment

## Useful Commands

```bash
# View logs
docker-compose logs -f

# Stop containers
docker-compose down

# Clean up everything
make clean

# Connect to Redis
make redis-cli

# Check health
make health
```