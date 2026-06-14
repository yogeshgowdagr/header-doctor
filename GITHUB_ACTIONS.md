# GitHub Actions Setup Guide

## 🚀 Automated Docker Build & Deploy

This repository includes GitHub Actions workflows to automatically build and publish Docker images.

## Workflows

### 1. **CI Workflow** (`.github/workflows/ci.yml`)
- Runs on every push and pull request
- Tests Docker builds for both standard and Alpine versions
- Lints Dockerfiles with Hadolint
- Tests application startup

### 2. **Release Workflow** (`.github/workflows/release.yml`)
- Runs on pushes to main/master branch
- Runs on new releases/tags
- Builds and pushes multi-architecture images (amd64, arm64)
- Publishes to both GitHub Container Registry and Docker Hub

### 3. **Full CI/CD Pipeline** (`.github/workflows/docker-build.yml`)
- Comprehensive testing and security scanning
- Vulnerability scanning with Trivy
- Code coverage reporting
- Security analysis

## Setup Instructions

### Required Secrets

Add these secrets to your GitHub repository settings:

#### For Docker Hub (Optional)
```
DOCKERHUB_USERNAME=yourdockerhubusername
DOCKERHUB_TOKEN=your_dockerhub_access_token
```

#### For Security Scanning (Optional)
```
SNYK_TOKEN=your_snyk_token
```

### GitHub Container Registry

The workflows automatically use `GITHUB_TOKEN` for GitHub Container Registry - no additional setup required!

## Published Images

After setup, your images will be available at:

### GitHub Container Registry
```
ghcr.io/yourusername/headerdoctor:latest
ghcr.io/yourusername/headerdoctor:alpine
ghcr.io/yourusername/headerdoctor:v1.0.0
```

### Docker Hub (if configured)
```
yourusername/headerdoctor:latest
yourusername/headerdoctor:alpine
yourusername/headerdoctor:v1.0.0
```

## Usage

### Pull and run from GitHub Container Registry
```bash
docker pull ghcr.io/yourusername/headerdoctor:latest
docker run -p 5000:5000 ghcr.io/yourusername/headerdoctor:latest
```

### Pull and run from Docker Hub
```bash
docker pull yourusername/headerdoctor:latest
docker run -p 5000:5000 yourusername/headerdoctor:latest
```

### Using Docker Compose
```yaml
services:
  headerdoctor:
    image: ghcr.io/yourusername/headerdoctor:latest
    ports:
      - "5000:5000"
```

## Triggering Builds

### Automatic Triggers
- **Push to main/master**: Builds `latest` tag
- **Create release/tag**: Builds versioned tag (e.g., `v1.0.0`)
- **Pull requests**: Runs tests only (no publishing)

### Manual Trigger
Go to Actions tab → Select workflow → "Run workflow"

## Image Variants

| Tag | Base | Size | Use Case |
|-----|------|------|----------|
| `latest` | python:3.11-slim | ~200MB | Production |
| `alpine` | python:3.11-alpine | ~150MB | Lightweight |
| `v1.0.0` | python:3.11-slim | ~200MB | Specific version |
| `v1.0.0-alpine` | python:3.11-alpine | ~150MB | Lightweight version |

## Multi-Architecture Support

All images are built for:
- `linux/amd64` (Intel/AMD)
- `linux/arm64` (ARM, Apple Silicon)

Perfect for deployment on various platforms including Raspberry Pi, AWS Graviton, and Apple Silicon Macs!

## Security Features

- 🔒 Vulnerability scanning with Trivy
- 📋 Dockerfile linting with Hadolint
- 🛡️ Dependency security analysis
- 🔍 SARIF security report integration
- 📊 Code coverage reporting

---

**Next Steps:**
1. Push code to GitHub
2. Add required secrets (if using Docker Hub)
3. Create a release to trigger versioned builds
4. Your Docker images will be automatically built and published! 🎉