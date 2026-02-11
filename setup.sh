#!/bin/bash
#
# IPAM System Setup Script
# This script prepares the environment for first-time deployment
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo "=========================================="
echo "  IPAM System Setup"
echo "=========================================="
echo ""

# Check prerequisites
log_info "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    log_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

log_success "Prerequisites check passed."

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    log_info "Creating .env file from template..."
    cp .env.example .env

    # Generate random passwords
    MYSQL_ROOT_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
    MYSQL_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)

    # Update passwords in .env
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/change_this_root_password/${MYSQL_ROOT_PASS}/" .env
        sed -i '' "s/change_this_phpipam_password/${MYSQL_PASS}/" .env
    else
        sed -i "s/change_this_root_password/${MYSQL_ROOT_PASS}/" .env
        sed -i "s/change_this_phpipam_password/${MYSQL_PASS}/" .env
    fi

    log_success "Created .env file with generated passwords."
    log_warning "Please review and update .env before continuing."
else
    log_info ".env file already exists, skipping creation."
fi

# Generate SSL certificates if they don't exist
if [ ! -f ssl/server.crt ] || [ ! -f ssl/server.key ]; then
    log_info "Generating SSL certificates..."
    chmod +x ssl/generate-certs.sh
    (cd ssl && ./generate-certs.sh)
    log_success "SSL certificates generated."
else
    log_info "SSL certificates already exist, skipping generation."
fi

# Download PHPIPAM if not present
if [ ! -f phpipam/index.php ]; then
    log_info "Downloading PHPIPAM..."

    PHPIPAM_VERSION="v1.6.0"

    # Remove empty phpipam directory if it exists
    rm -rf phpipam 2>/dev/null || true

    # Clone from GitHub (more reliable than tarball)
    if command -v git &> /dev/null; then
        git clone --depth 1 --branch "${PHPIPAM_VERSION}" https://github.com/phpipam/phpipam.git phpipam 2>/dev/null
        if [ -f phpipam/index.php ]; then
            # Remove .git directory to save space
            rm -rf phpipam/.git
            log_success "PHPIPAM ${PHPIPAM_VERSION} downloaded successfully."
        else
            log_warning "Git clone failed, trying alternative method..."
        fi
    fi

    # Fallback: try direct download if git failed
    if [ ! -f phpipam/index.php ]; then
        mkdir -p phpipam
        PHPIPAM_URL="https://github.com/phpipam/phpipam/archive/refs/tags/${PHPIPAM_VERSION}.tar.gz"
        log_info "Trying download from: ${PHPIPAM_URL}"

        if curl -fsSL "${PHPIPAM_URL}" -o /tmp/phpipam.tar.gz; then
            tar -xzf /tmp/phpipam.tar.gz --strip-components=1 -C phpipam
            rm -f /tmp/phpipam.tar.gz
            if [ -f phpipam/index.php ]; then
                log_success "PHPIPAM ${PHPIPAM_VERSION} downloaded successfully."
            fi
        fi
    fi

    # Final check
    if [ ! -f phpipam/index.php ]; then
        log_warning "Could not download PHPIPAM automatically."
        log_info "Please download PHPIPAM manually:"
        log_info "  git clone https://github.com/phpipam/phpipam.git phpipam"
        log_info "Or download from: https://phpipam.net/download/"
    fi
else
    log_info "PHPIPAM already present in phpipam directory."
fi

# Create required directories
log_info "Creating required directories..."
mkdir -p {nginx/conf.d,ssl,phpipam,scripts,database/init,config/phpipam}
log_success "Directories created."

# Set permissions
log_info "Setting permissions..."
chmod +x scripts/*.sh 2>/dev/null || true
chmod +x docker/*/entrypoint.sh 2>/dev/null || true
log_success "Permissions set."

# Build Docker images
log_info "Building Docker images..."
docker compose build --no-cache
log_success "Docker images built."

echo ""
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Review and update the .env file with your settings"
echo "2. Start the containers:"
echo "   docker compose up -d"
echo ""
echo "3. Access the web UI:"
echo "   https://localhost (or your configured domain)"
echo ""
echo "4. Complete PHPIPAM installation via web interface"
echo "   Default credentials: admin / ipamadmin"
echo ""
echo "5. Configure Active Directory (optional):"
echo "   Update AD_* settings in .env and restart"
echo ""
log_info "Run 'docker compose logs -f' to monitor startup."
echo ""
