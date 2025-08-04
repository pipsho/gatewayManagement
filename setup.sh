#!/bin/bash

# IoT Gateway Management Setup Script
# Run with: sudo ./setup.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/iot-gateway"
SERVICE_NAME="iot-gateway"
PORT=3000

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_dependencies() {
    print_status "Checking dependencies..."
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed. Please install Node.js 14+ first."
        exit 1
    fi
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed. Please install npm first."
        exit 1
    fi
    
    # Check SQLite3 (via npm package)
    if ! npm list sqlite3 &> /dev/null; then
        print_status "Installing SQLite3..."
        npm install sqlite3
    fi
    
    print_status "Dependencies check completed"
}

install_application() {
    print_status "Installing IoT Gateway..."
    
    # Create installation directory
    if [ -d "$INSTALL_DIR" ]; then
        print_warning "Directory $INSTALL_DIR already exists. Backing up..."
        mv "$INSTALL_DIR" "$INSTALL_DIR.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    mkdir -p "$INSTALL_DIR"
    
    # Copy application files
    print_status "Copying application files..."
    cp -r * "$INSTALL_DIR/"
    
    # Set permissions
    print_status "Setting permissions..."
    chown -R www-data:www-data "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 644 "$INSTALL_DIR"/*
    chmod 755 "$INSTALL_DIR/server.js"
    chmod 755 "$INSTALL_DIR/setup.sh"
    
    # Install Node.js dependencies
    print_status "Installing Node.js dependencies..."
    cd "$INSTALL_DIR"
    npm install --production
    
    print_status "Application installed successfully"
}

create_service() {
    print_status "Creating systemd service..."
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=IoT Gateway Management System
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=PORT=${PORT}

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    print_status "Service created and enabled"
}

configure_firewall() {
    print_status "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw allow "$PORT/tcp"
        print_status "Firewall rule added for port $PORT"
    else
        print_warning "UFW not found. Please manually configure your firewall to allow port $PORT"
    fi
}

test_installation() {
    print_status "Testing installation..."
    
    # Start service
    systemctl start "$SERVICE_NAME"
    
    # Wait for service to start
    sleep 3
    
    # Check if service is running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Service is running successfully"
        print_status "Access the web interface at: http://localhost:$PORT"
        print_status "Default login: admin / admin123"
        print_warning "Please change the default password immediately!"
    else
        print_error "Service failed to start. Check logs with: journalctl -u $SERVICE_NAME -f"
        exit 1
    fi
}

show_next_steps() {
    echo ""
    print_status "Installation completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Access the web interface: http://localhost:$PORT"
    echo "2. Login with: admin / admin123"
    echo "3. Change the default password immediately"
    echo "4. Configure your network interfaces"
    echo "5. Install ZeroTier if needed: curl -s https://install.zerotier.com | sudo bash"
    echo ""
    echo "Service management:"
    echo "  Start: sudo systemctl start $SERVICE_NAME"
    echo "  Stop: sudo systemctl stop $SERVICE_NAME"
    echo "  Status: sudo systemctl status $SERVICE_NAME"
    echo "  Logs: sudo journalctl -u $SERVICE_NAME -f"
    echo ""
}

main() {
    echo "IoT Gateway Management Setup"
    echo "============================"
    echo ""
    
    check_root
    check_dependencies
    install_application
    create_service
    configure_firewall
    test_installation
    show_next_steps
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: sudo ./setup.sh"
        echo ""
        echo "This script will:"
        echo "- Check dependencies"
        echo "- Install the application"
        echo "- Create systemd service"
        echo "- Configure firewall"
        echo "- Test the installation"
        exit 0
        ;;
    --uninstall)
        print_status "Uninstalling IoT Gateway..."
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
        rm -rf "$INSTALL_DIR"
        print_status "Uninstallation completed"
        exit 0
        ;;
    *)
        main
        ;;
esac