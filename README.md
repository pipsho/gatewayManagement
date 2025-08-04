# IoT Gateway Management System

A lightweight, efficient web application for managing industrial IoT gateways. Designed for low-resource environments with a focus on simplicity and reliability.

## Features

### Core Functionality
- **User Authentication**: Secure login/logout with password hashing
- **System Monitoring**: Real-time CPU, memory, and system status
- **Network Management**: Configure Cellular, LAN, and WiFi interfaces
- **ZeroTier Integration**: Join/leave ZeroTier networks
- **Network Diagnostics**: Built-in ping testing with interface selection
- **Firmware Updates**: Web-based firmware upload and installation
- **Activity Logging**: Comprehensive audit trail of user actions

### Technical Highlights
- **Ultra-lightweight**: Optimized for ARM processors with 256MB RAM
- **Zero Dependencies**: Pure Node.js implementation (only SQLite3)
- **Responsive Design**: Works on desktop and tablet browsers
- **Real-time Updates**: Automatic refresh of system metrics
- **Security First**: Input validation and session management

## System Requirements

### Hardware
- **Processor**: Single-core ARM (or x86)
- **Memory**: 256MB RAM minimum
- **Storage**: 512MB available space
- **Network**: Ethernet/WiFi connectivity

### Software
- **OS**: Ubuntu 24.04 (or compatible Linux)
- **Node.js**: v14.0.0 or higher
- **SQLite3**: Included via npm
- **System Tools**: `ifconfig`, `ping`, `zerotier-cli` (optional)

## Installation

### 1. Install Dependencies
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Node.js (if not already installed)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install ZeroTier (optional, for ZeroTier functionality)
curl -s https://install.zerotier.com | sudo bash
```

### 2. Deploy Application
```bash
# Create application directory
sudo mkdir -p /opt/iot-gateway
cd /opt/iot-gateway

# Copy application files
sudo cp -r /path/to/application/* .

# Install Node.js dependencies
sudo npm install --production

# Set proper permissions
sudo chown -R www-data:www-data /opt/iot-gateway
sudo chmod 755 /opt/iot-gateway
sudo chmod 644 /opt/iot-gateway/*
sudo chmod 755 /opt/iot-gateway/server.js
```

### 3. Configure as System Service
```bash
# Create systemd service file
sudo tee /etc/systemd/system/iot-gateway.service > /dev/null <<EOF
[Unit]
Description=IoT Gateway Management System
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/iot-gateway
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable iot-gateway
sudo systemctl start iot-gateway
```

### 4. Configure Firewall (if needed)
```bash
# Allow HTTP traffic
sudo ufw allow 3000/tcp

# Or configure nginx reverse proxy
sudo apt install nginx
sudo tee /etc/nginx/sites-available/iot-gateway > /dev/null <<EOF
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/iot-gateway /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx
```

## Usage

### First Login
1. Open browser to `http://localhost:3000` (or your configured domain)
2. Login with default credentials:
   - **Username**: admin
   - **Password**: admin123
3. **IMPORTANT**: Change the default password immediately

### Dashboard Overview
- **Overview**: System status, resource usage, recent activity
- **Network**: Interface configuration and status monitoring
- **ZeroTier**: Virtual network management (requires ZeroTier)
- **Diagnostics**: Network testing tools
- **Settings**: Firmware updates and system controls

### Network Configuration
1. Navigate to **Network** section
2. Select interface from dropdown
3. Choose DHCP or Static IP configuration
4. For static IP, enter:
   - IP Address (e.g., 192.168.1.100)
   - Subnet Mask (e.g., 255.255.255.0)
   - Gateway (e.g., 192.168.1.1)
   - DNS Servers (comma-separated)
5. Click "Save Configuration"

### ZeroTier Setup
1. Install ZeroTier: `curl -s https://install.zerotier.com | sudo bash`
2. Join network: Enter Network ID and click "Join Network"
3. Manage networks: View status and leave networks as needed

### Firmware Updates
1. Navigate to **Settings** section
2. Click "Choose File" and select firmware file
3. Click "Upload & Update"
4. Monitor progress bar during update
5. System will automatically reboot after update

## Security Considerations

### Password Security
- Change default password immediately
- Use strong passwords (minimum 12 characters)
- Consider implementing 2FA for production use

### Network Security
- Use HTTPS in production (configure reverse proxy)
- Restrict access via firewall rules
- Consider VPN access for remote management

### File Permissions
```bash
# Secure the application directory
sudo chmod 750 /opt/iot-gateway
sudo chmod 640 /opt/iot-gateway/gateway.db
sudo chmod 644 /opt/iot-gateway/server.js
sudo chmod 755 /opt/iot-gateway/public
```

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check service status
sudo systemctl status iot-gateway

# Check logs
sudo journalctl -u iot-gateway -f

# Check Node.js
node --version
```

#### Database Issues
```bash
# Reset database (backup first!)
sudo systemctl stop iot-gateway
sudo rm /opt/iot-gateway/gateway.db
sudo systemctl start iot-gateway
```

#### Network Interface Not Found
```bash
# Check available interfaces
ip addr show
# or
ifconfig -a

# Update interface names in configuration
```

#### ZeroTier Not Available
```bash
# Check ZeroTier status
sudo zerotier-cli info

# Start ZeroTier service
sudo systemctl start zerotier-one
sudo systemctl enable zerotier-one
```

### Log Files
- **Application Logs**: Check browser console for frontend issues
- **System Logs**: `sudo journalctl -u iot-gateway -f`
- **Database Logs**: Located in application directory

## Performance Optimization

### Memory Usage
- Application uses ~50MB RAM at idle
- Database cleanup runs automatically
- Consider increasing Node.js memory for large deployments

### CPU Optimization
- Real-time updates every 5 seconds (configurable)
- Network interface scanning on demand
- Efficient SQLite queries with proper indexing

### Storage
- Database grows slowly (~1MB per 1000 log entries)
- Automatic log rotation (keep last 1000 entries)
- Firmware files are temporary and auto-cleaned

## API Reference

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout

### System
- `GET /api/system/info` - System information
- `GET /api/system/resources` - Resource usage
- `GET /api/system/logs` - Activity logs
- `POST /api/system/reboot` - System reboot

### Network
- `GET /api/network/interfaces` - List interfaces
- `GET /api/network/config` - Get configurations
- `POST /api/network/config` - Save configuration

### ZeroTier
- `GET /api/zerotier/status` - Network status
- `POST /api/zerotier/join` - Join network
- `POST /api/zerotier/leave` - Leave network

### Diagnostics
- `POST /api/diagnostics/ping` - Ping test

### Firmware
- `POST /api/firmware/upload` - Upload firmware
- `GET /api/firmware/status` - Update status

## Development

### Local Development
```bash
# Clone repository
git clone <repository-url>
cd iot-gateway-management

# Install dependencies
npm install

# Start development server
npm run dev
```

### Testing
```bash
# Run basic connectivity tests
node -e "console.log('Node.js:', process.version)"
sqlite3 --version

# Test API endpoints
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

## Support

### Documentation
- This README file
- Inline code comments
- API endpoint documentation above

### Getting Help
1. Check troubleshooting section above
2. Review system logs
3. Test API endpoints manually
4. Check browser developer tools

### Contributing
- Fork the repository
- Create feature branch
- Test on target hardware
- Submit pull request with clear description

## License

MIT License - see LICENSE file for details.

## Version History

- **v1.0.0** - Initial release
  - Basic authentication and user management
  - System monitoring and resource tracking
  - Network interface configuration
  - ZeroTier network management
  - Firmware update system
  - Responsive web interface

---

**Note**: This application is designed for industrial IoT environments. Always test thoroughly in your specific environment before production deployment.