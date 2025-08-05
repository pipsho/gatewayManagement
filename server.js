const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const { exec, execSync } = require('child_process');
const os = require('os');

// Database setup
const db = new Database('./gateway.db');

// Initialize database
db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

db.exec(`CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id)
)`);

db.exec(`CREATE TABLE IF NOT EXISTS network_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_name TEXT NOT NULL,
    config_type TEXT NOT NULL,
    ip_address TEXT,
    subnet_mask TEXT,
    gateway TEXT,
    dns_servers TEXT,
    enabled BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

db.exec(`CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    level TEXT DEFAULT 'info',
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)`);

db.exec(`CREATE TABLE IF NOT EXISTS firmware_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
)`);

db.exec(`CREATE TABLE IF NOT EXISTS update_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    auto_update_enabled BOOLEAN DEFAULT 0,
    update_schedule TEXT DEFAULT 'manual',
    update_source TEXT DEFAULT 'manual',
    custom_update_url TEXT,
    auto_reboot_enabled BOOLEAN DEFAULT 1,
    last_check DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Create default admin user if none exists
const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get();
if (userCount.count === 0) {
    const defaultHash = crypto.createHash('sha256').update('admin123').digest('hex');
    db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run('admin', defaultHash);
}

// Utility functions
function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function logSystemEvent(action, userId = null, level = 'info', details = '') {
    db.prepare("INSERT INTO system_logs (user_id, action, level, details) VALUES (?, ?, ?, ?)").run(userId, action, level, details);
}

function authenticateRequest(req, callback) {
    const cookies = req.headers.cookie || '';
    const sessionMatch = cookies.match(/session=([^;]+)/);
    
    if (!sessionMatch) {
        return callback(false, null);
    }
    
    const sessionId = sessionMatch[1];
    try {
        const row = db.prepare("SELECT user_id FROM sessions WHERE id = ? AND expires_at > datetime('now')").get(sessionId);
        if (row) {
            callback(true, row.user_id);
        } else {
            callback(false, null);
        }
    } catch (err) {
        callback(false, null);
    }
}

// API endpoints
const routes = {
    '/api/auth/login': (req, res) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const { username, password } = JSON.parse(body);
                const hash = hashPassword(password);
                
                const row = db.prepare("SELECT id FROM users WHERE username = ? AND password_hash = ?").get(username, hash);
                if (row) {
                    const sessionId = generateSessionId();
                    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
                    
                    db.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)").run(sessionId, row.id, expiresAt);
                    
                    logSystemEvent('User login', row.id);
                    
                    res.writeHead(200, {
                        'Set-Cookie': `session=${sessionId}; HttpOnly; Path=/; Max-Age=86400`,
                        'Content-Type': 'application/json'
                    });

                    res.end(JSON.stringify({ success: true, user: { id: row.id, username } }));
                } else {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid credentials' }));
                }
            } catch (err) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid request' }));
            }
        });
    },
    
    '/api/auth/logout': (req, res) => {
        if (req.method !== 'POST') {
            res.writeHead(405, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Method not allowed' }));
            return;
        }
        
        authenticateRequest(req, (isAuthenticated, userId) => {
            if (isAuthenticated) {
                const cookies = req.headers.cookie || '';
                const sessionMatch = cookies.match(/session=([^;]+)/);
                if (sessionMatch) {
                    db.prepare("DELETE FROM sessions WHERE id = ?").run(sessionMatch[1]);
                }
                logSystemEvent('User logout', userId);
                res.writeHead(200, {
                    'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0',
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                });
                console.log('Session cookie header set with Max-Age=0.');
                res.end(JSON.stringify({ success: true }));
            } else {
                // If not authenticated, still clear client-side cookie and redirect
                res.writeHead(200, {
                    'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0',
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                });
                console.log('Not authenticated, but sending logout response.');
                res.end(JSON.stringify({ success: true }));
            }
        });
    },
    
    '/api/auth/change-password': (req, res) => {
        authenticateRequest(req, (isAuthenticated, userId) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                try {
                    const { currentPassword, newPassword } = JSON.parse(body);
                    
                    if (!currentPassword || !newPassword) {
                        res.writeHead(400);
                        res.end(JSON.stringify({ error: 'Missing required fields' }));
                        return;
                    }
                    
                    if (newPassword.length < 6) {
                        res.writeHead(400);
                        res.end(JSON.stringify({ error: 'New password must be at least 6 characters' }));
                        return;
                    }
                    
                    try {
                        const row = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(userId);
                        if (!row) {
                            res.writeHead(500);
                            res.end(JSON.stringify({ error: 'User not found' }));
                            return;
                        }
                        
                        const currentHash = crypto.createHash('sha256').update(currentPassword).digest('hex');
                        
                        if (currentHash !== row.password_hash) {
                            res.writeHead(400);
                            res.end(JSON.stringify({ error: 'Current password is incorrect' }));
                            return;
                        }
                        
                        const newHash = crypto.createHash('sha256').update(newPassword).digest('hex');
                        
                        db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, userId);
                        
                        logSystemEvent('Password changed', userId, 'info');
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true, message: 'Password updated successfully' }));
                    } catch (err) {
                        res.writeHead(500);
                        res.end(JSON.stringify({ error: 'Failed to update password' }));
                    }
                } catch (e) {
                    res.writeHead(400);
                    res.end(JSON.stringify({ error: 'Invalid JSON' }));
                }
            });
        });
    },
    
    '/api/auth/me': (req, res) => {
        authenticateRequest(req, (isAuthenticated, userId) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            try {
                const user = db.prepare('SELECT id, username, created_at FROM users WHERE id = ?').get(userId);
                if (!user) {
                    res.writeHead(404);
                    res.end(JSON.stringify({ error: 'User not found' }));
                    return;
                }
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    id: user.id,
                    username: user.username,
                    created_at: user.created_at
                }));
            } catch (err) {
                res.writeHead(500);
                res.end(JSON.stringify({ error: 'Database error' }));
            }
        });
    },
    
    '/api/system/info': (req, res) => {
        authenticateRequest(req, (isAuthenticated) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            const info = {
                hostname: os.hostname(),
                platform: os.platform(),
                arch: os.arch(),
                release: os.release(),
                uptime: os.uptime(),
                load: os.loadavg(),
                memory: {
                    total: os.totalmem(),
                    free: os.freemem(),
                    used: os.totalmem() - os.freemem()
                },
                cpu: os.cpus()[0].model,
                disk: 'N/A'
            };
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(info));
        });
    },
    
    '/api/system/resources': (req, res) => {
        authenticateRequest(req, (isAuthenticated) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            // Get disk usage using df command
            let diskUsage = { total: 0, used: 0, free: 0, percentage: 0 };
            try {
                const dfOutput = execSync('df -h / | tail -1', { encoding: 'utf8' });
                const parts = dfOutput.trim().split(/\s+/);
                if (parts.length >= 5) {
                    diskUsage.total = parts[1];
                    diskUsage.used = parts[2];
                    diskUsage.free = parts[3];
                    diskUsage.percentage = parseFloat(parts[4].replace('%', '')) || 0;
                }
            } catch (error) {
                console.error('Failed to get disk usage:', error);
            }
            
            const resources = {
                cpu: os.loadavg(),
                memory: {
                    total: os.totalmem(),
                    free: os.freemem(),
                    used: os.totalmem() - os.freemem(),
                    percentage: ((os.totalmem() - os.freemem()) / os.totalmem() * 100).toFixed(1)
                },
                storage: {
                    total: diskUsage.total,
                    used: diskUsage.used,
                    free: diskUsage.free,
                    percentage: diskUsage.percentage.toFixed(1)
                }
            };
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(resources));
        });
    },
    
    '/api/network/interfaces': (req, res) => {
        authenticateRequest(req, (isAuthenticated) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            try {
                const output = execSync('ifconfig', { encoding: 'utf8' });
                const interfaces = [];
                const blocks = output.split('\n\n').filter(block => block.trim());
                
                blocks.forEach(block => {
                    const lines = block.split('\n').filter(line => line.trim());
                    if (lines.length === 0) return;
                    
                    const interfaceName = lines[0].split(':')[0];
                    if (interfaceName === 'lo') return;
                    
                    const interfaceInfo = {
                        name: interfaceName,
                        type: interfaceName.startsWith('eth') || interfaceName.startsWith('feth') ? 'ethernet' : 
                              interfaceName.startsWith('wlan') || interfaceName.startsWith('wifi') ? 'wifi' : 
                              interfaceName.startsWith('zt') ? 'zerotier' : 
                              interfaceName.startsWith('en') ? 'ethernet' : 'unknown',
                        mac: '',
                        status: 'down',
                        addresses: []
                    };
                    
                    lines.forEach(line => {
                        line = line.trim();
                        if (line.includes('ether')) {
                            interfaceInfo.mac = line.split(' ')[1];
                        }
                        if (line.includes('inet ')) {
                            const parts = line.split(' ').filter(p => p);
                            interfaceInfo.addresses.push({
                                family: 'IPv4',
                                address: parts[1],
                                netmask: parts[3]
                            });
                            interfaceInfo.status = 'up';
                        }
                        if (line.includes('inet6')) {
                            const parts = line.split(' ').filter(p => p);
                            interfaceInfo.addresses.push({
                                family: 'IPv6',
                                address: parts[1]
                            });
                        }
                    });
                    
                    interfaces.push(interfaceInfo);
                });
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(interfaces));
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Failed to get interfaces' }));
            }
        });
    },
    
    '/api/network/config': (req, res) => {
        authenticateRequest(req, (isAuthenticated) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            if (req.method === 'GET') {
                try {
                    const rows = db.prepare("SELECT * FROM network_configs").all();
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify(rows || []));
                } catch (err) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Database error' }));
                }
            } else if (req.method === 'POST') {
                let body = '';
                req.on('data', chunk => body += chunk);
                req.on('end', () => {
                    const config = JSON.parse(body);
                    try {
                        const stmt = db.prepare(`INSERT INTO network_configs 
                               (interface_name, config_type, ip_address, subnet_mask, gateway, dns_servers, enabled) 
                               VALUES (?, ?, ?, ?, ?, ?, ?)`);
                        const result = stmt.run(config.interface_name, config.config_type, config.ip_address, 
                                config.subnet_mask, config.gateway, config.dns_servers, config.enabled);
                        
                        logSystemEvent('Network config updated', null, 'info', 
                                     `Interface: ${config.interface_name}`);
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ id: result.lastInsertRowid }));
                    } catch (err) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Failed to save config' }));
                    }
                });
            }
        });
    },
    
    '/api/zerotier/status': (req, res) => {
        authenticateRequest(req, (isAuthenticated) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            exec('zerotier-cli listnetworks -j', (error, stdout) => {
                if (error) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'ZeroTier not available' }));
                    return;
                }
                
                try {
                    const networks = JSON.parse(stdout);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify(networks));
                } catch (e) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify([]));
                }
            });
        });
    },
    
    '/api/zerotier/join': (req, res) => {
        authenticateRequest(req, (isAuthenticated, userId) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                const { networkId } = JSON.parse(body);
                
                exec(`zerotier-cli join ${networkId}`, (error, stdout) => {
                    if (error) {
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Failed to join network' }));
                    } else {
                        logSystemEvent('ZeroTier join', userId, 'info', `Network: ${networkId}`);
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true, message: stdout }));
                    }
                });
            });
        });
    },
    
    '/api/zerotier/leave': (req, res) => {
        authenticateRequest(req, (isAuthenticated, userId) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                const { networkId } = JSON.parse(body);
                
                exec(`zerotier-cli leave ${networkId}`, (error, stdout) => {
                    if (error) {
                        res.writeHead(500, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Failed to leave network' }));
                    } else {
                        logSystemEvent('ZeroTier leave', userId, 'info', `Network: ${networkId}`);
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true, message: stdout }));
                    }
                });
            });
        });
    },
    
    '/api/diagnostics/ping': (req, res) => {
        authenticateRequest(req, (isAuthenticated, userId) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                const { target, interface: interfaceName, count = 4 } = JSON.parse(body);
                
                const pingCmd = interfaceName 
                    ? `ping -I ${interfaceName} -c ${count} ${target}`
                    : `ping -c ${count} ${target}`;
                
                exec(pingCmd, (error, stdout, stderr) => {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        success: !error,
                        output: stdout + stderr,
                        target
                    }));
                });
            });
        });
    },
    
    '/api/system/logs': (req, res) => {
        authenticateRequest(req, (isAuthenticated) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            try {
                const rows = db.prepare(`SELECT sl.*, u.username 
                       FROM system_logs sl 
                       LEFT JOIN users u ON sl.user_id = u.id 
                       ORDER BY sl.created_at DESC 
                       LIMIT 100`).all();
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ logs: rows || [] }));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Database error' }));
            }
        });
    },
    
    '/api/system/reboot': (req, res) => {
        authenticateRequest(req, (isAuthenticated, userId) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            logSystemEvent('System reboot', userId, 'warn');
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true }));
            
            setTimeout(() => {
                exec('reboot', () => {});
            }, 2000);
        });
    },
    
    '/api/firmware/upload': (req, res) => {
        authenticateRequest(req, (isAuthenticated, userId) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            // Simple firmware upload simulation
            const boundary = req.headers['content-type']?.split('boundary=')[1];
            if (!boundary) {
                res.writeHead(400);
                res.end(JSON.stringify({ error: 'Invalid upload' }));
                return;
            }
            
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                // Parse multipart form data (simplified)
                const filename = body.match(/filename="([^"]+)"/)[1];
                const version = filename.match(/(\d+\.\d+\.\d+)/)?.[1] || '1.0.0';
                
                try {
                    const result = db.prepare("INSERT INTO firmware_updates (filename, version) VALUES (?, ?)").run(filename, version);
                    logSystemEvent('Firmware uploaded', userId, 'info', filename);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: true, 
                        updateId: result.lastInsertRowid,
                        version 
                    }));
                } catch (err) {
                    res.writeHead(500);
                    res.end(JSON.stringify({ error: 'Upload failed' }));
                }
            });
        });
    },
    
    '/api/firmware/status': (req, res) => {
        authenticateRequest(req, (isAuthenticated) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            try {
                const row = db.prepare("SELECT * FROM firmware_updates ORDER BY created_at DESC LIMIT 1").get();
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(row || {}));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Database error' }));
            }
        });
    },
    
    '/api/firmware/settings': (req, res) => {
        authenticateRequest(req, (isAuthenticated, userId) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            if (req.method === 'GET') {
                try {
                    const row = db.prepare("SELECT * FROM update_settings ORDER BY id DESC LIMIT 1").get();
                    if (!row) {
                        // Return default settings if none exist
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({
                            auto_update_enabled: false,
                            update_schedule: 'manual',
                            update_source: 'manual',
                            custom_update_url: '',
                            auto_reboot_enabled: true
                        }));
                    } else {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify(row));
                    }
                } catch (err) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Database error' }));
                }
            } else if (req.method === 'POST') {
                let body = '';
                req.on('data', chunk => body += chunk);
                req.on('end', () => {
                    const settings = JSON.parse(body);
                    
                    try {
                        db.prepare(`INSERT OR REPLACE INTO update_settings 
                               (id, auto_update_enabled, update_schedule, update_source, 
                                custom_update_url, auto_reboot_enabled, updated_at) 
                               VALUES ((SELECT id FROM update_settings LIMIT 1), ?, ?, ?, ?, ?, datetime('now'))`)
                          .run(
                               settings.auto_update_enabled ? 1 : 0,
                               settings.update_schedule || 'weekly',
                               settings.update_source || 'official',
                               settings.custom_update_url || null,
                               settings.auto_reboot_enabled ? 1 : 0
                           );
                        
                        logSystemEvent('Update settings changed', userId, 'info', 
                                     JSON.stringify(settings));
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: true }));
                    } catch (err) {
                        res.writeHead(500);
                        res.end(JSON.stringify({ error: 'Failed to save settings' }));
                    }
                });
            }
        });
    },
    
    '/api/firmware/history': (req, res) => {
        authenticateRequest(req, (isAuthenticated) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            try {
                const rows = db.prepare("SELECT * FROM firmware_updates ORDER BY created_at DESC LIMIT 10").all();
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ history: rows || [] }));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Database error' }));
            }
        });
    },
    
    '/api/system/about': (req, res) => {
        authenticateRequest(req, (isAuthenticated) => {
            if (!isAuthenticated) {
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            
            const aboutInfo = {
                hostname: os.hostname(),
                version: '1.0.0',
                website: 'www.epithos.com',
                support: {
                    line: '@epithos',
                    email: 'global@epithos.com'
                }
            };
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(aboutInfo));
        });
    }
};

// Static file serving
function serveStaticFile(req, res) {
    const parsedUrl = url.parse(req.url);
    let pathname = parsedUrl.pathname;
    
    if (pathname === '/') pathname = '/index.html';
    
    const ext = path.extname(pathname);
    const mimeTypes = {
        '.html': 'text/html',
        '.js': 'text/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpg',
        '.gif': 'image/gif',
        '.svg': 'image/svg+xml'
    };
    
    const filePath = path.join(__dirname, 'public', pathname);
    
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(404);
            res.end('File not found');
        } else {
            res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
            res.end(data);
        }
    });
}

// Authentication-aware static file serving
function serveProtectedFile(req, res) {
    const parsedUrl = url.parse(req.url);
    let pathname = parsedUrl.pathname;
    
    if (pathname === '/') pathname = '/index.html';
    
    // Always serve login.html for root if not authenticated
    if (pathname === '/index.html') {
        authenticateRequest(req, (isAuthenticated) => {
            if (!isAuthenticated) {
                // Serve login page for unauthenticated users
                const loginPath = path.join(__dirname, 'public', 'login.html');
                fs.readFile(loginPath, (err, data) => {
                    if (err) {
                        // If login.html doesn't exist, serve index.html but with auth check
                        const filePath = path.join(__dirname, 'public', 'index.html');
                        fs.readFile(filePath, (err, data) => {
                            if (err) {
                                res.writeHead(404);
                                res.end('File not found');
                            } else {
                                res.writeHead(200, { 'Content-Type': 'text/html' });
                                res.end(data);
                            }
                        });
                    } else {
                        res.writeHead(200, { 'Content-Type': 'text/html' });
                        res.end(data);
                    }
                });
                return;
            }
            
            // Serve dashboard for authenticated users
            const filePath = path.join(__dirname, 'public', pathname);
            const ext = path.extname(pathname);
            const mimeTypes = {
                '.html': 'text/html',
                '.js': 'text/javascript',
                '.css': 'text/css',
                '.json': 'application/json',
                '.png': 'image/png',
                '.jpg': 'image/jpg',
                '.gif': 'image/gif',
                '.svg': 'image/svg+xml'
            };
            
            fs.readFile(filePath, (err, data) => {
                if (err) {
                    res.writeHead(404);
                    res.end('File not found');
                } else {
                    res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
                    res.end(data);
                }
            });
        });
        return;
    }
    
    // For non-root paths, use regular static serving
    serveStaticFile(req, res);
}

// Main server
const server = http.createServer((req, res) => {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }
    
    const parsedUrl = url.parse(req.url, true);
    
    if (routes[parsedUrl.pathname]) {
        routes[parsedUrl.pathname](req, res);
    } else if (req.url.startsWith('/api/')) {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'API endpoint not found' }));
    } else if (parsedUrl.pathname === '/' || parsedUrl.pathname === '/index.html') {
        // Protect the main dashboard page
        serveProtectedFile(req, res);
    } else {
        serveStaticFile(req, res);
    }
});

const PORT = process.env.PORT || 80;
server.listen(PORT, () => {
    console.log(`IoT Gateway server running on port ${PORT}`);
    logSystemEvent('Server started', null, 'info', `Port: ${PORT}`);
});