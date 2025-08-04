// API Configuration
const API_BASE = '/api';

// Global state
let currentUser = null;
let updateInterval = null;

// Utility functions
function showScreen(screenId) {
    console.log('Showing screen:', screenId);
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    const targetScreen = document.getElementById(screenId);
    if (targetScreen) {
        targetScreen.classList.add('active');
        console.log('Screen activated:', screenId);
    } else {
        console.error('Screen not found:', screenId);
    }
}

function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    document.getElementById(sectionId).classList.add('active');
    
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-section="${sectionId.replace('-section', '')}"]`).classList.add('active');
    
    // Set default tabs for Network and Settings sections
    if (sectionId === 'network-section') {
        const firstTab = document.querySelector('#network-section .tab-btn');
        if (firstTab) {
            firstTab.click();
        }
    } else if (sectionId === 'settings-section') {
        const firstTab = document.querySelector('#settings-section .tab-btn');
        if (firstTab) {
            firstTab.click();
        }
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) {
        return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else {
        return `${minutes}m`;
    }
}

function showError(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = message;
        element.style.display = 'block';
        setTimeout(() => {
            element.style.display = 'none';
        }, 5000);
    }
}

function showSuccess(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = message;
        element.className = 'success-message';
        element.style.display = 'block';
        setTimeout(() => {
            element.style.display = 'none';
        }, 3000);
    }
}

// API functions
async function apiCall(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const config = {
        credentials: 'include', // Include cookies for session
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        cache: 'no-store',
        ...options
    };

    try {
        const response = await fetch(url, config);
        if (!response.ok) {
            if (response.status === 401) {
                console.log('Received 401, forcing login');
                showScreen('login-screen');
                throw new Error('Unauthorized');
            }
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return await response.json();
    } catch (error) {
        if (error.message === 'Unauthorized') {
            throw error;
        }
        console.error('API call failed:', error);
        throw error;
    }
}

// Authentication
async function login(username, password) {
    try {
        const response = await apiCall('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        
        if (response.success) {
            currentUser = response.user;
            document.getElementById('username-display').textContent = currentUser.username;
            showScreen('dashboard-screen');
            showSection('overview-section');
            startAutoUpdate();
            loadAllData();
        }
        return response;
    } catch (error) {
        throw error;
    }
}

async function logout() {
    console.log('Logout initiated - proper server logout then redirect');
    
    // Stop all background processes immediately
    stopAutoUpdate();
    
    // Clear client-side data
    currentUser = null;
    localStorage.clear();
    sessionStorage.clear();
    
    try {
        // Force server logout - wait for completion
        console.log('Calling server logout...');
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
        
        const response = await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include',
            cache: 'no-store',
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
            console.log('Server logout successful');
            const result = await response.json();
            console.log('Logout response:', result);
        } else {
            console.log('Server logout failed with status:', response.status);
        }
    } catch (error) {
        if (error.name === 'AbortError') {
            console.log('Logout request timed out, continuing...');
        } else {
            console.log('Server logout error:', error.message);
        }
    }
    
    // Force redirect after ensuring session is cleared
    console.log('Redirecting to login...');
    // Use a longer delay to ensure the request completes
    setTimeout(() => {
        window.location.replace('/');
    }, 500);
}

// Data loading functions
async function loadSystemInfo() {
    try {
        const info = await apiCall('/system/info');
        document.getElementById('hostname').textContent = info.hostname;
        document.getElementById('uptime').textContent = formatUptime(info.uptime);
        document.getElementById('platform').textContent = `${info.platform} ${info.arch}`;
    } catch (error) {
        console.error('Failed to load system info:', error);
    }
}

async function loadResources() {
    try {
        const resources = await apiCall('/system/resources');
        
        const cpuUsage = Math.round(resources.cpu?.[0] || 0);
        document.getElementById('cpu-usage').textContent = `${cpuUsage}%`;
        document.getElementById('cpu-bar').style.width = `${cpuUsage}%`;
        
        const memoryPercentage = parseFloat(resources.memory?.percentage || 0);
        document.getElementById('memory-usage').textContent = `${memoryPercentage}%`;
        document.getElementById('memory-bar').style.width = `${memoryPercentage}%`;
        
        const storagePercentage = parseFloat(resources.storage?.percentage || 0);
        document.getElementById('storage-usage').textContent = `${storagePercentage}%`;
        document.getElementById('storage-bar').style.width = `${storagePercentage}%`;
    } catch (error) {
        console.error('Failed to load resources:', error);
    }
}

async function loadRecentLogs() {
    try {
        const response = await apiCall('/system/logs');
        const logsContainer = document.getElementById('recent-logs');
        
        if (response.logs && response.logs.length > 0) {
            logsContainer.innerHTML = '';
            response.logs.slice(0, 5).forEach(log => {
                const logDiv = document.createElement('div');
                logDiv.className = `log-entry level-${log.level || 'info'}`;
                logDiv.innerHTML = `
                    <div class="timestamp">${new Date(log.created_at).toLocaleString()}</div>
                    <div class="action">${log.action}</div>
                `;
                logsContainer.appendChild(logDiv);
            });
        }
    } catch (error) {
        console.error('Failed to load logs:', error);
    }
}

async function loadNetworkInterfaces() {
    try {
        const interfaces = await apiCall('/network/interfaces');
        
        // Categorize interfaces by type
        const lanInterfaces = interfaces.filter(iface => 
            iface.type.toLowerCase().includes('ethernet') || 
            iface.type.toLowerCase().includes('lan') ||
            iface.name.toLowerCase().includes('eth') ||
            iface.name.toLowerCase().includes('enp')
        );
        
        const cellularInterfaces = interfaces.filter(iface => 
            iface.type.toLowerCase().includes('wwan') ||
            iface.type.toLowerCase().includes('cellular') ||
            iface.name.toLowerCase().includes('wwan') ||
            iface.name.toLowerCase().includes('cellular') ||
            iface.name.toLowerCase().includes('usb') ||
            iface.name.toLowerCase().includes('cdc')
        );
        
        const wifiInterfaces = interfaces.filter(iface => 
            iface.type.toLowerCase().includes('wireless') || 
            iface.type.toLowerCase().includes('wifi') ||
            iface.name.toLowerCase().includes('wlan') ||
            iface.name.toLowerCase().includes('wlp')
        );
        
        // Update tabbed interfaces
        updateTabInterfaces('lan-interfaces', lanInterfaces);
        updateTabInterfaces('cellular-interfaces', cellularInterfaces);
        updateTabInterfaces('wifi-interfaces', wifiInterfaces);
        
        // Update interface select dropdowns, excluding WWAN from configuration
        const select = document.getElementById('interface-select');
        const pingInterface = document.getElementById('ping-interface');
        
        // For configuration dropdown, exclude Cellular interfaces
        select.innerHTML = '<option value="">Select interface...</option>';
        interfaces.filter(iface => 
            !iface.type.toLowerCase().includes('wwan') &&
            !iface.type.toLowerCase().includes('cellular') &&
            !iface.name.toLowerCase().includes('wwan') &&
            !iface.name.toLowerCase().includes('cellular') &&
            !iface.name.toLowerCase().includes('usb') &&
            !iface.name.toLowerCase().includes('cdc')
        ).forEach(iface => {
            const option = document.createElement('option');
            option.value = iface.name;
            option.textContent = `${iface.name} (${iface.type})`;
            select.appendChild(option);
        });
        
        // For ping dropdown, include all interfaces
        pingInterface.innerHTML = '<option value="">Auto</option>';
        interfaces.forEach(iface => {
            const option = document.createElement('option');
            option.value = iface.name;
            option.textContent = `${iface.name} (${iface.type})`;
            pingInterface.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load network interfaces:', error);
    }
}

function updateTabInterfaces(containerId, interfaces) {
    const container = document.getElementById(containerId);
    
    if (interfaces.length === 0) {
        container.innerHTML = '<div class="placeholder">No interfaces found</div>';
        return;
    }
    
    container.innerHTML = '';
    interfaces.forEach(iface => {
        const div = document.createElement('div');
        div.className = `interface-item ${iface.status}`;
        div.innerHTML = `
            <div class="interface-header">
                <span class="interface-name">${iface.name}</span>
                <span class="interface-status ${iface.status}">${iface.status}</span>
            </div>
            <div class="interface-details">
                <div>Type: ${iface.type}</div>
                <div>MAC: ${iface.mac}</div>
                <div class="interface-addresses">
                    ${iface.addresses.map(addr => `
                        <div class="address-item">${addr.family}: ${addr.address}</div>
                    `).join('')}
                </div>
            </div>
        `;
        container.appendChild(div);
    });
}

async function loadZeroTierNetworks() {
    try {
        const networks = await apiCall('/zerotier/status');
        
        const container = document.getElementById('zerotier-networks');
        container.innerHTML = '';
        
        if (networks.length === 0) {
            container.innerHTML = '<div class="placeholder">No ZeroTier networks connected</div>';
            return;
        }
        
        networks.forEach(network => {
            const div = document.createElement('div');
            div.className = 'network-item';
            div.innerHTML = `
                <div><strong>${network.name || 'Unnamed Network'}</strong></div>
                <div>Network ID: ${network.nwid}</div>
                <div>Status: ${network.status}</div>
                <div>Addresses: ${network.assignedAddresses.join(', ')}</div>
                <button class="btn btn-secondary" onclick="leaveZeroTierNetwork('${network.nwid}')">Leave</button>
            `;
            container.appendChild(div);
        });
    } catch (error) {
        console.error('Failed to load ZeroTier networks:', error);
        document.getElementById('zerotier-networks').innerHTML = 
            '<div class="placeholder">ZeroTier not available</div>';
    }
}

// Form handlers (login form removed - handled by separate login.html)



// Navigation
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const section = btn.dataset.section;
        showSection(`${section}-section`);
    });
});

// Network tab functionality
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
        const tabName = e.target.dataset.tab;
        
        // Remove active class from all tabs and panels
        document.querySelectorAll('.tab-btn').forEach(tab => tab.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
        
        // Add active class to clicked tab and corresponding panel
        e.target.classList.add('active');
        document.getElementById(`${tabName}-tab`).classList.add('active');
        
        // Show/hide Configure Interface container based on tab
        const configureContainer = document.getElementById('configure-interface-container');
        if (configureContainer) {
            const visibleTabs = configureContainer.dataset.visibleTabs.split(',');
            if (visibleTabs.includes(tabName)) {
                configureContainer.style.display = 'block';
            } else {
                configureContainer.style.display = 'none';
            }
        }
    });
});

// Interface configuration
document.getElementById('config-type').addEventListener('change', (e) => {
    const staticConfig = document.getElementById('static-config');
    if (e.target.value === 'static') {
        staticConfig.classList.add('show');
    } else {
        staticConfig.classList.remove('show');
    }
});

document.getElementById('interface-config-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const config = {
        interface_name: document.getElementById('interface-select').value,
        config_type: document.getElementById('config-type').value,
        ip_address: document.getElementById('ip-address').value || null,
        subnet_mask: document.getElementById('subnet-mask').value || null,
        gateway: document.getElementById('gateway').value || null,
        dns_servers: document.getElementById('dns-servers').value || null,
        enabled: document.getElementById('interface-enabled').checked
    };
    
    try {
        await apiCall('/network/config', {
            method: 'POST',
            body: JSON.stringify(config)
        });
        
        showSuccess('interface-config-form', 'Configuration saved successfully');
        loadNetworkInterfaces();
    } catch (error) {
        showError('interface-config-form', 'Failed to save configuration');
    }
});

// ZeroTier management
async function joinZeroTierNetwork() {
    const networkId = document.getElementById('network-id').value;
    if (!networkId) return;
    
    try {
        await apiCall('/zerotier/join', {
            method: 'POST',
            body: JSON.stringify({ networkId })
        });
        
        showSuccess('join-network-form', 'Successfully joined network');
        document.getElementById('join-network-form').reset();
        loadZeroTierNetworks();
    } catch (error) {
        showError('join-network-form', 'Failed to join network');
    }
}

async function leaveZeroTierNetwork(networkId) {
    if (!confirm('Are you sure you want to leave this network?')) return;
    
    try {
        await apiCall('/zerotier/leave', {
            method: 'POST',
            body: JSON.stringify({ networkId })
        });
        
        loadZeroTierNetworks();
    } catch (error) {
        alert('Failed to leave network');
    }
}

document.getElementById('join-network-form').addEventListener('submit', (e) => {
    e.preventDefault();
    joinZeroTierNetwork();
});

// Ping diagnostics
document.getElementById('ping-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const target = document.getElementById('ping-target').value;
    const interfaceName = document.getElementById('ping-interface').value;
    const count = document.getElementById('ping-count').value;
    
    const resultsContainer = document.getElementById('ping-results');
    resultsContainer.innerHTML = '<div class="loading">Running ping test...</div>';
    
    try {
        const result = await apiCall('/diagnostics/ping', {
            method: 'POST',
            body: JSON.stringify({ target, interface: interfaceName, count })
        });
        
        resultsContainer.textContent = result.output;
    } catch (error) {
        resultsContainer.textContent = 'Ping test failed';
    }
});

// Firmware update settings




// Firmware update
document.getElementById('firmware-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const fileInput = document.getElementById('firmware-file');
    const file = fileInput.files[0];
    if (!file) return;
    
    const formData = new FormData();
    formData.append('firmware', file);
    
    document.getElementById('update-progress').style.display = 'block';
    
    try {
        const response = await fetch('/api/firmware/upload', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        if (result.success) {
            showSuccess('firmware-form', 'Firmware uploaded successfully');
            monitorUpdateProgress(result.updateId);
            loadUpdateHistory(); // Refresh history
        }
    } catch (error) {
        showError('firmware-form', 'Firmware upload failed');
    }
});

async function monitorUpdateProgress(updateId) {
    const interval = setInterval(async () => {
        try {
            const status = await apiCall('/firmware/status');
            const progress = status.progress || 0;
            
            document.getElementById('update-bar').style.width = `${progress}%`;
            document.getElementById('update-status').textContent = 
                `Updating... ${progress}%`;
            
            if (status.status === 'completed') {
                clearInterval(interval);
                document.getElementById('update-status').textContent = 'Update completed';
                setTimeout(() => {
                    document.getElementById('update-progress').style.display = 'none';
                }, 3000);
            }
        } catch (error) {
            clearInterval(interval);
            document.getElementById('update-status').textContent = 'Update failed';
        }
    }, 1000);
}

// Password change
async function changePassword() {
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    
    if (!currentPassword || !newPassword || !confirmPassword) {
        showError('password-form', 'Please fill in all fields');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showError('password-form', 'New passwords do not match');
        return;
    }
    
    if (newPassword.length < 6) {
        showError('password-form', 'New password must be at least 6 characters');
        return;
    }
    
    try {
        await apiCall('/auth/change-password', {
            method: 'POST',
            body: JSON.stringify({
                currentPassword,
                newPassword
            })
        });
        
        showSuccess('password-form', 'Password changed successfully');
        document.getElementById('password-form').reset();
    } catch (error) {
        showError('password-form', 'Failed to change password');
    }
}

document.getElementById('password-form').addEventListener('submit', (e) => {
    e.preventDefault();
    changePassword();
});

// System reboot
document.getElementById('reboot-btn').addEventListener('click', async () => {
    if (!confirm('Are you sure you want to reboot the system?')) return;
    
    try {
        await apiCall('/system/reboot', { method: 'POST' });
        alert('System is rebooting...');
        logout();
    } catch (error) {
        alert('Failed to reboot system');
    }
});

// Auto-update functions
function startAutoUpdate() {
    updateInterval = setInterval(() => {
        loadResources();
        loadRecentLogs();
    }, 5000);
}

function stopAutoUpdate() {
    if (updateInterval) {
        clearInterval(updateInterval);
        updateInterval = null;
    }
}

function loadAllData() {
    loadSystemInfo();
    loadResources();
    loadRecentLogs();
    loadNetworkInterfaces();
    loadZeroTierNetworks();
    loadNetworkConnections();
  
    
    // Initialize Configure Interface visibility based on active tab
    const activeTab = document.querySelector('.tab-btn.active');
    if (activeTab) {
        const tabName = activeTab.dataset.tab;
        const configureContainer = document.getElementById('configure-interface-container');
        if (configureContainer) {
            const visibleTabs = configureContainer.dataset.visibleTabs.split(',');
            if (visibleTabs.includes(tabName)) {
                configureContainer.style.display = 'block';
            } else {
                configureContainer.style.display = 'none';
            }
        }
    }
}

async function loadNetworkConnections() {
    try {
        const interfaces = await apiCall('/network/interfaces');
        const container = document.getElementById('network-connections');
        
        if (interfaces.length === 0) {
            container.innerHTML = '<div class="placeholder">No network interfaces found</div>';
            return;
        }
        
        container.innerHTML = '';
        interfaces.forEach(iface => {
            const div = document.createElement('div');
            div.className = `interface-item ${iface.status}`;
            
            // Get primary IP address
            const primaryIP = iface.addresses.find(addr => addr.family === 'IPv4') || 
                             iface.addresses.find(addr => addr.family === 'IPv6') || 
                             { address: 'No IP assigned' };
            
            // Status indicator (green for up, red for down)
            const statusColor = iface.status === 'up' ? '#22c55e' : '#ef4444';
            const statusText = iface.status === 'up' ? 'Connected' : 'Disconnected';
            
            div.innerHTML = `
                <div class="interface-header">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span class="interface-name">${iface.name}</span>
                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: ${statusColor};" title="${statusText}"></span>
                    </div>
                    <span class="interface-status ${iface.status}">${iface.status}</span>
                </div>
                <div class="interface-details">
                    <div>Type: ${iface.type}</div>
                    <div>IP: ${primaryIP.address}</div>
                    ${iface.addresses.length > 1 ? `<div>Additional: ${iface.addresses.length - 1} more</div>` : ''}
                </div>
            `;
            container.appendChild(div);
        });
    } catch (error) {
        console.error('Failed to load network connections:', error);
        document.getElementById('network-connections').innerHTML = 
            '<div class="placeholder">Failed to load network interfaces</div>';
    }
}

// Simple showScreen without authentication check (server handles auth)
function showScreen(screenId) {
    const screens = document.querySelectorAll('.screen');
    screens.forEach(screen => {
        screen.classList.remove('active');
    });
    
    const targetScreen = document.getElementById(screenId);
    if (targetScreen) {
        targetScreen.classList.add('active');
    }
}

// Initialize dashboard (server ensures authentication)
document.addEventListener('DOMContentLoaded', () => {
    // Make logout globally available for testing
    window.testLogout = logout;
    
    // Set up logout button with direct onclick
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.onclick = function(e) {
            console.log('Logout button clicked via onclick');
            e.preventDefault();
            e.stopPropagation();
            logout();
            return false;
        };
        console.log('Logout button setup complete');
    } else {
        console.error('Logout button not found');
    }
    
    console.log('Initializing dashboard...');
    
    // Initialize dashboard directly (server ensures user is authenticated)
    showScreen('dashboard-screen');
    showSection('overview-section');
    startAutoUpdate();
    loadAllData();
    
    // Load current user info
    apiCall('/auth/me').then(user => {
        if (user && user.username) {
            document.getElementById('username-display').textContent = user.username;
            currentUser = user;
        }
    }).catch(error => {
        console.log('Could not load user info:', error);
    });
});

// Handle page visibility for auto-updates
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        stopAutoUpdate();
    } else if (currentUser) {
        startAutoUpdate();
    }
});