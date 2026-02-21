/**
 * ELK Alert Streaming Module for RansomRun
 * 
 * Provides real-time alert streaming via Server-Sent Events (SSE)
 * with auto-reconnect, duplicate suppression, and graceful degradation.
 */

class ELKAlertStream {
    constructor(options = {}) {
        this.streamUrl = options.streamUrl || '/api/alerts/stream';
        this.onAlert = options.onAlert || this._defaultAlertHandler;
        this.onConnect = options.onConnect || (() => {});
        this.onDisconnect = options.onDisconnect || (() => {});
        this.onError = options.onError || (() => {});
        this.maxAlerts = options.maxAlerts || 100;
        
        this.eventSource = null;
        this.connected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 1000; // Start with 1 second
        this.maxReconnectDelay = 30000; // Max 30 seconds
        
        // Duplicate suppression
        this.seenAlerts = new Set();
        this.seenAlertsTTL = 300000; // 5 minutes
        
        // Alert storage
        this.alerts = [];
    }
    
    /**
     * Connect to the SSE stream
     */
    connect() {
        if (this.eventSource) {
            this.disconnect();
        }
        
        console.log('[ELK Stream] Connecting to', this.streamUrl);
        
        try {
            this.eventSource = new EventSource(this.streamUrl);
            
            this.eventSource.addEventListener('connected', (e) => {
                console.log('[ELK Stream] Connected');
                this.connected = true;
                this.reconnectAttempts = 0;
                this.reconnectDelay = 1000;
                this.onConnect(JSON.parse(e.data));
            });
            
            this.eventSource.addEventListener('alert', (e) => {
                const alert = JSON.parse(e.data);
                this._handleAlert(alert);
            });
            
            this.eventSource.addEventListener('heartbeat', (e) => {
                const data = JSON.parse(e.data);
                console.log('[ELK Stream] Heartbeat:', data.timestamp);
            });
            
            this.eventSource.onerror = (e) => {
                console.error('[ELK Stream] Error:', e);
                this.connected = false;
                this.onError(e);
                this._scheduleReconnect();
            };
            
        } catch (error) {
            console.error('[ELK Stream] Failed to create EventSource:', error);
            this.onError(error);
            this._scheduleReconnect();
        }
    }
    
    /**
     * Disconnect from the stream
     */
    disconnect() {
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }
        this.connected = false;
        this.onDisconnect();
        console.log('[ELK Stream] Disconnected');
    }
    
    /**
     * Handle incoming alert with deduplication
     */
    _handleAlert(alert) {
        // Check for duplicate
        if (this.seenAlerts.has(alert.id)) {
            console.log('[ELK Stream] Duplicate alert suppressed:', alert.id);
            return;
        }
        
        // Mark as seen
        this.seenAlerts.add(alert.id);
        
        // Clean old entries periodically
        if (this.seenAlerts.size > 1000) {
            this._cleanSeenAlerts();
        }
        
        // Store alert
        this.alerts.unshift(alert);
        if (this.alerts.length > this.maxAlerts) {
            this.alerts.pop();
        }
        
        // Notify callback
        this.onAlert(alert);
        
        console.log('[ELK Stream] New alert:', alert.rule_id, alert.summary);
    }
    
    /**
     * Schedule reconnection with exponential backoff
     */
    _scheduleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('[ELK Stream] Max reconnect attempts reached');
            return;
        }
        
        this.reconnectAttempts++;
        const delay = Math.min(
            this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1),
            this.maxReconnectDelay
        );
        
        console.log(`[ELK Stream] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
        
        setTimeout(() => {
            if (!this.connected) {
                this.connect();
            }
        }, delay);
    }
    
    /**
     * Clean old seen alerts
     */
    _cleanSeenAlerts() {
        // Keep only last 500 entries
        const entries = Array.from(this.seenAlerts);
        this.seenAlerts = new Set(entries.slice(-500));
    }
    
    /**
     * Default alert handler (logs to console)
     */
    _defaultAlertHandler(alert) {
        console.log('[ELK Stream] Alert received:', alert);
    }
    
    /**
     * Get all stored alerts
     */
    getAlerts() {
        return this.alerts;
    }
    
    /**
     * Check if connected
     */
    isConnected() {
        return this.connected;
    }
}


/**
 * Alert Feed Widget for ELK Dashboard
 */
class AlertFeedWidget {
    constructor(containerId, options = {}) {
        this.container = document.getElementById(containerId);
        this.maxItems = options.maxItems || 20;
        this.stream = null;
        
        if (!this.container) {
            console.error('[AlertFeed] Container not found:', containerId);
            return;
        }
        
        this._initWidget();
    }
    
    /**
     * Initialize the widget UI
     */
    _initWidget() {
        this.container.innerHTML = `
            <div class="alert-feed-header">
                <span class="feed-status" id="feed-status">
                    <i class="bi bi-circle-fill disconnected"></i>
                    <span>Disconnected</span>
                </span>
                <button class="btn btn-sm btn-ghost" id="feed-toggle">
                    <i class="bi bi-play-fill"></i> Connect
                </button>
            </div>
            <div class="alert-feed-list" id="alert-feed-list">
                <div class="feed-empty">
                    <i class="bi bi-bell"></i>
                    <p>No alerts yet. Connect to start streaming.</p>
                </div>
            </div>
        `;
        
        // Bind toggle button
        document.getElementById('feed-toggle').addEventListener('click', () => {
            if (this.stream && this.stream.isConnected()) {
                this.disconnect();
            } else {
                this.connect();
            }
        });
    }
    
    /**
     * Connect to alert stream
     */
    connect() {
        this.stream = new ELKAlertStream({
            onAlert: (alert) => this._addAlert(alert),
            onConnect: () => this._updateStatus(true),
            onDisconnect: () => this._updateStatus(false),
            onError: () => this._updateStatus(false, true)
        });
        
        this.stream.connect();
        this._updateToggleButton(true);
    }
    
    /**
     * Disconnect from stream
     */
    disconnect() {
        if (this.stream) {
            this.stream.disconnect();
        }
        this._updateToggleButton(false);
    }
    
    /**
     * Update connection status indicator
     */
    _updateStatus(connected, error = false) {
        const statusEl = document.getElementById('feed-status');
        if (!statusEl) return;
        
        if (connected) {
            statusEl.innerHTML = `
                <i class="bi bi-circle-fill connected"></i>
                <span>Live</span>
            `;
        } else if (error) {
            statusEl.innerHTML = `
                <i class="bi bi-circle-fill error"></i>
                <span>Error - Reconnecting...</span>
            `;
        } else {
            statusEl.innerHTML = `
                <i class="bi bi-circle-fill disconnected"></i>
                <span>Disconnected</span>
            `;
        }
    }
    
    /**
     * Update toggle button state
     */
    _updateToggleButton(connected) {
        const btn = document.getElementById('feed-toggle');
        if (!btn) return;
        
        if (connected) {
            btn.innerHTML = '<i class="bi bi-stop-fill"></i> Disconnect';
            btn.classList.add('active');
        } else {
            btn.innerHTML = '<i class="bi bi-play-fill"></i> Connect';
            btn.classList.remove('active');
        }
    }
    
    /**
     * Add alert to the feed
     */
    _addAlert(alert) {
        const list = document.getElementById('alert-feed-list');
        if (!list) return;
        
        // Remove empty state
        const empty = list.querySelector('.feed-empty');
        if (empty) {
            empty.remove();
        }
        
        // Create alert element
        const alertEl = document.createElement('div');
        alertEl.className = `feed-alert severity-${alert.severity.toLowerCase()}`;
        alertEl.dataset.alertId = alert.id;
        
        const timestamp = alert.ts ? new Date(alert.ts).toLocaleTimeString() : 'N/A';
        const mitre = alert.mitre ? alert.mitre.join(', ') : 'N/A';
        
        alertEl.innerHTML = `
            <div class="feed-alert-header">
                <span class="severity-badge ${alert.severity.toLowerCase()}">${alert.severity}</span>
                <span class="rule-id">${alert.rule_id}</span>
                <span class="timestamp">${timestamp}</span>
            </div>
            <div class="feed-alert-body">
                <div class="host"><i class="bi bi-pc-display"></i> ${alert.host}</div>
                <div class="summary">${alert.summary}</div>
                <div class="mitre"><i class="bi bi-shield-exclamation"></i> ${mitre}</div>
            </div>
        `;
        
        // Add click handler for details
        alertEl.addEventListener('click', () => this._showAlertDetails(alert));
        
        // Insert at top
        list.insertBefore(alertEl, list.firstChild);
        
        // Limit items
        while (list.children.length > this.maxItems) {
            list.removeChild(list.lastChild);
        }
        
        // Flash animation
        alertEl.classList.add('new');
        setTimeout(() => alertEl.classList.remove('new'), 1000);
    }
    
    /**
     * Show alert details in modal
     */
    _showAlertDetails(alert) {
        // Create or get modal
        let modal = document.getElementById('alert-detail-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'alert-detail-modal';
            modal.className = 'modal-overlay';
            modal.innerHTML = `
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>Alert Details</h3>
                        <button class="modal-close">&times;</button>
                    </div>
                    <div class="modal-body" id="alert-detail-body"></div>
                </div>
            `;
            document.body.appendChild(modal);
            
            modal.querySelector('.modal-close').addEventListener('click', () => {
                modal.classList.remove('show');
            });
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('show');
                }
            });
        }
        
        // Populate details
        const body = document.getElementById('alert-detail-body');
        const raw = alert.raw || {};
        
        body.innerHTML = `
            <div class="detail-section">
                <h4>Alert Info</h4>
                <table class="detail-table">
                    <tr><td>ID</td><td><code>${alert.id}</code></td></tr>
                    <tr><td>Rule</td><td>${alert.rule_id} - ${alert.rule_name}</td></tr>
                    <tr><td>Severity</td><td><span class="severity-badge ${alert.severity.toLowerCase()}">${alert.severity}</span> (${alert.severity_num})</td></tr>
                    <tr><td>Timestamp</td><td>${alert.ts}</td></tr>
                    <tr><td>Host</td><td>${alert.host}</td></tr>
                    <tr><td>User</td><td>${alert.user || 'N/A'}</td></tr>
                    <tr><td>MITRE</td><td>${(alert.mitre || []).join(', ')}</td></tr>
                </table>
            </div>
            <div class="detail-section">
                <h4>Summary</h4>
                <p>${alert.summary}</p>
            </div>
            <div class="detail-section">
                <h4>Process Details</h4>
                <table class="detail-table">
                    <tr><td>Process</td><td><code>${raw.process_name || 'N/A'}</code></td></tr>
                    <tr><td>PID</td><td>${raw.process_pid || 'N/A'}</td></tr>
                    <tr><td>Command Line</td><td><code class="cmd">${raw.process_command_line || 'N/A'}</code></td></tr>
                    <tr><td>Parent</td><td><code>${raw.process_parent_name || 'N/A'}</code></td></tr>
                    <tr><td>Parent Cmd</td><td><code class="cmd">${raw.process_parent_command_line || 'N/A'}</code></td></tr>
                </table>
            </div>
            ${raw.file_path ? `
            <div class="detail-section">
                <h4>File</h4>
                <table class="detail-table">
                    <tr><td>Path</td><td><code>${raw.file_path}</code></td></tr>
                    <tr><td>Name</td><td>${raw.file_name || 'N/A'}</td></tr>
                </table>
            </div>
            ` : ''}
            ${raw.destination_ip ? `
            <div class="detail-section">
                <h4>Network</h4>
                <table class="detail-table">
                    <tr><td>Destination</td><td>${raw.destination_ip}:${raw.destination_port}</td></tr>
                </table>
            </div>
            ` : ''}
        `;
        
        modal.classList.add('show');
    }
}


// Export for use
window.ELKAlertStream = ELKAlertStream;
window.AlertFeedWidget = AlertFeedWidget;
