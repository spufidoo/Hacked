# Real-Time Web Dashboard Implementation Guide

## Overview

This document outlines how to implement a real-time web dashboard for HackedSSH that provides live monitoring of security events, attack attempts, and system status.

## Architecture

### Components

1. **Backend Web Server** (Flask/FastAPI)
   - REST API for historical data
   - WebSocket/SSE for real-time events
   - Authentication/authorization

2. **Real-Time Log Monitor**
   - Follows systemd journal in real-time
   - Processes events as they occur
   - Filters and categorizes security events

3. **Frontend Dashboard**
   - Real-time event feed
   - Interactive maps (reuse existing Folium maps)
   - Charts and statistics
   - Alert notifications

4. **Event Processing Pipeline**
   - Parse journal entries
   - Extract IP addresses, users, services
   - Geolocate IPs (reuse existing functions)
   - Categorize by severity

## Implementation Options

### Option 1: Flask + WebSocket (Recommended)

**Backend (`dashboard_server.py`):**
```python
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import subprocess
import threading
import re
from systemd import journal
from datetime import datetime
from collections import deque

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Store recent events (last 1000)
recent_events = deque(maxlen=1000)
event_stats = {
    'total_attempts': 0,
    'critical_events': 0,
    'high_events': 0,
    'medium_events': 0,
    'by_country': defaultdict(int),
    'by_service': defaultdict(int)
}

def follow_journal():
    """Follow systemd journal in real-time"""
    j = journal.Reader()
    j.seek_tail()  # Start from end
    j.get_previous()  # Move to last entry
    
    # Filter for security-relevant units
    j.add_match(_SYSTEMD_UNIT="ssh.service")
    j.add_match(_SYSTEMD_UNIT="nginx.service")
    # Add more units as needed
    
    while True:
        j.wait()  # Wait for new entries
        for entry in j:
            process_journal_entry(entry)

def process_journal_entry(entry):
    """Process a journal entry and emit to clients"""
    message = entry.get('MESSAGE', '')
    unit = entry.get('_SYSTEMD_UNIT', '')
    timestamp = datetime.fromtimestamp(
        entry.get('__REALTIME_TIMESTAMP', 0) / 1000000
    )
    
    # Reuse existing pattern matching from HackedSSH.py
    event = parse_security_event(message, unit, timestamp)
    
    if event:
        recent_events.append(event)
        update_stats(event)
        socketio.emit('new_event', event, broadcast=True)

def parse_security_event(message, unit, timestamp):
    """Parse security event from log message"""
    # Reuse patterns from extract_attack_attempts()
    ip_pattern = re.compile(IP_REGEX)
    
    # Check for failed SSH login
    if 'Failed password' in message or 'Invalid user' in message:
        ip_match = ip_pattern.search(message)
        if ip_match:
            return {
                'type': 'ssh_failure',
                'severity': 'medium',
                'ip': ip_match.group(),
                'service': 'SSH',
                'message': message,
                'timestamp': timestamp.isoformat()
            }
    
    # Check for successful login (CRITICAL)
    if 'Accepted' in message and 'ssh' in unit.lower():
        ip_match = ip_pattern.search(message)
        if ip_match:
            return {
                'type': 'ssh_success',
                'severity': 'critical',
                'ip': ip_match.group(),
                'service': 'SSH',
                'message': message,
                'timestamp': timestamp.isoformat()
            }
    
    # Add more patterns from extract_security_events()
    return None

def update_stats(event):
    """Update statistics"""
    event_stats['total_attempts'] += 1
    if event['severity'] == 'critical':
        event_stats['critical_events'] += 1
    # Update by_country, by_service, etc.

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    return jsonify(event_stats)

@app.route('/api/events')
def get_events():
    return jsonify(list(recent_events))

@socketio.on('connect')
def handle_connect():
    emit('connected', {'status': 'Connected to HackedSSH Dashboard'})

if __name__ == '__main__':
    # Start journal follower in background thread
    journal_thread = threading.Thread(target=follow_journal, daemon=True)
    journal_thread.start()
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
```

**Frontend (`templates/dashboard.html`):**
```html
<!DOCTYPE html>
<html>
<head>
    <title>HackedSSH Real-Time Dashboard</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        .event-feed { max-height: 400px; overflow-y: auto; }
        .event { padding: 10px; margin: 5px; border-left: 4px solid; }
        .critical { border-color: red; background: #ffe6e6; }
        .high { border-color: orange; background: #fff4e6; }
        .medium { border-color: yellow; background: #fffce6; }
    </style>
</head>
<body>
    <h1>HackedSSH Real-Time Dashboard</h1>
    
    <div id="stats">
        <div>Total Attempts: <span id="total">0</span></div>
        <div>Critical: <span id="critical">0</span></div>
        <div>High: <span id="high">0</span></div>
        <div>Medium: <span id="medium">0</span></div>
    </div>
    
    <div class="event-feed" id="events"></div>
    
    <canvas id="chart"></canvas>
    
    <script>
        const socket = io();
        const eventsDiv = document.getElementById('events');
        
        socket.on('new_event', (event) => {
            const eventEl = document.createElement('div');
            eventEl.className = `event ${event.severity}`;
            eventEl.innerHTML = `
                <strong>${event.service}</strong> - ${event.type}
                <br>IP: ${event.ip} | ${event.timestamp}
            `;
            eventsDiv.insertBefore(eventEl, eventsDiv.firstChild);
            
            // Update stats
            updateStats();
        });
        
        function updateStats() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(stats => {
                    document.getElementById('total').textContent = stats.total_attempts;
                    document.getElementById('critical').textContent = stats.critical_events;
                    // Update chart
                });
        }
        
        // Update stats every 5 seconds
        setInterval(updateStats, 5000);
    </script>
</body>
</html>
```

### Option 2: FastAPI + Server-Sent Events

**Backend (`dashboard_fastapi.py`):**
```python
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
from systemd import journal

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"])

@app.get("/")
async def dashboard():
    with open("templates/dashboard.html") as f:
        return HTMLResponse(content=f.read())

@app.get("/events")
async def stream_events():
    async def event_generator():
        j = journal.Reader()
        j.seek_tail()
        j.add_match(_SYSTEMD_UNIT="ssh.service")
        
        while True:
            j.wait()
            for entry in j:
                event = process_entry(entry)
                if event:
                    yield f"data: {json.dumps(event)}\n\n"
            await asyncio.sleep(0.1)
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")
```

## Integration with Existing Code

### Reuse Existing Functions

1. **Geolocation Functions:**
   - `get_city_and_coords_from_ip()` - Already implemented
   - `batch_lookup_ips()` - For batch geolocation
   - `get_country_from_ip()` - Country lookup

2. **Event Parsing:**
   - Reuse patterns from `extract_attack_attempts()`
   - Reuse severity classification from `extract_security_events()`

3. **Map Generation:**
   - Reuse Folium map generation code
   - Update map in real-time as events arrive

### Database (Optional)

For historical data and better performance:

```python
# SQLite for simplicity, or PostgreSQL for production
import sqlite3

def init_db():
    conn = sqlite3.connect('hackedssh.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            severity TEXT,
            service TEXT,
            ip TEXT,
            user TEXT,
            message TEXT,
            country TEXT,
            city TEXT,
            lat REAL,
            lon REAL
        )
    ''')
    conn.commit()
    conn.close()
```

## Security Considerations

1. **Authentication:**
   ```python
   from flask_login import LoginManager
   from werkzeug.security import check_password_hash
   
   login_manager = LoginManager()
   login_manager.init_app(app)
   
   @app.route('/login', methods=['POST'])
   def login():
       # Implement authentication
       pass
   ```

2. **HTTPS:**
   - Use nginx as reverse proxy with SSL
   - Configure Let's Encrypt certificate

3. **Rate Limiting:**
   ```python
   from flask_limiter import Limiter
   limiter = Limiter(app, key_func=get_remote_address)
   ```

4. **Input Validation:**
   - Sanitize all user inputs
   - Validate IP addresses
   - Prevent injection attacks

## Deployment

### Systemd Service

```ini
[Unit]
Description=HackedSSH Real-Time Dashboard
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/usr/local/bin
ExecStart=/usr/bin/python3 /usr/local/bin/dashboard_server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### Nginx Configuration

```nginx
server {
    listen 80;
    server_name dashboard.yourdomain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

## Features to Implement

### Phase 1: Basic Dashboard
- [ ] Real-time event feed
- [ ] Event statistics
- [ ] Basic authentication
- [ ] Event filtering by severity

### Phase 2: Enhanced Visualization
- [ ] Interactive map with real-time markers
- [ ] Charts (line, bar, pie)
- [ ] Country/region breakdown
- [ ] Service breakdown

### Phase 3: Advanced Features
- [ ] Alert rules and notifications
- [ ] Historical data analysis
- [ ] Export functionality
- [ ] Multi-server support

### Phase 4: Machine Learning
- [ ] Anomaly detection
- [ ] Attack pattern recognition
- [ ] Predictive alerts
- [ ] Automated response suggestions

## Dependencies

```bash
# For Flask option
pip3 install flask flask-socketio flask-login flask-limiter

# For FastAPI option
pip3 install fastapi uvicorn python-multipart

# Common
pip3 install systemd-python geoip2 folium
```

## Performance Considerations

1. **Event Buffer:** Use deque with maxlen to limit memory
2. **Batch Processing:** Group events before emitting
3. **Caching:** Cache geolocation results
4. **Database:** Store events in database for historical queries
5. **Connection Limits:** Limit WebSocket connections

## Testing

```python
# test_dashboard.py
import pytest
from dashboard_server import app, process_journal_entry

def test_event_parsing():
    entry = {
        'MESSAGE': 'Failed password for user from 192.168.1.1',
        '_SYSTEMD_UNIT': 'ssh.service',
        '__REALTIME_TIMESTAMP': 1234567890000000
    }
    event = process_journal_entry(entry)
    assert event['severity'] == 'medium'
    assert event['ip'] == '192.168.1.1'
```

## Next Steps

1. Create `dashboard_server.py` with basic Flask setup
2. Implement journal following
3. Create frontend template
4. Add authentication
5. Integrate with existing geolocation functions
6. Add map visualization
7. Deploy and test


