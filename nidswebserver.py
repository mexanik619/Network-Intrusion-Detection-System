## !/usr/bin/env python3
#C:\Users\Administrator\Documents\GitHub\Network-Intrusion-Detection-System\nidswebserver.py

"""
NIDS Web Server
--------------
This script provides a web server interface for the Network Intrusion Detection System.
It allows users to control the NIDS via a web dashboard and view real-time data.
"""

import os
import json
import time
import signal
import logging
import datetime
import threading
import subprocess
import ipaddress
from typing import Dict, List, Optional, Tuple, Any
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from flask_socketio import SocketIO

# Basic logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("nids_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NIDS-Server')

# Initialize Flask app
app = Flask(__name__, static_folder='static')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
NIDS_PROCESS = None
NIDS_RUNNING = False
NIDS_CONFIG = {
    'interface': 'eth0',
    'pcap_file': None,
    'threshold_port_scan': 15,
    'threshold_ddos': 100,
    'whitelist': ['127.0.0.1', '192.168.1.1']
}

# Path to the NIDS script
NIDS_SCRIPT_PATH = "./nids.py"

# Directory for PCAP files
PCAP_DIR = "./pcap_files"
os.makedirs(PCAP_DIR, exist_ok=True)

# Store for traffic data and alerts
TRAFFIC_DATA = {
    'timestamps': [],
    'normal': [],
    'suspicious': []
}

ALERTS = []
MAX_ALERTS = 100  # Maximum number of alerts to store

# Thread for log monitoring
LOG_MONITOR_THREAD = None
STOP_LOG_MONITOR = False

def start_nids(config: Dict[str, Any]) -> bool:
    """
    Start the NIDS process with the given configuration
    
    Args:
        config: NIDS configuration parameters
        
    Returns:
        bool: True if started successfully, False otherwise
    """
    global NIDS_PROCESS, NIDS_RUNNING
    
    if NIDS_RUNNING:
        logger.warning("NIDS is already running")
        return False
    
    cmd = [NIDS_SCRIPT_PATH]
    
    # Add interface or pcap file
    if config['pcap_file']:
        cmd.extend(['-r', config['pcap_file']])
    else:
        cmd.extend(['-i', config['interface']])
    
    # Add thresholds
    cmd.extend(['-p', str(config['threshold_port_scan'])])
    cmd.extend(['-d', str(config['threshold_ddos'])])
    
    # Add whitelist
    if config['whitelist']:
        cmd.extend(['-w'] + config['whitelist'])
    
    try:
        logger.info(f"Starting NIDS with command: {' '.join(cmd)}")
        NIDS_PROCESS = subprocess.Popen(cmd)
        NIDS_RUNNING = True
        return True
    except Exception as e:
        logger.error(f"Failed to start NIDS: {e}")
        return False

def stop_nids() -> bool:
    """
    Stop the running NIDS process
    
    Returns:
        bool: True if stopped successfully, False otherwise
    """
    global NIDS_PROCESS, NIDS_RUNNING
    
    if not NIDS_RUNNING:
        logger.warning("NIDS is not running")
        return False
    
    try:
        logger.info("Stopping NIDS")
        NIDS_PROCESS.send_signal(signal.SIGINT)
        NIDS_PROCESS.wait(timeout=5)
        NIDS_RUNNING = False
        return True
    except Exception as e:
        logger.error(f"Failed to stop NIDS gracefully: {e}")
        try:
            NIDS_PROCESS.kill()
            NIDS_RUNNING = False
            return True
        except Exception as e2:
            logger.error(f"Failed to kill NIDS process: {e2}")
            return False

def restart_nids() -> bool:
    """
    Restart the NIDS process
    
    Returns:
        bool: True if restarted successfully, False otherwise
    """
    if NIDS_RUNNING:
        if not stop_nids():
            return False
    
    time.sleep(1)  # Small delay to ensure clean shutdown
    return start_nids(NIDS_CONFIG)

def parse_nids_log(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a line from the NIDS log file
    
    Args:
        line: A log line from the NIDS
        
    Returns:
        Dict or None: Parsed alert information or None if not an alert
    """
    try:
        if "ALERT:" in line:
            # Parse timestamp, alert type, and details
            parts = line.strip().split(" - ", 2)
            if len(parts) < 3:
                return None
                
            timestamp = parts[0]
            log_level = parts[1]
            
            if log_level != "WARNING":
                return None
                
            alert_info = parts[2][7:]  # Remove "ALERT: " prefix
            alert_parts = alert_info.split(" detected from ", 1)
            
            if len(alert_parts) < 2:
                return None
                
            alert_type = alert_parts[0]
            rest = alert_parts[1].split(" - ", 1)
            
            if len(rest) < 2:
                return None
                
            source_ip = rest[0]
            details = rest[1]
            
            return {
                'time': timestamp,
                'type': alert_type,
                'source': source_ip,
                'details': details
            }
    except Exception as e:
        logger.error(f"Error parsing log line: {e}")
    
    return None

def monitor_nids_log():
    """
    Monitor the NIDS log file for new alerts
    This runs in a separate thread
    """
    global ALERTS, STOP_LOG_MONITOR
    
    log_file = "nids.log"
    
    # Wait for the log file to be created if it doesn't exist
    while not os.path.exists(log_file) and not STOP_LOG_MONITOR:
        time.sleep(1)
    
    if STOP_LOG_MONITOR:
        return
        
    # Get file size to start from the end
    file_size = os.path.getsize(log_file)
    
    with open(log_file, 'r') as f:
        # Move to the end of the file
        f.seek(file_size)
        
        while not STOP_LOG_MONITOR:
            line = f.readline()
            
            if line:
                alert = parse_nids_log(line)
                
                if alert:
                    # Add alert to our list (limited size)
                    ALERTS.append(alert)
                    if len(ALERTS) > MAX_ALERTS:
                        ALERTS.pop(0)
                    
                    # Emit alert to connected clients
                    socketio.emit('new_alert', alert)
                    
                    # Also emit updated traffic data
                    update_traffic_data()
            else:
                time.sleep(0.1)

def update_traffic_data():
    """
    Update traffic data with some simulated values
    In a real application, this would parse actual traffic data
    """
    global TRAFFIC_DATA
    
    # Add current timestamp
    now = datetime.datetime.now().strftime("%H:%M:%S")
    
    # Generate some random traffic data
    import random
    normal = random.randint(10, 60)
    suspicious = random.randint(0, 15)
    
    # Add data point
    TRAFFIC_DATA['timestamps'].append(now)
    TRAFFIC_DATA['normal'].append(normal)
    TRAFFIC_DATA['suspicious'].append(suspicious)
    
    # Keep only the last 60 data points
    if len(TRAFFIC_DATA['timestamps']) > 60:
        TRAFFIC_DATA['timestamps'].pop(0)
        TRAFFIC_DATA['normal'].pop(0)
        TRAFFIC_DATA['suspicious'].pop(0)
    
    # Emit to connected clients
    socketio.emit('traffic_data', TRAFFIC_DATA)

def validate_ip(ip: str) -> bool:
    """
    Validate if a string is a valid IP address
    
    Args:
        ip: String to validate as IP address
        
    Returns:
        bool: True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def extract_log_entries(count: int = 100) -> List[str]:
    """
    Extract the last N log entries from the NIDS log file
    
    Args:
        count: Number of log entries to extract
        
    Returns:
        List[str]: List of log entries
    """
    log_file = "nids.log"
    
    if not os.path.exists(log_file):
        return []
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
            return lines[-count:]
    except Exception as e:
        logger.error(f"Error reading log file: {e}")
        return []

# API Routes
@app.route('/')
def index():
    """Serve the main dashboard HTML"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current NIDS status"""
    return jsonify({
        'running': NIDS_RUNNING,
        'config': NIDS_CONFIG
    })

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    """Get or update NIDS configuration"""
    global NIDS_CONFIG
    
    if request.method == 'GET':
        return jsonify(NIDS_CONFIG)
    
    if request.method == 'POST':
        try:
            new_config = request.json
            
            # Basic validation
            if 'interface' in new_config and new_config['interface']:
                NIDS_CONFIG['interface'] = new_config['interface']
            
            if 'pcap_file' in new_config:
                NIDS_CONFIG['pcap_file'] = new_config['pcap_file']
            
            if 'threshold_port_scan' in new_config:
                threshold = int(new_config['threshold_port_scan'])
                if threshold > 0:
                    NIDS_CONFIG['threshold_port_scan'] = threshold
            
            if 'threshold_ddos' in new_config:
                threshold = int(new_config['threshold_ddos'])
                if threshold > 0:
                    NIDS_CONFIG['threshold_ddos'] = threshold
            
            if 'whitelist' in new_config:
                whitelist = []
                for ip in new_config['whitelist']:
                    if validate_ip(ip):
                        whitelist.append(ip)
                NIDS_CONFIG['whitelist'] = whitelist
            
            return jsonify({
                'success': True, 
                'config': NIDS_CONFIG
            })
        except Exception as e:
            logger.error(f"Error updating config: {e}")
            return jsonify({
                'success': False, 
                'error': str(e)
            }), 400

@app.route('/api/start', methods=['POST'])
def api_start_nids():
    """Start the NIDS"""
    success = start_nids(NIDS_CONFIG)
    return jsonify({'success': success})

@app.route('/api/stop', methods=['POST'])
def api_stop_nids():
    """Stop the NIDS"""
    success = stop_nids()
    return jsonify({'success': success})

@app.route('/api/restart', methods=['POST'])
def api_restart_nids():
    """Restart the NIDS"""
    success = restart_nids()
    return jsonify({'success': success})

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    return jsonify(ALERTS)

@app.route('/api/traffic', methods=['GET'])
def get_traffic():
    """Get traffic data"""
    return jsonify(TRAFFIC_DATA)

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get recent log entries"""
    count = request.args.get('count', default=100, type=int)
    logs = extract_log_entries(count)
    return jsonify({'logs': logs})

@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    """
    Block an IP address
    In a real application, this would add the IP to a firewall rule
    """
    try:
        ip = request.json.get('ip')
        
        if not ip or not validate_ip(ip):
            return jsonify({
                'success': False, 
                'error': 'Invalid IP address'
            }), 400
        
        # In a real application, add firewall rule here
        logger.info(f"Blocking IP: {ip}")
        
        return jsonify({
            'success': True,
            'message': f"IP {ip} has been blocked"
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/upload-pcap', methods=['POST'])
def upload_pcap():
    """
    Handle PCAP file upload
    """
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'error': 'No file part'
        }), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({
            'success': False,
            'error': 'No selected file'
        }), 400
    
    if file and file.filename.endswith('.pcap'):
        filename = os.path.join(PCAP_DIR, file.filename)
        file.save(filename)
        
        return jsonify({
            'success': True,
            'filename': file.filename,
            'path': filename
        })
    
    return jsonify({
        'success': False,
        'error': 'Invalid file type'
    }), 400

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    
    # Send initial data
    socketio.emit('status', {'running': NIDS_RUNNING}, room=request.sid)
    socketio.emit('alerts', ALERTS, room=request.sid)
    socketio.emit('traffic_data', TRAFFIC_DATA, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

def start_log_monitor():
    """Start the log monitoring thread"""
    global LOG_MONITOR_THREAD, STOP_LOG_MONITOR
    
    STOP_LOG_MONITOR = False
    LOG_MONITOR_THREAD = threading.Thread(target=monitor_nids_log)
    LOG_MONITOR_THREAD.daemon = True
    LOG_MONITOR_THREAD.start()

def stop_log_monitor():
    """Stop the log monitoring thread"""
    global STOP_LOG_MONITOR
    STOP_LOG_MONITOR = True
    if LOG_MONITOR_THREAD:
        LOG_MONITOR_THREAD.join(timeout=2)

if __name__ == '__main__':
    try:
        # Copy the HTML file to static folder
        os.makedirs(app.static_folder, exist_ok=True)
        
        # Start log monitor thread
        start_log_monitor()
        
        # Start the server
        logger.info("Starting NIDS Web Server")
        socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
    finally:
        # Clean up
        stop_log_monitor()
        if NIDS_RUNNING:
            stop_nids()