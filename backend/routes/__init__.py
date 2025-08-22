from flask import Blueprint, jsonify, request
import sqlite3
import os
from datetime import datetime

init_bp = Blueprint('init', __name__)

def create_database_tables():
    """Create all necessary database tables"""
    conn = sqlite3.connect('shadowpulse.db')
    cursor = conn.cursor()
    
    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            target_ip TEXT,
            description TEXT,
            details TEXT,
            status TEXT DEFAULT 'open',
            notes TEXT,
            updated_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Network logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            log_type TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            packet_size INTEGER,
            flags TEXT,
            payload_snippet TEXT
        )
    ''')
    
    # Devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            mac_address TEXT,
            hostname TEXT,
            vendor TEXT,
            device_type TEXT,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_trusted BOOLEAN DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            ports TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME
        )
    ''')
    
    # Scheduled reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scheduled_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            report_type TEXT NOT NULL,
            schedule TEXT NOT NULL,
            recipients TEXT,
            next_run_time DATETIME,
            last_run_time DATETIME,
            is_active BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME
        )
    ''')
    
    # System configuration table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            config_key TEXT UNIQUE NOT NULL,
            config_value TEXT,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME
        )
    ''')
    
    # Detector status table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detector_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detector_name TEXT UNIQUE NOT NULL,
            is_enabled BOOLEAN DEFAULT 1,
            last_update DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'running',
            config TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def insert_default_data():
    """Insert default configuration and sample data"""
    conn = sqlite3.connect('shadowpulse.db')
    cursor = conn.cursor()
    
    # Default system configuration
    default_configs = [
        ('monitoring_interface', 'eth0', 'Network interface to monitor'),
        ('alert_retention_days', '30', 'Days to retain alert data'),
        ('log_retention_days', '7', 'Days to retain network logs'),
        ('scan_interval', '300', 'Device scan interval in seconds'),
        ('threat_threshold', '5', 'Threat score threshold for alerts'),
        ('admin_email', 'admin@shadowpulse.local', 'Administrator email for alerts')
    ]
    
    for config in default_configs:
        cursor.execute('''
            INSERT OR IGNORE INTO system_config (config_key, config_value, description)
            VALUES (?, ?, ?)
        ''', config)
    
    # Initialize detector status
    detectors = [
        'arp_spoof', 'dhcp_spoofing', 'dns_spoof', 'http_injection',
        'icmp_redirect', 'rogue_access', 'ssl_strip'
    ]
    
    for detector in detectors:
        cursor.execute('''
            INSERT OR IGNORE INTO detector_status (detector_name, is_enabled, status)
            VALUES (?, 1, 'running')
        ''', (detector,))
    
    conn.commit()
    conn.close()

@init_bp.route('/setup', methods=['POST'])
def initialize_system():
    """Initialize the SHADOWPULSE system"""
    try:
        # Create database tables
        create_database_tables()
        
        # Insert default data
        insert_default_data()
        
        # Create necessary directories
        directories = ['logs', 'exports', 'reports', 'captures']
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
        return jsonify({
            'status': 'success',
            'message': 'SHADOWPULSE system initialized successfully',
            'initialized_at': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@init_bp.route('/status', methods=['GET'])
def get_system_status():
    """Get current system initialization status"""
    try:
        # Check if database exists and has tables
        db_exists = os.path.exists('shadowpulse.db')
        
        if db_exists:
            conn = sqlite3.connect('shadowpulse.db')
            cursor = conn.cursor()
            
            # Check if main tables exist
            cursor.execute('''
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name IN ('alerts', 'network_logs', 'devices')
            ''')
            tables = cursor.fetchall()
            
            # Check detector status
            cursor.execute('SELECT detector_name, is_enabled, status FROM detector_status')
            detectors = cursor.fetchall()
            
            conn.close()
            
            is_initialized = len(tables) >= 3
        else:
            is_initialized = False
            detectors = []
        
        return jsonify({
            'status': 'success',
            'is_initialized': is_initialized,
            'database_exists': db_exists,
            'detectors': [
                {
                    'name': d[0],
                    'enabled': bool(d[1]),
                    'status': d[2]
                } for d in detectors
            ] if db_exists else []
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@init_bp.route('/config', methods=['GET'])
def get_system_config():
    """Get system configuration"""
    try:
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT config_key, config_value, description FROM system_config')
        configs = cursor.fetchall()
        
        conn.close()
        
        config_dict = {}
        for config in configs:
            config_dict[config[0]] = {
                'value': config[1],
                'description': config[2]
            }
        
        return jsonify({
            'status': 'success',
            'configuration': config_dict
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@init_bp.route('/config', methods=['PUT'])
def update_system_config():
    """Update system configuration"""
    try:
        data = request.get_json()
        
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        for key, value in data.items():
            cursor.execute('''
                UPDATE system_config 
                SET config_value = ?, updated_at = datetime('now')
                WHERE config_key = ?
            ''', (value, key))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'message': 'Configuration updated successfully'
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@init_bp.route('/detectors', methods=['PUT'])
def update_detector_config():
    """Update detector configuration and status"""
    try:
        data = request.get_json()
        detector_name = data.get('detector_name')
        is_enabled = data.get('is_enabled')
        config = data.get('config', {})
        
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE detector_status 
            SET is_enabled = ?, config = ?, last_update = datetime('now')
            WHERE detector_name = ?
        ''', (is_enabled, str(config), detector_name))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'message': f'Detector {detector_name} configuration updated'
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@init_bp.route('/health', methods=['GET'])
def health_check():
    """System health check endpoint"""
    try:
        # Check database connectivity
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        db_healthy = True
        conn.close()
        
        # Check disk space
        disk_usage = os.statvfs('.')
        free_space = disk_usage.f_bavail * disk_usage.f_frsize
        total_space = disk_usage.f_blocks * disk_usage.f_frsize
        disk_usage_percent = ((total_space - free_space) / total_space) * 100
        
        # Check if critical directories exist
        required_dirs = ['logs', 'exports', 'reports', 'captures']
        dirs_exist = all(os.path.exists(d) for d in required_dirs)
        
        health_status = {
            'database': 'healthy' if db_healthy else 'unhealthy',
            'disk_usage_percent': round(disk_usage_percent, 2),
            'free_space_gb': round(free_space / (1024**3), 2),
            'directories': 'ok' if dirs_exist else 'missing',
            'timestamp': datetime.now().isoformat()
        }
        
        overall_status = 'healthy' if all([
            db_healthy,
            disk_usage_percent < 90,
            dirs_exist
        ]) else 'unhealthy'
        
        return jsonify({
            'status': 'success',
            'overall_health': overall_status,
            'details': health_status
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'overall_health': 'unhealthy',
            'message': str(e)
        }), 500
