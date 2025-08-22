from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
import sqlite3
import psutil
import json

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/stats', methods=['GET'])
def get_dashboard_stats():
    """Get comprehensive dashboard statistics"""
    try:
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Security metrics
        cursor.execute('''
            SELECT COUNT(*) FROM alerts 
            WHERE timestamp > datetime('now', '-24 hours')
        ''')
        alerts_24h = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM network_logs 
            WHERE timestamp > datetime('now', '-1 hour')
        ''')
        traffic_1h = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(DISTINCT source_ip) FROM network_logs 
            WHERE timestamp > datetime('now', '-24 hours')
        ''')
        unique_ips = cursor.fetchone()[0]
        
        # Threat level calculation
        if alerts_24h > 100:
            threat_level = 'HIGH'
        elif alerts_24h > 50:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'
        
        # Active detectors status
        detector_status = {
            'arp_spoof': True,
            'dhcp_spoofing': True,
            'dns_spoof': True,
            'http_injection': True,
            'icmp_redirect': True,
            'rogue_access': True,
            'ssl_strip': True
        }
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'system_metrics': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': (disk.used / disk.total) * 100,
                'uptime': psutil.boot_time()
            },
            'security_metrics': {
                'alerts_24h': alerts_24h,
                'traffic_1h': traffic_1h,
                'unique_ips': unique_ips,
                'threat_level': threat_level
            },
            'detector_status': detector_status
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@dashboard_bp.route('/network-overview', methods=['GET'])
def get_network_overview():
    """Get network traffic overview for dashboard"""
    try:
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        # Traffic by protocol
        cursor.execute('''
            SELECT protocol, COUNT(*) as count
            FROM network_logs
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY protocol
        ''')
        protocol_stats = dict(cursor.fetchall())
        
        # Top source IPs
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count
            FROM network_logs
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_sources = cursor.fetchall()
        
        # Traffic timeline (last 24 hours)
        cursor.execute('''
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM network_logs
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY strftime('%H', timestamp)
            ORDER BY hour
        ''')
        traffic_timeline = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'protocol_stats': protocol_stats,
            'top_sources': top_sources,
            'traffic_timeline': traffic_timeline
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
