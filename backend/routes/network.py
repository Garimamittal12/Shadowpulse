from flask import Blueprint, jsonify, request
import sqlite3
import json
from datetime import datetime, timedelta

network_bp = Blueprint('network', __name__)

@network_bp.route('/topology', methods=['GET'])
def get_network_topology():
    """Get network topology data"""
    try:
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        # Get devices with their connections
        cursor.execute('''
            SELECT ip_address, mac_address, hostname, device_type, is_trusted
            FROM devices
            WHERE last_seen > datetime('now', '-1 hour')
        ''')
        devices = cursor.fetchall()
        
        # Get connection data from recent logs
        cursor.execute('''
            SELECT DISTINCT source_ip, destination_ip, protocol, COUNT(*) as connection_count
            FROM network_logs
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY source_ip, destination_ip, protocol
            ORDER BY connection_count DESC
            LIMIT 100
        ''')
        connections = cursor.fetchall()
        
        conn.close()
        
        # Format for network visualization
        nodes = []
        edges = []
        
        for device in devices:
            nodes.append({
                'id': device[0],
                'label': device[2] or device[0],
                'type': device[3],
                'trusted': bool(device[4]),
                'mac': device[1]
            })
        
        for conn in connections:
            edges.append({
                'source': conn[0],
                'target': conn[1],
                'protocol': conn[2],
                'weight': conn[3]
            })
        
        return jsonify({
            'status': 'success',
            'topology': {
                'nodes': nodes,
                'edges': edges
            }
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network_bp.route('/traffic/realtime', methods=['GET'])
def get_realtime_traffic():
    """Get real-time network traffic data"""
    try:
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        # Get traffic from last 5 minutes
        cursor.execute('''
            SELECT strftime('%Y-%m-%d %H:%M', timestamp) as minute,
                   protocol,
                   COUNT(*) as packet_count,
                   SUM(packet_size) as total_bytes
            FROM network_logs
            WHERE timestamp > datetime('now', '-5 minutes')
            GROUP BY strftime('%Y-%m-%d %H:%M', timestamp), protocol
            ORDER BY minute DESC
        ''')
        traffic_data = cursor.fetchall()
        
        # Get current top talkers
        cursor.execute('''
            SELECT source_ip, destination_ip, COUNT(*) as packet_count
            FROM network_logs
            WHERE timestamp > datetime('now', '-1 minute')
            GROUP BY source_ip, destination_ip
            ORDER BY packet_count DESC
            LIMIT 10
        ''')
        top_talkers = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'traffic_data': traffic_data,
            'top_talkers': top_talkers,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@network_bp.route('/bandwidth', methods=['GET'])
def get_bandwidth_usage():
    """Get bandwidth usage statistics"""
    try:
        period = request.args.get('period', 'hour')  # hour, day, week
        
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        if period == 'hour':
            time_format = '%Y-%m-%d %H:%M'
            time_filter = "datetime('now', '-1 hour')"
        elif period == 'day':
            time_format = '%Y-%m-%d %H'
            time_filter = "datetime('now', '-1 day')"
        else:  # week
            time_format = '%Y-%m-%d'
            time_filter = "datetime('now', '-7 days')"
        
        cursor.execute(f'''
            SELECT strftime('{time_format}', timestamp) as time_period,
                   SUM(packet_size) as total_bytes,
                   COUNT(*) as packet_count
            FROM network_logs
            WHERE timestamp > {time_filter}
            GROUP BY strftime('{time_format}', timestamp)
            ORDER BY time_period
        ''')
        bandwidth_data = cursor.fetchall()
        
        # Get bandwidth by protocol
        cursor.execute(f'''
            SELECT protocol, SUM(packet_size) as total_bytes
            FROM network_logs
            WHERE timestamp > {time_filter}
            GROUP BY protocol
            ORDER BY total_bytes DESC
        ''')
        protocol_usage = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'bandwidth_data': bandwidth_data,
            'protocol_usage': protocol_usage,
            'period': period
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
