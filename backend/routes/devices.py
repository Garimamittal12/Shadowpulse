from flask import Blueprint, jsonify, request
import sqlite3
import json
from datetime import datetime

devices_bp = Blueprint('devices', __name__)

@devices_bp.route('/', methods=['GET'])
def get_devices():
    """Get all discovered network devices"""
    try:
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM devices 
            ORDER BY last_seen DESC
        ''')
        devices = cursor.fetchall()
        
        device_list = []
        for device in devices:
            device_dict = {
                'id': device[0],
                'ip_address': device[1],
                'mac_address': device[2],
                'hostname': device[3],
                'vendor': device[4],
                'device_type': device[5],
                'first_seen': device[6],
                'last_seen': device[7],
                'is_trusted': bool(device[8]),
                'risk_score': device[9],
                'ports': json.loads(device[10]) if device[10] else []
            }
            device_list.append(device_dict)
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'devices': device_list,
            'count': len(device_list)
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@devices_bp.route('/scan', methods=['POST'])
def initiate_device_scan():
    """Initiate a network device discovery scan"""
    try:
        data = request.get_json()
        network_range = data.get('network_range', '192.168.1.0/24')
        
        # This would typically trigger an async network scan
        # For now, we'll simulate by returning a scan ID
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return jsonify({
            'status': 'success',
            'message': 'Device scan initiated',
            'scan_id': scan_id,
            'network_range': network_range
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@devices_bp.route('/<int:device_id>/trust', methods=['PUT'])
def update_device_trust(device_id):
    """Update device trust status"""
    try:
        data = request.get_json()
        is_trusted = data.get('is_trusted', False)
        
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE devices 
            SET is_trusted = ?, updated_at = datetime('now')
            WHERE id = ?
        ''', (is_trusted, device_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'message': 'Device trust status updated'
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@devices_bp.route('/rogue', methods=['GET'])
def get_rogue_devices():
    """Get devices identified as potentially rogue"""
    try:
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM devices 
            WHERE is_trusted = 0 AND risk_score > 5
            ORDER BY risk_score DESC
        ''')
        rogue_devices = cursor.fetchall()
        
        device_list = []
        for device in rogue_devices:
            device_dict = {
                'id': device[0],
                'ip_address': device[1],
                'mac_address': device[2],
                'hostname': device[3],
                'vendor': device[4],
                'risk_score': device[9],
                'last_seen': device[7]
            }
            device_list.append(device_dict)
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'rogue_devices': device_list,
            'count': len(device_list)
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
