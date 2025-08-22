from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
import sqlite3
import json

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/', methods=['GET'])
def get_alerts():
    """Get all security alerts with optional filtering"""
    try:
        severity = request.args.get('severity', 'all')
        limit = int(request.args.get('limit', 100))
        
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        if severity != 'all':
            cursor.execute('''
                SELECT * FROM alerts 
                WHERE severity = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (severity, limit))
        else:
            cursor.execute('''
                SELECT * FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
        
        alerts = cursor.fetchall()
        conn.close()
        
        alert_list = []
        for alert in alerts:
            alert_dict = {
                'id': alert[0],
                'timestamp': alert[1],
                'type': alert[2],
                'severity': alert[3],
                'source_ip': alert[4],
                'target_ip': alert[5],
                'description': alert[6],
                'details': json.loads(alert[7]) if alert[7] else {}
            }
            alert_list.append(alert_dict)
        
        return jsonify({
            'status': 'success',
            'alerts': alert_list,
            'count': len(alert_list)
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@alerts_bp.route('/stats', methods=['GET'])
def get_alert_stats():
    """Get alert statistics for dashboard"""
    try:
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        # Get counts by severity
        cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM alerts 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY severity
        ''')
        severity_stats = dict(cursor.fetchall())
        
        # Get recent alert trends
        cursor.execute('''
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM alerts
            WHERE timestamp > datetime('now', '-7 days')
            GROUP BY DATE(timestamp)
            ORDER BY date
        ''')
        trend_data = cursor.fetchall()
        
        # Get top attack types
        cursor.execute('''
            SELECT type, COUNT(*) as count
            FROM alerts
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY type
            ORDER BY count DESC
            LIMIT 5
        ''')
        top_attacks = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'severity_stats': severity_stats,
            'trend_data': trend_data,
            'top_attacks': top_attacks
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@alerts_bp.route('/<int:alert_id>', methods=['PUT'])
def update_alert(alert_id):
    """Update alert status or add notes"""
    try:
        data = request.get_json()
        
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        if 'status' in data:
            cursor.execute('''
                UPDATE alerts 
                SET status = ?, updated_at = datetime('now')
                WHERE id = ?
            ''', (data['status'], alert_id))
        
        if 'notes' in data:
            cursor.execute('''
                UPDATE alerts 
                SET notes = ?, updated_at = datetime('now')
                WHERE id = ?
            ''', (data['notes'], alert_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'message': 'Alert updated'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
