from flask import Blueprint, jsonify, request
import sqlite3
from datetime import datetime, timedelta

logs_bp = Blueprint('logs', __name__)

@logs_bp.route('/', methods=['GET'])
def get_logs():
    """Get network logs with filtering options"""
    try:
        # Get query parameters
        log_type = request.args.get('type', 'all')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        source_ip = request.args.get('source_ip')
        limit = int(request.args.get('limit', 1000))
        
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        # Build query based on filters
        query = "SELECT * FROM network_logs WHERE 1=1"
        params = []
        
        if log_type != 'all':
            query += " AND log_type = ?"
            params.append(log_type)
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        logs = cursor.fetchall()
        
        log_list = []
        for log in logs:
            log_dict = {
                'id': log[0],
                'timestamp': log[1],
                'log_type': log[2],
                'source_ip': log[3],
                'destination_ip': log[4],
                'protocol': log[5],
                'source_port': log[6],
                'destination_port': log[7],
                'packet_size': log[8],
                'flags': log[9],
                'payload_snippet': log[10]
            }
            log_list.append(log_dict)
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'logs': log_list,
            'count': len(log_list)
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@logs_bp.route('/export', methods=['POST'])
def export_logs():
    """Export logs based on criteria"""
    try:
        data = request.get_json()
        export_format = data.get('format', 'json')
        filters = data.get('filters', {})
        
        # This would typically generate a file for download
        export_id = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return jsonify({
            'status': 'success',
            'message': 'Log export initiated',
            'export_id': export_id,
            'format': export_format
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@logs_bp.route('/search', methods=['POST'])
def search_logs():
    """Search logs with advanced criteria"""
    try:
        data = request.get_json()
        search_term = data.get('search_term', '')
        filters = data.get('filters', {})
        
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        # Simple search implementation
        cursor.execute('''
            SELECT * FROM network_logs 
            WHERE source_ip LIKE ? OR destination_ip LIKE ? OR payload_snippet LIKE ?
            ORDER BY timestamp DESC
            LIMIT 500
        ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
        
        results = cursor.fetchall()
        conn.close()
        
        log_list = []
        for log in results:
            log_dict = {
                'id': log[0],
                'timestamp': log[1],
                'log_type': log[2],
                'source_ip': log[3],
                'destination_ip': log[4],
                'protocol': log[5],
                'source_port': log[6],
                'destination_port': log[7],
                'packet_size': log[8],
                'flags': log[9],
                'payload_snippet': log[10]
            }
            log_list.append(log_dict)
        
        return jsonify({
            'status': 'success',
            'results': log_list,
            'count': len(log_list),
            'search_term': search_term
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
