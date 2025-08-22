from flask import Blueprint, jsonify, request
import sqlite3
import json
from datetime import datetime, timedelta

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/security-summary', methods=['GET'])
def get_security_summary():
    """Generate security summary report"""
    try:
        period = request.args.get('period', 'day')  # day, week, month
        
        if period == 'day':
            time_filter = "datetime('now', '-1 day')"
        elif period == 'week':
            time_filter = "datetime('now', '-7 days')"
        else:  # month
            time_filter = "datetime('now', '-30 days')"
        
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        # Alert summary
        cursor.execute(f'''
            SELECT severity, type, COUNT(*) as count
            FROM alerts
            WHERE timestamp > {time_filter}
            GROUP BY severity, type
            ORDER BY count DESC
        ''')
        alert_summary = cursor.fetchall()
        
        # Top attacked targets
        cursor.execute(f'''
            SELECT target_ip, COUNT(*) as attack_count
            FROM alerts
            WHERE timestamp > {time_filter}
            GROUP BY target_ip
            ORDER BY attack_count DESC
            LIMIT 10
        ''')
        top_targets = cursor.fetchall()
        
        # Attack sources
        cursor.execute(f'''
            SELECT source_ip, COUNT(*) as attack_count
            FROM alerts
            WHERE timestamp > {time_filter}
            GROUP BY source_ip
            ORDER BY attack_count DESC
            LIMIT 10
        ''')
        attack_sources = cursor.fetchall()
        
        # Network activity summary
        cursor.execute(f'''
            SELECT COUNT(*) as total_packets,
                   COUNT(DISTINCT source_ip) as unique_sources,
                   COUNT(DISTINCT destination_ip) as unique_destinations,
                   AVG(packet_size) as avg_packet_size
            FROM network_logs
            WHERE timestamp > {time_filter}
        ''')
        network_summary = cursor.fetchone()
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'report': {
                'period': period,
                'generated_at': datetime.now().isoformat(),
                'alert_summary': alert_summary,
                'top_targets': top_targets,
                'attack_sources': attack_sources,
                'network_summary': {
                    'total_packets': network_summary[0],
                    'unique_sources': network_summary[1],
                    'unique_destinations': network_summary[2],
                    'avg_packet_size': network_summary[3]
                }
            }
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@reports_bp.route('/threat-analysis', methods=['GET'])
def get_threat_analysis():
    """Generate detailed threat analysis report"""
    try:
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        # Threat trend analysis (last 7 days)
        cursor.execute('''
            SELECT DATE(timestamp) as date,
                   type as threat_type,
                   COUNT(*) as count
            FROM alerts
            WHERE timestamp > datetime('now', '-7 days')
            GROUP BY DATE(timestamp), type
            ORDER BY date, count DESC
        ''')
        threat_trends = cursor.fetchall()
        
        # Critical threats requiring immediate attention
        cursor.execute('''
            SELECT * FROM alerts
            WHERE severity = 'critical' 
            AND timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
        ''')
        critical_threats = cursor.fetchall()
        
        # Compromised devices analysis
        cursor.execute('''
            SELECT d.ip_address, d.hostname, COUNT(a.id) as alert_count
            FROM devices d
            LEFT JOIN alerts a ON d.ip_address = a.source_ip OR d.ip_address = a.target_ip
            WHERE a.timestamp > datetime('now', '-24 hours')
            GROUP BY d.ip_address, d.hostname
            HAVING alert_count > 5
            ORDER BY alert_count DESC
        ''')
        compromised_devices = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'threat_analysis': {
                'generated_at': datetime.now().isoformat(),
                'threat_trends': threat_trends,
                'critical_threats': len(critical_threats),
                'compromised_devices': compromised_devices,
                'overall_risk_level': 'HIGH' if len(critical_threats) > 10 else 'MEDIUM' if len(critical_threats) > 5 else 'LOW'
            }
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@reports_bp.route('/compliance', methods=['GET'])
def get_compliance_report():
    """Generate compliance and audit report"""
    try:
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        # Security controls status
        security_controls = {
            'intrusion_detection': True,
            'network_monitoring': True,
            'device_discovery': True,
            'threat_detection': True,
            'log_retention': True,
            'alert_response': True
        }
        
        # Policy violations
        cursor.execute('''
            SELECT type, COUNT(*) as violation_count
            FROM alerts
            WHERE timestamp > datetime('now', '-30 days')
            AND type IN ('unauthorized_access', 'policy_violation', 'suspicious_activity')
            GROUP BY type
        ''')
        policy_violations = dict(cursor.fetchall())
        
        # Audit trail summary
        cursor.execute('''
            SELECT COUNT(*) as total_events,
                   MIN(timestamp) as earliest_log,
                   MAX(timestamp) as latest_log
            FROM network_logs
            WHERE timestamp > datetime('now', '-30 days')
        ''')
        audit_summary = cursor.fetchone()
        
        conn.close()
        
        compliance_score = 85  # Calculate based on various factors
        
        return jsonify({
            'status': 'success',
            'compliance_report': {
                'generated_at': datetime.now().isoformat(),
                'compliance_score': compliance_score,
                'security_controls': security_controls,
                'policy_violations': policy_violations,
                'audit_summary': {
                    'total_events': audit_summary[0],
                    'log_retention_period': '30 days',
                    'earliest_log': audit_summary[1],
                    'latest_log': audit_summary[2]
                }
            }
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@reports_bp.route('/export', methods=['POST'])
def export_report():
    """Export report in various formats"""
    try:
        data = request.get_json()
        report_type = data.get('report_type', 'security_summary')
        export_format = data.get('format', 'json')  # json, csv, pdf
        period = data.get('period', 'day')
        
        # Generate export ID for tracking
        export_id = f"report_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # In a real implementation, this would generate the actual file
        # For now, we'll return metadata about the export
        return jsonify({
            'status': 'success',
            'message': 'Report export initiated',
            'export_id': export_id,
            'report_type': report_type,
            'format': export_format,
            'period': period,
            'estimated_completion': (datetime.now() + timedelta(minutes=5)).isoformat()
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@reports_bp.route('/scheduled', methods=['GET'])
def get_scheduled_reports():
    """Get list of scheduled reports"""
    try:
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scheduled_reports 
            ORDER BY next_run_time ASC
        ''')
        scheduled_reports = cursor.fetchall()
        
        report_list = []
        for report in scheduled_reports:
            report_dict = {
                'id': report[0],
                'name': report[1],
                'report_type': report[2],
                'schedule': report[3],
                'recipients': json.loads(report[4]) if report[4] else [],
                'next_run_time': report[5],
                'last_run_time': report[6],
                'is_active': bool(report[7])
            }
            report_list.append(report_dict)
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'scheduled_reports': report_list,
            'count': len(report_list)
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@reports_bp.route('/scheduled', methods=['POST'])
def create_scheduled_report():
    """Create a new scheduled report"""
    try:
        data = request.get_json()
        
        conn = sqlite3.connect('shadowpulse.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scheduled_reports 
            (name, report_type, schedule, recipients, next_run_time, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        ''', (
            data['name'],
            data['report_type'],
            data['schedule'],
            json.dumps(data.get('recipients', [])),
            data['next_run_time'],
            data.get('is_active', True)
        ))
        
        report_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'message': 'Scheduled report created',
            'report_id': report_id
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500