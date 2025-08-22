# backend/routes/alerts.py
from flask import Blueprint, request, jsonify
import logging

alerts_bp = Blueprint("alerts", __name__)

# Store alerts in memory (for demo; in prod, use DB)
ALERTS = []

@alerts_bp.route("/alerts", methods=["POST"])
def receive_alert():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid alert payload"}), 400

        ALERTS.append(data)
        logging.info(f"[ALERT RECEIVED] {data.get('summary', 'No summary')}")
        return jsonify({"status": "Alert received"}), 200

    except Exception as e:
        logging.exception("Failed to process alert")
        return jsonify({"error": str(e)}), 500

@alerts_bp.route("/alerts", methods=["GET"])
def list_alerts():
    return jsonify(ALERTS)
