# backend/utils/config.py
import os

class Config:
    BACKEND_ALERT_URL = os.getenv("BACKEND_ALERT_URL", "http://127.0.0.1:5000/alerts")
    IFACE = os.getenv("IFACE", None)  # Network interface to sniff on
