# backend/app.py
from flask import Flask
from routes.alerts import alerts_bp
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Register routes
app.register_blueprint(alerts_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
