from collections import defaultdict
from flask import Flask, request, abort
from datetime import datetime, timedelta


# Initialize Flask app
app = Flask(__name__)


# Dictionary to store request counts by IP
request_counts = defaultdict(list)


# Configuration for anomaly detection
THRESHOLD_REQUESTS = 100  # Maximum requests allowed in time window
TIME_WINDOW = timedelta(minutes=1)  # Time window for frequency check
WHITELISTED_IPS = ['192.168.1.100']  # Example authorized IPs


# Function to check for anomalies
def detect_anomalies():
    current_time = datetime.now()
    client_ip = request.remote_addr
    
    # Check for high-frequency requests
    request_times = request_counts[client_ip]
    request_times = [time for time in request_times if current_time - time < TIME_WINDOW]
    request_counts[client_ip] = request_times  # Update request times within time window
    if len(request_times) > THRESHOLD_REQUESTS:
        logging.warning(f"Anomaly detected: High-frequency requests from {client_ip}")
        abort(429, description="Too many requests")
    
    # Check for unauthorized IPs
    if client_ip not in WHITELISTED_IPS:
        logging.warning(f"Anomaly detected: Unauthorized access from {client_ip}")
        abort(403, description="Unauthorized IP")


# Define a sample API endpoint with anomaly detection
@app.route('/api/secure-data', methods=['GET', 'POST'])
def secure_data():
    # Log the request and check for anomalies
    log_request()
    detect_anomalies()
    
    # Simulate storing request time for frequency check
    request_counts[request.remote_addr].append(datetime.now())
    
    return {"message": "API request processed"}


if __name__ == '__main__':
    app.run(debug=True)