from flask import Flask, request
import logging
from datetime import datetime


# Initialize Flask app
app = Flask(__name__)


# Configure logging to log API traffic
logging.basicConfig(filename='api_traffic.log', level=logging.INFO)


# Helper function to log request data
def log_request():
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "client_ip": request.remote_addr,
        "method": request.method,
        "endpoint": request.path,
        "user_agent": request.headers.get('User-Agent'),
        "user_role": request.headers.get('Role', 'Guest')  # Example: User roles passed via headers
    }
    logging.info(f"API Request: {log_data}")


# Define a sample API endpoint
@app.route('/api/data', methods=['GET', 'POST'])
def api_data():
    log_request()
    return {"message": "API request logged successfully!"}


if __name__ == '__main__':
    app.run(debug=True)