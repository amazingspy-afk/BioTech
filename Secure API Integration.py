from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Directory to store keys
KEY_DIR = "keys"

# Ensure the key directory exists
os.makedirs(KEY_DIR, exist_ok=True)

# 1. Generate RSA Keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open(os.path.join(KEY_DIR, "private_key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(os.path.join(KEY_DIR, "public_key.pem"), "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("RSA keys generated and saved.")

# Load keys from files
def load_public_key(filepath):
    with open(filepath, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def load_private_key(filepath):
    with open(filepath, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# 2. Encrypt API Key
def encrypt_api_key(api_key):
    public_key = load_public_key(os.path.join(KEY_DIR, "public_key.pem"))
    encrypted_api_key = public_key.encrypt(
        api_key.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_api_key

# 3. Decrypt API Key
def decrypt_api_key(encrypted_api_key):
    private_key = load_private_key(os.path.join(KEY_DIR, "private_key.pem"))
    decrypted_api_key = private_key.decrypt(
        encrypted_api_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_api_key.decode()

# API Endpoint to encrypt API Key
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    api_key = data.get('api_key')
    if not api_key:
        return jsonify({'error': 'API key is required'}), 400

    encrypted_api_key = encrypt_api_key(api_key)
    return jsonify({'encrypted_api_key': encrypted_api_key.hex()}), 200

# API Endpoint to decrypt API Key
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_api_key_hex = data.get('encrypted_api_key')
    if not encrypted_api_key_hex:
        return jsonify({'error': 'Encrypted API key is required'}), 400

    encrypted_api_key = bytes.fromhex(encrypted_api_key_hex)
    decrypted_api_key = decrypt_api_key(encrypted_api_key)
    return jsonify({'decrypted_api_key': decrypted_api_key}), 200

# Sample Data Exchange Endpoint
@app.route('/data', methods=['GET'])
def get_data():
    # Example data, replace with actual data source
    sample_data = {
        'message': 'Welcome to the BioConnect API!',
        'data': [1, 2, 3, 4, 5]
    }
    return jsonify(sample_data), 200

if __name__ == '__main__':
    # Uncomment the next line to generate keys for the first time
    # generate_rsa_keys()
    app.run(debug=True, host='0.0.0.0', port=5000)
