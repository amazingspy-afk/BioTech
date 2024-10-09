# Import necessary libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# 1. Generate RSA Keys
def generate_rsa_keys():
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate RSA public key
    public_key = private_key.public_key()

    # Save private key to a file
    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key to a file
    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("RSA keys generated and saved.")

# 2. Encrypt API Keys
def encrypt_api_key(api_key):
    # Load public key from file
    def load_public_key(filepath):
        with open(filepath, "rb") as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())
    
    public_key = load_public_key("public_key.pem")

    # Encrypt sensitive data (API key)
    encrypted_api_key = public_key.encrypt(
        api_key.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save encrypted API key to a file
    with open("encrypted_api_key.bin", "wb") as f:
        f.write(encrypted_api_key)
    print("API key encrypted and saved.")

# 3. Decrypt API Keys
def decrypt_api_key():
    # Load private key from file
    def load_private_key(filepath):
        with open(filepath, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    private_key = load_private_key("private_key.pem")

    # Load the encrypted API key
    with open("encrypted_api_key.bin", "rb") as f:
        encrypted_api_key = f.read()

    # Decrypt the API key
    decrypted_api_key = private_key.decrypt(
        encrypted_api_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print("Decrypted API Key:", decrypted_api_key.decode())

# Main Execution
if __name__ == "__main__":
    # Generate RSA keys (uncomment to generate keys)
    generate_rsa_keys()

    # Example usage:
    # Encrypt an API key
    api_key_to_encrypt = "your-api-key-here"  # Replace with your actual API key
    encrypt_api_key(api_key_to_encrypt)

    # Decrypt the API key
    decrypt_api_key()
