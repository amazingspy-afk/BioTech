# Import necessary libraries
import os
from shutil import move
from datetime import datetime
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
                encryption_algorithm=serialization.NoEncryption()  # Change to use a passphrase if needed
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
    return decrypted_api_key.decode()

# 4. Rotate RSA Keys and Re-encrypt API Key
def rotate_rsa_keys(api_key_file="encrypted_api_key.bin"):
    # Step 1: Backup current keys
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs('backup', exist_ok=True)
    move('private_key.pem', f'backup/private_key_{timestamp}.pem')
    move('public_key.pem', f'backup/public_key_{timestamp}.pem')

    print(f"Old keys backed up at {timestamp}")

    # Step 2: Generate new RSA keys
    generate_rsa_keys()

    # Step 3: Decrypt the API key with old private key
    def load_old_private_key(filepath):
        with open(filepath, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    old_private_key = load_old_private_key(f'backup/private_key_{timestamp}.pem')

    with open(api_key_file, "rb") as f:
        encrypted_api_key = f.read()

    # Decrypt the API key with old private key
    decrypted_api_key = old_private_key.decrypt(
        encrypted_api_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 4: Re-encrypt API key with the new public key
    encrypt_api_key(decrypted_api_key.decode())  # Re-encrypt with the new public key

    print("API key re-encrypted with new RSA keys.")

# Main Execution
if __name__ == "__main__":
    # Generate RSA keys (uncomment to generate keys)
    # generate_rsa_keys()

    # Encrypt an API key
    api_key_to_encrypt = "AIzaSyCwEro-wQ6YUNcA1ozA9FQev-DyJp3t2EQ"  # Replace with your actual API key
    encrypt_api_key(api_key_to_encrypt)

    # Decrypt the API key
    decrypt_api_key()

    # Rotate RSA keys and re-encrypt the API key
    rotate_rsa_keys()
