import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import base64

def generate_rsa_key_pair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, pem_private_key, pem_public_key

def pad_data(data):
    padder = sym_padding.PKCS7(128).padder() # Note: Check padding if you encounter an error
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data

def encrypt_data(data, session_key, iv):
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_data = pad_data(data)
    return encryptor.update(padded_data) + encryptor.finalize()

def encrypt_session_key(session_key, public_key):
    return public_key.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Generate RSA key pair
private_key, pem_private_key, pem_public_key = generate_rsa_key_pair()

# Write the private key to a file
with open("private-key.pem", "wb") as f:
    f.write(pem_private_key)

public_key = private_key.public_key()
session_key = os.urandom(32)
data_to_encrypt = b"encryptme!"
iv = os.urandom(16)

encrypted_data = encrypt_data(data_to_encrypt, session_key, iv)

encrypted_session_key = encrypt_session_key(session_key, public_key)

encoded_session_key = base64.b64encode(encrypted_session_key).decode('utf-8')
encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
encoded_iv = base64.b64encode(iv).decode('utf-8')

print("Private Key (PEM):\n", pem_private_key.decode())
print("Encrypted Session Key (Base64):\n", encoded_session_key)
print("Encrypted Data (Base64):\n", encoded_data)
print("IV (Base64):\n", encoded_iv)
