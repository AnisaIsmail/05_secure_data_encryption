import hashlib
from cryptography.fernet import Fernet
import base64

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key(passkey: str) -> bytes:
    # Derive a Fernet key from a hashed passkey
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def encrypt_data(text: str, passkey: str) -> str:
    f = Fernet(generate_key(passkey))
    return f.encrypt(text.encode()).decode()

def decrypt_data(cipher_text: str, passkey: str) -> str:
    f = Fernet(generate_key(passkey))
    return f.decrypt(cipher_text.encode()).decode()
