import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
password = input("password")
password = b'password'
salt = os.urandom(16)
print("salt", salt)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)
key = base64.urlsafe_b64encode(kdf.derive(password))
print("key", key)
f = Fernet(key)
token = f.encrypt(b"Secret message!")
print(token)
token
b'...'
token = f.decrypt(token)
print(token)
b'Secret message!'