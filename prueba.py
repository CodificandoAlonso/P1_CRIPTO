import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"hola caracola")


print("Token cifrado:", token)

# Desencriptar el token
decrypted_message = f.decrypt(token)

# Mostrar el mensaje desencriptado
print("Mensaje desencriptado:", decrypted_message)
print("Esta es la key: ", key)
