import json
import re
import getpass
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization



class user():
    def __init__(self, username, password):
        self.__username = validate_user(username)
        self.__password = validate_password(password)
        save_user(self.__username, self.__password)
        generate_keys(self.__username)

    


def validate_user(username):
    while len(username) < 5:
        print('Username must be at least 5 characters long')
        username = input('Enter username again: ')
    
    with open('jsones/users.json', 'r') as file:
        if not file.read().strip() == "":
                with open("jsones/users.json", "r", encoding="utf-8") as file:
                    users = json.load(file)
                while any(d['username'] == username for d in users):
                    print('Username already exists')
                    username = input('Enter username again: ')
        return username

def has_special_char(password):
    elem = r'[^\w\s]'
    return bool(re.search(elem, password))

def validate_password( password):
    while len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password) or not has_special_char(password):
        print('Password must be at least 8 characters long and contain at least one uppercase letter, one digit and one special character')
        password = getpass.getpass("Enter a correct password: ")
    prev = password
    password = getpass.getpass('Enter password again: ')
    while password != prev:
        print('Passwords do not match')
        password = getpass.getpass('Enter password again: ')
    return password



def save_user(username, password):
    try:
        with open('jsones/users.json', 'r', encoding='utf-8') as file:
            try:
                users = json.load(file)
            except json.JSONDecodeError:
                users = []
    except FileNotFoundError:
        users = []
    password = password.encode("utf-8")
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    users.append({'username': username, 'token': str(key), 'id':str(salt)})

    with open('jsones/users.json', 'w', encoding='utf-8') as file:
        json.dump(users, file, indent=4)

    


def generate_keys(username):

    user_dir = os.path.join('keys', username)
    os.makedirs(user_dir, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    public_key = private_key.public_key()

    with open("keys/" + username + "/"+username+"_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryptiousern()
    ))


    with open("keys/" + username + "/"+username+"_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


    